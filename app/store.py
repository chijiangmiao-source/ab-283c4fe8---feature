"""冻结审计记录存储（SQLite）。

语义：

* 相同标识 + 完全相同的载荷 -> 返回原始审计（幂等）；
* 复用标识但字节不同 -> 拒绝（409），既有记录原样保留；
* 结构解析失败 -> 不落任何库记录，绝不留下“成功结论”；
* verified / mismatch 都是完整、冻结的结论，一经写入不可更改。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Optional

from . import codesig

AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# 提交结果：
#   created            首次写入（verified 或 mismatch 都会冻结落库）
#   returned_existing  同标识同字节重传，返回原审计
#   conflict           同标识不同字节，拒绝且保留既有记录
#   invalid            标识/载荷格式不合法（不落库）
#   unparseable        结构解析失败（不落库，更不会留下成功结论）


@dataclass
class SubmitOutcome:
    status: str
    record: Optional[dict] = None
    error: Optional[str] = None
    http_status: int = 200


class AuditStore:
    def __init__(self, db_path: str):
        self._db_path = db_path
        directory = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audits (
                    audit_id       TEXT PRIMARY KEY,
                    payload_sha256 TEXT NOT NULL,
                    verdict        TEXT NOT NULL CHECK (verdict IN ('verified','mismatch')),
                    result_json    TEXT NOT NULL,
                    created_at     REAL NOT NULL
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def validate_id(audit_id: object) -> Optional[str]:
        if not isinstance(audit_id, str) or not AUDIT_ID_RE.fullmatch(audit_id):
            return "审计标识须为 1-128 位字母、数字、点、下划线或连字符，且以字母数字开头"
        return None

    def get(self, audit_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT result_json FROM audits WHERE audit_id = ?", (audit_id,)
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["result_json"])

    def list_ids(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT audit_id FROM audits ORDER BY created_at ASC"
            ).fetchall()
        return [r["audit_id"] for r in rows]

    def submit(self, audit_id: str, blob: bytes) -> SubmitOutcome:
        err = self.validate_id(audit_id)
        if err is not None:
            return SubmitOutcome("invalid", error=err, http_status=400)
        if not isinstance(blob, (bytes, bytearray)) or len(blob) == 0:
            return SubmitOutcome(
                "invalid", error="载荷为空或不是原始字节", http_status=400
            )
        if len(blob) > codesig.MAX_BLOB_BYTES:
            return SubmitOutcome(
                "invalid",
                error=f"载荷超过 {codesig.MAX_BLOB_BYTES} 字节（2 MiB）上限",
                http_status=413,
            )

        payload_sha = hashlib.sha256(blob).hexdigest()

        # 先看标识是否已占用：同字节幂等返回，异字节直接拒绝，两者都不重算。
        with self._lock:
            row = self._conn.execute(
                "SELECT payload_sha256, result_json FROM audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
        if row is not None:
            if row["payload_sha256"] == payload_sha:
                record = json.loads(row["result_json"])
                record["replayed"] = True
                return SubmitOutcome("returned_existing", record=record, http_status=200)
            return SubmitOutcome(
                "conflict",
                error="审计标识已被不同字节的载荷占用；复用标识更换载荷被拒绝，"
                "既有冻结记录保留不变",
                http_status=409,
            )

        # 严格解析 + 逐页复算。任何结构异常都在写库之前抛出。
        try:
            view = codesig.parse_superblob(blob)
            result = codesig.verify_pages(blob, view)
        except codesig.CodeSignatureError as exc:
            # 明确不落库：调用方也不会进入 INSERT 分支。
            return SubmitOutcome(
                "unparseable", error=exc.message, http_status=422
            )

        record = {
            "frozen": True,
            "auditId": audit_id,
            "payloadSha256": payload_sha,
            "createdAt": time.time(),
            **result.to_public_dict(),
        }
        record_json = json.dumps(record, sort_keys=True, ensure_ascii=False)

        with self._lock:
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO audits (audit_id, payload_sha256, verdict,"
                        " result_json, created_at) VALUES (?, ?, ?, ?, ?)",
                        (
                            audit_id,
                            payload_sha,
                            result.verdict,
                            record_json,
                            record["createdAt"],
                        ),
                    )
            except sqlite3.IntegrityError:
                # 并发下抢注：退化为重读 + 幂等/冲突判定。
                row = self._conn.execute(
                    "SELECT payload_sha256, result_json FROM audits WHERE audit_id = ?",
                    (audit_id,),
                ).fetchone()
                if row is not None and row["payload_sha256"] == payload_sha:
                    existing = json.loads(row["result_json"])
                    existing["replayed"] = True
                    return SubmitOutcome(
                        "returned_existing", record=existing, http_status=200
                    )
                return SubmitOutcome(
                    "conflict",
                    error="审计标识已被不同字节的载荷占用（并发提交）",
                    http_status=409,
                )

        return SubmitOutcome("created", record=record, http_status=201)
