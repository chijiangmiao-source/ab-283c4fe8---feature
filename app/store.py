"""冻结审计记录存储（SQLite）。

两种提交方式共享同一份冻结审计：

* 一次性整包提交（``submit``）：
  * 相同标识 + 完全相同的载荷 -> 返回原始审计（幂等）；
  * 复用标识但字节不同 -> 拒绝（409），既有记录原样保留；
  * 结构解析失败 -> 不落任何库记录，绝不留下“成功结论”；
  * verified / mismatch 都是完整、冻结的结论，一经写入不可更改。
* 分段送检（``init_submission`` / ``put_segment`` / ``seal_submission``）：
  * 审查员以同一审计标识、总字节数与预期载荷 SHA-256 建立送检，随后可
    乱序上传不超过 64 KiB 的原始字节区段（半开区间 [start,end)），每段的
    区间与字节都持久化，断线后可重新读取覆盖范围续传；
  * 重叠区段只有逐字节相同才接受；任一重叠冲突、总长/摘要变更都把该送检
    冻结为 rejected，且绝不影响已存在的完整审计；
  * 封存仅在 [0,total) 无空洞、总长 <= 2 MiB 且整体 SHA-256 一致后，才把
    拼装字节交给严格 SuperBlob 解析与逐页复核；解析失败只留下拒绝原因；
  * 生成/复用冻结审计与送检置 sealed 在同一事务完成，重复封存不产生两份
    审计，进程重启后状态完整保留。
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
SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# 单次区段上传的原始字节上限（Base64 文本在 HTTP 层另行放宽）。
MAX_SEGMENT_BYTES = 64 * 1024

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


@dataclass
class SubmissionOutcome:
    """分段送检操作的统一结果。

    status 取值：
      created           送检已建立（receiving）
      opened            幂等重开既有送检（参数一致）
      stored            区段已接收（含相同区段重传/相同重叠合并）
      sealed_created    封存成功且新生成一份冻结审计（201）
      sealed_reused     封存/建立时复用了既有冻结审计（200）
      incomplete        封存时仍有空洞（送检保持 receiving，不冻结）
      rejected          送检已被冻结为拒绝（409）
      conflict         参数与既有终态/审计冲突（409），不改动任何数据
      not_found         送检不存在（404）
      invalid           请求参数不合法（400/413），不改变送检状态
    """

    status: str
    state: Optional[dict] = None
    record: Optional[dict] = None
    error: Optional[str] = None
    http_status: int = 200


class AuditStore:
    def __init__(self, db_path: str):
        self._db_path = db_path
        directory = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.RLock()
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
            # 分段送检：同一审计标识至多一条；state 为
            # receiving（接收中）/ sealed（已封存，关联一条冻结审计）/
            # rejected（冲突或最终校验失败，冻结不可变）。
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS submissions (
                    audit_id        TEXT PRIMARY KEY,
                    total_bytes     INTEGER NOT NULL,
                    expected_sha256 TEXT NOT NULL,
                    state           TEXT NOT NULL
                        CHECK (state IN ('receiving','sealed','rejected')),
                    reason          TEXT,
                    frozen_audit_id TEXT,
                    created_at      REAL NOT NULL,
                    updated_at      REAL NOT NULL,
                    FOREIGN KEY (frozen_audit_id) REFERENCES audits(audit_id)
                )
                """
            )
            # 每段的半开区间 [start_off,end_off) 与原始字节。
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS submission_segments (
                    audit_id  TEXT NOT NULL,
                    start_off INTEGER NOT NULL,
                    end_off   INTEGER NOT NULL,
                    data      BLOB NOT NULL,
                    PRIMARY KEY (audit_id, start_off),
                    FOREIGN KEY (audit_id) REFERENCES submissions(audit_id)
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_segments_audit"
                " ON submission_segments(audit_id, start_off)"
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

    # ---- 分段送检 ------------------------------------------------------------

    @staticmethod
    def validate_sha256(digest: object) -> Optional[str]:
        if not isinstance(digest, str) or not SHA256_HEX_RE.fullmatch(digest):
            return "预期载荷摘要须为 64 位十六进制 SHA-256"
        return None

    def _coverage(self, audit_id: str, total: int) -> tuple[list[tuple[int, int]], Optional[int]]:
        """计算已收区段的连续覆盖范围与首个缺口。

        返回 (区间列表, 首个缺口起点)：区间列表按起点升序且已合并；
        从偏移 0 起的连续前缀结束于 ``contiguous``，首个缺口即
        ``contiguous``（若已覆盖到 total 则为 None）。
        """
        rows = self._conn.execute(
            "SELECT start_off, end_off FROM submission_segments"
            " WHERE audit_id = ? ORDER BY start_off",
            (audit_id,),
        ).fetchall()
        merged: list[list[int]] = []
        for r in rows:
            s, e = r["start_off"], r["end_off"]
            if merged and s <= merged[-1][1]:
                if e > merged[-1][1]:
                    merged[-1][1] = e
            else:
                merged.append([s, e])
        contiguous = 0
        for s, e in merged:
            if s <= contiguous < e:
                contiguous = e
            else:
                break
        gap = None if contiguous >= total else contiguous
        return [(s, e) for s, e in merged], gap

    def _submission_state(self, row: sqlite3.Row) -> dict:
        total = row["total_bytes"]
        # sealed 即代表 [0,total) 已完整封存（原始字节保存在冻结审计中），
        # 覆盖范围按完整区间报告，不依赖接收阶段的区段行。
        if row["state"] == "sealed":
            ranges: list[tuple[int, int]] = [(0, total)]
            gap: Optional[int] = None
            received = total
            contiguous = total
        else:
            ranges, gap = self._coverage(row["audit_id"], total)
            received = min(sum(e - s for s, e in ranges), total)
            contiguous = total if gap is None else gap
        state = {
            "auditId": row["audit_id"],
            "status": row["state"],
            "totalBytes": total,
            "expectedSha256": row["expected_sha256"],
            "receivedBytes": received,
            "contiguousBytes": contiguous,
            "firstGap": gap,
            "coveredRanges": [[s, e] for s, e in ranges],
            "reason": row["reason"],
            "frozenAuditId": row["frozen_audit_id"],
        }
        return state

    def get_submission(self, audit_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submissions WHERE audit_id = ?", (audit_id,)
            ).fetchone()
            if row is None:
                return None
            return self._submission_state(row)

    def _freeze_rejected(self, audit_id: str, reason: str) -> None:
        """把送检冻结为 rejected（调用方须持锁并处于事务内）。"""
        self._conn.execute(
            "UPDATE submissions SET state='rejected', reason=?, updated_at=?"
            " WHERE audit_id=?",
            (reason, time.time(), audit_id),
        )

    def init_submission(
        self, audit_id: str, total_bytes: object, expected_sha256: object
    ) -> SubmissionOutcome:
        err = self.validate_id(audit_id)
        if err is not None:
            return SubmissionOutcome("invalid", error=err, http_status=400)
        digest_err = self.validate_sha256(expected_sha256)
        if digest_err is not None:
            return SubmissionOutcome("invalid", error=digest_err, http_status=400)
        assert isinstance(expected_sha256, str)
        digest = expected_sha256.lower()
        if not isinstance(total_bytes, int) or isinstance(total_bytes, bool):
            return SubmissionOutcome(
                "invalid", error="总字节数须为非负整数", http_status=400
            )
        if total_bytes <= 0:
            return SubmissionOutcome(
                "invalid", error="总字节数须为正数", http_status=400
            )
        if total_bytes > codesig.MAX_BLOB_BYTES:
            return SubmissionOutcome(
                "invalid",
                error=f"总字节数超过 {codesig.MAX_BLOB_BYTES}（2 MiB）上限",
                http_status=413,
            )

        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
            ).fetchone()
            if row is not None:
                # 重开：参数一致即幂等；改总长/摘要属于变更送检身份，
                # 正在接收中的送检立即冻结为 rejected（终态原因不覆盖）。
                if row["total_bytes"] != total_bytes or row["expected_sha256"] != digest:
                    if row["state"] == "receiving":
                        reason = (
                            "送检身份参数变更被拒绝："
                            f"原 totalBytes={row['total_bytes']}"
                            f"/sha256={row['expected_sha256']}，"
                            f"新 totalBytes={total_bytes}/sha256={digest}"
                        )
                        with self._conn:
                            self._freeze_rejected(audit_id, reason)
                        row = self._conn.execute(
                            "SELECT * FROM submissions WHERE audit_id=?",
                            (audit_id,),
                        ).fetchone()
                        return SubmissionOutcome(
                            "rejected", state=self._submission_state(row),
                            error=reason, http_status=409,
                        )
                    state = self._submission_state(row)
                    if row["state"] == "rejected":
                        return SubmissionOutcome(
                            "rejected", state=state,
                            error=f"送检已冻结为拒绝：{row['reason']}",
                            http_status=409,
                        )
                    # 已 sealed：终态不可变，拒绝改参数但保持 sealed。
                    return SubmissionOutcome(
                        "conflict", state=state,
                        error="送检已封存；总字节数或摘要与封存记录不同，"
                        "变更被拒绝，封存结论保留不变",
                        http_status=409,
                    )
                state = self._submission_state(row)
                if row["state"] == "rejected":
                    return SubmissionOutcome(
                        "rejected", state=state,
                        error=f"送检已冻结为拒绝：{row['reason']}", http_status=409,
                    )
                if row["state"] == "sealed":
                    rec = self.get(audit_id)
                    return SubmissionOutcome(
                        "sealed_reused", state=state, record=rec, http_status=200
                    )
                return SubmissionOutcome("opened", state=state, http_status=200)

            # 送检尚不存在：若已有同标识冻结审计，则按整包语义幂等/拒绝，
            # 绝不允许分段流程影响已有完整审计。同摘要时登记一条 sealed 送检
            # 指向既有审计，使送检状态读取与封存语义保持一致。
            audit = self._conn.execute(
                "SELECT result_json, payload_sha256 FROM audits WHERE audit_id=?",
                (audit_id,),
            ).fetchone()
            if audit is not None:
                if audit["payload_sha256"] != digest:
                    return SubmissionOutcome(
                        "conflict",
                        error="审计标识已被不同摘要的冻结审计占用；"
                        "分段送检被拒绝，既有冻结记录保留不变",
                        http_status=409,
                    )
                try:
                    with self._conn:
                        self._conn.execute(
                            "INSERT INTO submissions (audit_id, total_bytes,"
                            " expected_sha256, state, frozen_audit_id,"
                            " created_at, updated_at)"
                            " VALUES (?, ?, ?, 'sealed', ?, ?, ?)",
                            (audit_id, total_bytes, digest, audit_id, now, now),
                        )
                except sqlite3.IntegrityError:
                    # 并发建立：退化为重读既有送检。
                    row = self._conn.execute(
                        "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
                    ).fetchone()
                    return SubmissionOutcome(
                        "sealed_reused", state=self._submission_state(row),
                        record=json.loads(audit["result_json"]), http_status=200,
                    )
                row = self._conn.execute(
                    "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
                ).fetchone()
                return SubmissionOutcome(
                    "sealed_reused", state=self._submission_state(row),
                    record=json.loads(audit["result_json"]), http_status=200,
                )

            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO submissions (audit_id, total_bytes,"
                        " expected_sha256, state, created_at, updated_at)"
                        " VALUES (?, ?, ?, 'receiving', ?, ?)",
                        (audit_id, total_bytes, digest, now, now),
                    )
            except sqlite3.IntegrityError:
                # 并发抢注：退化为重读判定。
                return self.init_submission(audit_id, total_bytes, expected_sha256)
            row = self._conn.execute(
                "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
            ).fetchone()
            return SubmissionOutcome(
                "created", state=self._submission_state(row), http_status=201
            )

    def put_segment(
        self, audit_id: str, start: object, end: object, data: bytes
    ) -> SubmissionOutcome:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
            ).fetchone()
            if row is None:
                return SubmissionOutcome(
                    "not_found", error="送检不存在，请先建立分段送检", http_status=404
                )
            state = self._submission_state(row)
            if row["state"] == "rejected":
                return SubmissionOutcome(
                    "rejected", state=state,
                    error=f"送检已冻结为拒绝：{row['reason']}", http_status=409,
                )
            if row["state"] == "sealed":
                rec = self.get(audit_id)
                return SubmissionOutcome(
                    "sealed_reused", state=state, record=rec, http_status=200
                )

            total = row["total_bytes"]
            # ---- 参数校验（不改变既有接收状态） ----
            if (
                not isinstance(start, int) or isinstance(start, bool)
                or not isinstance(end, int) or isinstance(end, bool)
            ):
                return SubmissionOutcome(
                    "invalid", state=state,
                    error="区段起止必须为整数", http_status=400,
                )
            if start < 0 or end <= start:
                return SubmissionOutcome(
                    "invalid", state=state,
                    error="区段半开区间非法：须 0 <= start < end", http_status=400,
                )
            if end > total:
                return SubmissionOutcome(
                    "invalid", state=state,
                    error=f"区段 [{start},{end}) 越过总字节数 {total}",
                    http_status=400,
                )
            if not isinstance(data, (bytes, bytearray)):
                return SubmissionOutcome(
                    "invalid", state=state, error="区段数据必须是原始字节",
                    http_status=400,
                )
            data = bytes(data)
            if len(data) != end - start:
                return SubmissionOutcome(
                    "invalid", state=state,
                    error=f"区段数据 {len(data)} 字节与声明区间长度"
                    f" {end - start} 不一致", http_status=400,
                )
            if len(data) > MAX_SEGMENT_BYTES:
                return SubmissionOutcome(
                    "invalid", state=state,
                    error=f"单段超过 {MAX_SEGMENT_BYTES} 字节（64 KiB）上限",
                    http_status=413,
                )

            # ---- 与所有已有相交区段逐字节核对 ----
            overlaps = self._conn.execute(
                "SELECT start_off, end_off, data FROM submission_segments"
                " WHERE audit_id=? AND start_off < ? AND end_off > ?"
                " ORDER BY start_off",
                (audit_id, end, start),
            ).fetchall()
            for ov in overlaps:
                ov_s, ov_e = ov["start_off"], ov["end_off"]
                lo, hi = max(start, ov_s), min(end, ov_e)
                old_part = ov["data"][lo - ov_s : hi - ov_s]
                new_part = data[lo - start : hi - start]
                if old_part != new_part:
                    reason = (
                        f"区段重叠冲突：[{start},{end}) 与已收区段 [{ov_s},{ov_e})"
                        f" 在 [{lo},{hi}) 字节不一致"
                    )
                    with self._conn:
                        self._freeze_rejected(audit_id, reason)
                    row = self._conn.execute(
                        "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
                    ).fetchone()
                    frozen = self._submission_state(row)
                    frozen["conflictRange"] = [lo, hi]
                    return SubmissionOutcome(
                        "rejected", state=frozen, error=reason, http_status=409
                    )

            # ---- 全部一致：幂等写入并集（合并相同字节的相邻/重叠区段） ----
            # 与新区间相邻（端点相接）的区段也可一并合并，避免碎片化。
            adjacent = self._conn.execute(
                "SELECT start_off, end_off, data FROM submission_segments"
                " WHERE audit_id=? AND start_off <= ? AND end_off >= ?"
                " ORDER BY start_off",
                (audit_id, end, start),
            ).fetchall()
            merge_start, merge_end = start, end
            pieces: list[tuple[int, bytes]] = [(start, data)]
            for ov in adjacent:
                pieces.append((ov["start_off"], ov["data"]))
                merge_start = min(merge_start, ov["start_off"])
                merge_end = max(merge_end, ov["end_off"])
            buf = bytearray(merge_end - merge_start)
            for off, chunk in pieces:
                buf[off - merge_start : off - merge_start + len(chunk)] = chunk
            with self._conn:
                self._conn.execute(
                    "DELETE FROM submission_segments WHERE audit_id=?"
                    " AND start_off >= ? AND end_off <= ?",
                    (audit_id, merge_start, merge_end),
                )
                self._conn.execute(
                    "INSERT INTO submission_segments (audit_id, start_off,"
                    " end_off, data) VALUES (?, ?, ?, ?)",
                    (audit_id, merge_start, merge_end, bytes(buf)),
                )
                self._conn.execute(
                    "UPDATE submissions SET updated_at=? WHERE audit_id=?",
                    (time.time(), audit_id),
                )
            row = self._conn.execute(
                "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
            ).fetchone()
            return SubmissionOutcome(
                "stored", state=self._submission_state(row), http_status=200
            )

    def _assemble(self, audit_id: str, total: int) -> Optional[bytearray]:
        """按已收区段拼装 [0,total)；若有无洞则返回 None。"""
        rows = self._conn.execute(
            "SELECT start_off, end_off, data FROM submission_segments"
            " WHERE audit_id=? ORDER BY start_off",
            (audit_id,),
        ).fetchall()
        buf = bytearray(total)
        pos = 0
        for r in rows:
            s, e = r["start_off"], r["end_off"]
            if s > pos:
                return None
            if e > pos:
                buf[pos:e] = r["data"][pos - s : e - s]
                pos = e
        if pos < total:
            return None
        return buf

    def seal_submission(self, audit_id: str) -> SubmissionOutcome:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
            ).fetchone()
            if row is None:
                return SubmissionOutcome(
                    "not_found", error="送检不存在", http_status=404
                )
            if row["state"] == "rejected":
                return SubmissionOutcome(
                    "rejected", state=self._submission_state(row),
                    error=f"送检已冻结为拒绝：{row['reason']}", http_status=409,
                )
            if row["state"] == "sealed":
                # 重复封存：返回同一份冻结审计，绝不生成第二份。
                rec = self.get(audit_id)
                return SubmissionOutcome(
                    "sealed_reused", state=self._submission_state(row),
                    record=rec, http_status=200,
                )

            total = row["total_bytes"]
            digest = row["expected_sha256"]
            state = self._submission_state(row)
            if state["firstGap"] is not None:
                return SubmissionOutcome(
                    "incomplete", state=state,
                    error=f"尚有未覆盖区段，首个缺口位于 {state['firstGap']}",
                    http_status=409,
                )

            assembled = self._assemble(audit_id, total)
            if assembled is None:
                return SubmissionOutcome(
                    "incomplete", state=state,
                    error="拼装失败：覆盖存在空洞", http_status=409,
                )
            blob = bytes(assembled)
            actual_sha = hashlib.sha256(blob).hexdigest()
            if actual_sha != digest:
                reason = (
                    f"整体 SHA-256 与预期不符：拼装后 {actual_sha}，"
                    f"预期 {digest}"
                )
                with self._conn:
                    self._freeze_rejected(audit_id, reason)
                row = self._conn.execute(
                    "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
                ).fetchone()
                return SubmissionOutcome(
                    "rejected", state=self._submission_state(row),
                    error=reason, http_status=409,
                )

            # 长度、连续性与整体摘要均已确认；做严格结构解析与逐页复核。
            # 失败只留下该送检的拒绝原因，绝不写入/读取成功审计。
            try:
                view = codesig.parse_superblob(blob)
                result = codesig.verify_pages(blob, view)
            except codesig.CodeSignatureError as exc:
                reason = f"封存结构复核失败：{exc.message}"
                with self._conn:
                    self._freeze_rejected(audit_id, reason)
                row = self._conn.execute(
                    "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
                ).fetchone()
                return SubmissionOutcome(
                    "rejected", state=self._submission_state(row),
                    error=reason, http_status=422,
                )

            record = {
                "frozen": True,
                "auditId": audit_id,
                "payloadSha256": digest,
                "createdAt": time.time(),
                **result.to_public_dict(),
            }
            record_json = json.dumps(record, sort_keys=True, ensure_ascii=False)

            # 生成或复用对应冻结审计 + 送检置 sealed 必须在同一事务，
            # 保证并发封存与重启下至多一份审计、不漏页、不改页证据。
            try:
                with self._conn:
                    existing = self._conn.execute(
                        "SELECT result_json FROM audits WHERE audit_id=?",
                        (audit_id,),
                    ).fetchone()
                    if existing is not None:
                        saved = json.loads(existing["result_json"])
                        if saved["payloadSha256"] != digest:
                            # 理论不可达：建送时已拦截；fail-closed。
                            raise sqlite3.IntegrityError(
                                "同标识冻结审计摘要不一致"
                            )
                        reused = True
                    else:
                        self._conn.execute(
                            "INSERT INTO audits (audit_id, payload_sha256,"
                            " verdict, result_json, created_at)"
                            " VALUES (?, ?, ?, ?, ?)",
                            (
                                audit_id, digest, result.verdict,
                                record_json, record["createdAt"],
                            ),
                        )
                        reused = False
                    self._conn.execute(
                        "UPDATE submissions SET state='sealed', reason=NULL,"
                        " frozen_audit_id=?, updated_at=? WHERE audit_id=?",
                        (audit_id, time.time(), audit_id),
                    )
            except sqlite3.IntegrityError as exc:
                # 并发下审计被抢注：同摘要则复用，否则送检拒绝、两不改动。
                existing = self._conn.execute(
                    "SELECT result_json, payload_sha256 FROM audits"
                    " WHERE audit_id=?", (audit_id,)
                ).fetchone()
                if existing is not None and existing["payload_sha256"] == digest:
                    with self._conn:
                        self._conn.execute(
                            "UPDATE submissions SET state='sealed', reason=NULL,"
                            " frozen_audit_id=?, updated_at=? WHERE audit_id=?",
                            (audit_id, time.time(), audit_id),
                        )
                    saved = json.loads(existing["result_json"])
                    row = self._conn.execute(
                        "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
                    ).fetchone()
                    return SubmissionOutcome(
                        "sealed_reused", state=self._submission_state(row),
                        record=saved, http_status=200,
                    )
                reason = f"封存被并发冻结审计冲突阻止：{exc}"
                with self._conn:
                    self._freeze_rejected(audit_id, reason)
                row = self._conn.execute(
                    "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
                ).fetchone()
                return SubmissionOutcome(
                    "rejected", state=self._submission_state(row),
                    error=reason, http_status=409,
                )

            row = self._conn.execute(
                "SELECT * FROM submissions WHERE audit_id=?", (audit_id,)
            ).fetchone()
            out_record = json.loads(existing["result_json"]) if reused else record
            return SubmissionOutcome(
                "sealed_reused" if reused else "sealed_created",
                state=self._submission_state(row),
                record=out_record,
                http_status=200 if reused else 201,
            )

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
