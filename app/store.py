"""冻结审计记录存储（SQLite）。

两类对象：

* **冻结审计**（``audits`` 表）：verified / mismatch 都是完整、冻结、可重复
  读取的结论。一次性整包提交的旧语义保持不变：
    - 相同标识 + 完全相同的载荷 -> 返回原始审计（幂等）；
    - 复用标识但字节不同 -> 拒绝（409），既有记录原样保留；
    - 结构解析失败 -> 不落任何库记录，绝不留下“成功结论”。
* **分段送检**（``submissions`` / ``submission_chunks`` 表）：审查员以同一
  审计标识、总字节数与预期载荷摘要，乱序提交不超过 64 KiB 的 Base64 区段。
  每段的半开区间与原始字节立即持久化（断线/重启可续）：
    - 重叠内容逐字节相同 -> 接受重传（幂等去重）；
    - 任一重叠字节冲突、总长或预期摘要变更 -> 该送检永久冻结为 rejected，
      且不影响任何已存在的完整审计；
    - 封存时只在 [0, totalBytes) 无空洞、总长 <= 2 MiB、整体 SHA-256
      一致后，才进入严格 SuperBlob 解析与逐页复核；通过后在**同一立即
      事务**里生成（或复用）冻结审计并将送检置为 sealed。

并发：所有写事务均为 ``BEGIN IMMEDIATE``，配合进程内 RLock 与 SQLite busy
等待，使“封存与最后一段并发、重复封存、进程重启续传”都不会产生两份审计、
漏页或改变页证据。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

from . import codesig

AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# 分段送检中单段原始字节上限：64 KiB。
MAX_CHUNK_BYTES = 64 * 1024

# 一次性整包提交结果：
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


class SubmissionError(Exception):
    """分段送检操作被拒绝。code 面向 API 状态字段，state 为当前送检视图。"""

    def __init__(self, code: str, message: str, http_status: int,
                 state: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.state = state


class AuditStore:
    def __init__(self, db_path: str):
        self._db_path = db_path
        directory = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(directory, exist_ok=True)
        # 进程内一把 RLock：同进程多线程全部串行化；跨连接/跨进程靠
        # BEGIN IMMEDIATE 写锁 + busy_timeout 兜底。
        self._lock = threading.RLock()
        # isolation_level=None：自己显式管理事务（BEGIN IMMEDIATE 立即取写锁）。
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False, isolation_level=None, timeout=30
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 30000")
        with self._tx():
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
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS submissions (
                    audit_id        TEXT PRIMARY KEY,
                    total_bytes     INTEGER NOT NULL
                                    CHECK (total_bytes BETWEEN 1 AND 2097152),
                    expected_sha256 TEXT NOT NULL,
                    state           TEXT NOT NULL
                                    CHECK (state IN ('receiving','sealed','rejected')),
                    reason          TEXT,
                    conflict_start  INTEGER,
                    conflict_end    INTEGER,
                    sealed_audit_id TEXT,
                    created_at      REAL NOT NULL,
                    updated_at      REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS submission_chunks (
                    audit_id  TEXT NOT NULL,
                    start_off INTEGER NOT NULL,
                    end_off   INTEGER NOT NULL,
                    seq       INTEGER NOT NULL,
                    data      BLOB NOT NULL,
                    PRIMARY KEY (audit_id, start_off, end_off)
                )
                """
            )

    @contextmanager
    def _tx(self):
        """立即写事务：BEGIN IMMEDIATE 取写锁，提交/回滚均显式。"""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def validate_id(audit_id: object) -> Optional[str]:
        if not isinstance(audit_id, str) or not AUDIT_ID_RE.fullmatch(audit_id):
            return "审计标识须为 1-128 位字母、数字、点、下划线或连字符，且以字母数字开头"
        return None

    @staticmethod
    def _validate_digest(digest: object) -> Optional[str]:
        if not isinstance(digest, str):
            return "预期载荷摘要必须为字符串"
        if not SHA256_HEX_RE.fullmatch(digest.strip().lower()):
            return "预期载荷摘要必须为 64 位十六进制 SHA-256"
        return None

    # ---- 冻结审计 ------------------------------------------------------------
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

        # 先看标识是否已冻结：同字节幂等返回，异字节直接拒绝，两者都不重算。
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

        # 进行中的同标识送检：整包恰好就是声明的完整字节时，直接代为封存，
        # 两条路径汇入同一事务；其余情况一律拒绝，保持标识占用语义。
        sub_row = self._get_submission_row(audit_id)
        if sub_row is not None:
            if sub_row["state"] == "receiving" \
                    and sub_row["total_bytes"] == len(blob) \
                    and sub_row["expected_sha256"] == payload_sha:
                try:
                    return self._seal_with_bytes(audit_id, blob, payload_sha)
                except SubmissionError as exc:
                    return SubmitOutcome(
                        "conflict" if exc.http_status == 409 else "unparseable",
                        error=exc.message,
                        http_status=exc.http_status,
                    )
            return SubmitOutcome(
                "conflict",
                error="审计标识已被分段送检占用（该送检未封存或已拒绝），"
                "不能改用整包提交",
                http_status=409,
            )

        # 严格解析 + 逐页复算。任何结构异常都在写库之前抛出。
        try:
            record = self._build_record(audit_id, blob, payload_sha)
        except codesig.CodeSignatureError as exc:
            # 明确不落库：调用方不会进入 INSERT 分支。
            return SubmitOutcome(
                "unparseable", error=exc.message, http_status=422
            )

        return self._insert_audit(audit_id, blob, payload_sha, record)

    def _insert_audit(self, audit_id: str, blob: bytes, payload_sha: str,
                      record: dict) -> SubmitOutcome:
        """在立即事务中插入冻结审计；并发抢注时退化为幂等/冲突判定。"""
        record_json = json.dumps(record, sort_keys=True, ensure_ascii=False)
        try:
            with self._tx():
                existing = self._conn.execute(
                    "SELECT payload_sha256, result_json FROM audits"
                    " WHERE audit_id = ?",
                    (audit_id,),
                ).fetchone()
                if existing is not None:
                    if existing["payload_sha256"] == payload_sha:
                        out = json.loads(existing["result_json"])
                        out["replayed"] = True
                        return SubmitOutcome(
                            "returned_existing", record=out, http_status=200
                        )
                    raise _ConflictNow("审计标识已被不同字节的载荷占用（并发提交）")
                self._conn.execute(
                    "INSERT INTO audits (audit_id, payload_sha256, verdict,"
                    " result_json, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        audit_id,
                        payload_sha,
                        record["verdict"],
                        record_json,
                        record["createdAt"],
                    ),
                )
        except _ConflictNow as exc:
            return SubmitOutcome("conflict", error=str(exc), http_status=409)
        except sqlite3.IntegrityError:
            row = self._get_audit_row(audit_id)
            if row is not None and row["payload_sha256"] == payload_sha:
                out = json.loads(row["result_json"])
                out["replayed"] = True
                return SubmitOutcome(
                    "returned_existing", record=out, http_status=200
                )
            return SubmitOutcome(
                "conflict",
                error="审计标识已被不同字节的载荷占用（并发提交）",
                http_status=409,
            )
        return SubmitOutcome("created", record=record, http_status=201)

    # ---- 分段送检 ------------------------------------------------------------
    def begin_submission(
        self, audit_id: object, total_bytes: object, expected_sha256: object
    ) -> tuple[dict, bool]:
        """开始（或幂等恢复）一个分段送检。

        返回 ``(送检视图, 是否本次新建)``。
        """
        err = self.validate_id(audit_id)
        if err is not None:
            raise SubmissionError("invalid", err, 400)
        audit_id = str(audit_id)

        digest_err = self._validate_digest(expected_sha256)
        if digest_err is not None:
            raise SubmissionError("invalid", digest_err, 400)
        digest = str(expected_sha256).strip().lower()

        if not isinstance(total_bytes, int) or isinstance(total_bytes, bool):
            raise SubmissionError("invalid", "总字节数必须为整数", 400)
        if total_bytes < 1:
            raise SubmissionError("invalid", "总字节数必须为正", 400)
        if total_bytes > codesig.MAX_BLOB_BYTES:
            raise SubmissionError(
                "invalid",
                f"总字节数超过 {codesig.MAX_BLOB_BYTES}（2 MiB）上限",
                413,
            )

        # 所有判定与写入在同一个立即事务中完成，避免与封存/整包并发抢注。
        with self._tx():
            audit = self._conn.execute(
                "SELECT payload_sha256 FROM audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
            if audit is not None:
                if audit["payload_sha256"] == digest:
                    return self._state_for_sealed(audit_id, digest, total_bytes), False
                raise SubmissionError(
                    "conflict",
                    "审计标识已被不同字节的冻结审计占用，不能开始分段送检",
                    409,
                )

            row = self._get_submission_row(audit_id)
            now = time.time()
            if row is None:
                self._conn.execute(
                    "INSERT INTO submissions (audit_id, total_bytes,"
                    " expected_sha256, state, created_at, updated_at)"
                    " VALUES (?, ?, ?, 'receiving', ?, ?)",
                    (audit_id, total_bytes, digest, now, now),
                )
                return self._build_state(audit_id), True

            if row["state"] == "rejected":
                raise SubmissionError(
                    "conflict",
                    f"该标识的分段送检已冻结为拒绝：{row['reason']}",
                    409,
                    self._state_from_row(row),
                )
            if row["state"] == "sealed":
                if row["expected_sha256"] == digest \
                        and row["total_bytes"] == total_bytes:
                    return self._state_from_row(row), False
                raise SubmissionError(
                    "conflict", "该标识的分段送检已封存，参数不可变更", 409,
                    self._state_from_row(row),
                )
            # receiving：同参数幂等（断线后重新开始即恢复进度）；
            # 总长或预期摘要变更立即冻结为拒绝。
            pending: Optional[SubmissionError] = None
            if row["total_bytes"] != total_bytes \
                    or row["expected_sha256"] != digest:
                reason = (
                    f"送检参数变更被拒绝（原 totalBytes={row['total_bytes']},"
                    f" expectedSha256={row['expected_sha256'][:16]}…；"
                    f"新 totalBytes={total_bytes},"
                    f" expectedSha256={digest[:16]}…）"
                )
                self._set_rejected_locked(audit_id, reason, None)
                state = self._build_state(audit_id)
                pending = SubmissionError("conflict", reason, 409, state)
            else:
                state = self._build_state(audit_id)
                created = False
        if pending is not None:
            raise pending
        return state, created

    def put_chunk(self, audit_id: str, start: object, end: object,
                  data: bytes) -> dict:
        """写入半开区间 [start, end) 的原始字节并持久化。

        与已有区段重叠时，重叠部分必须逐字节相同，否则整个送检冻结为
        rejected。完全相同的重复区间幂等跳过。
        """
        row = self._get_submission_row(audit_id)
        if row is None:
            raise SubmissionError("not_found", "该标识没有进行中的分段送检", 404)
        if row["state"] == "sealed":
            raise SubmissionError(
                "sealed", "该分段送检已封存，不能再写入区段", 409,
                self._state_from_row(row),
            )
        if row["state"] == "rejected":
            raise SubmissionError(
                "rejected",
                f"该分段送检已冻结为拒绝：{row['reason']}",
                409,
                self._state_from_row(row),
            )

        total = row["total_bytes"]
        if not isinstance(start, int) or isinstance(start, bool) \
                or not isinstance(end, int) or isinstance(end, bool):
            raise SubmissionError("invalid", "区段端点必须为整数", 400)
        if start < 0 or end <= start or end > total:
            raise SubmissionError(
                "invalid",
                f"区段 [{start}, {end}) 非法：须满足 0 <= start < end"
                f" <= totalBytes({total})",
                400,
            )
        if not isinstance(data, (bytes, bytearray)):
            raise SubmissionError("invalid", "区段必须为原始字节", 400)
        data = bytes(data)
        if len(data) != end - start:
            raise SubmissionError(
                "invalid",
                f"区段 [{start}, {end}) 长 {end - start} 字节，"
                f"但载荷解码后为 {len(data)} 字节",
                400,
            )
        if len(data) > MAX_CHUNK_BYTES:
            raise SubmissionError(
                "invalid",
                f"单段 {len(data)} 字节超过 {MAX_CHUNK_BYTES}（64 KiB）上限",
                413,
            )

        # 状态复核、冲突判定与写入在同一立即事务：跨连接并发时写锁串行化，
        # 后到者一定看得到已提交区段，冲突段绝不落库。
        pending: Optional[SubmissionError] = None
        with self._tx():
            row = self._get_submission_row(audit_id)
            if row["state"] != "receiving":
                # 并发封存/拒绝刚好抢先：不写入本段。直接抛错无需提交任何写入。
                raise SubmissionError(
                    row["state"],
                    f"该分段送检已{('封存' if row['state'] == 'sealed' else '拒绝')}，"
                    "不能再写入区段",
                    409,
                    self._state_from_row(row),
                )
            chunks = self._get_chunks(audit_id)
            conflict_range = self._first_conflict_range(start, end, data, chunks)
            if conflict_range is not None:
                lo, hi = conflict_range
                reason = (
                    f"区段重叠冲突：[{lo}, {hi}) 重传字节与已接收内容"
                    "逐字节不一致，送检冻结为拒绝"
                )
                self._set_rejected_locked(audit_id, reason, (lo, hi))
                pending = SubmissionError(
                    "conflict", reason, 409, self._build_state(audit_id)
                )

            if pending is None:
                # 重叠但逐字节相同：完全相同的整段跳过，部分相交则记录新段。
                exists_exact = any(
                    c_start == start and c_end == end for c_start, c_end, _ in chunks
                )
                if not exists_exact:
                    next_seq = max(
                        (r["seq"] for r in self._get_chunk_rows(audit_id)), default=-1
                    ) + 1
                    self._conn.execute(
                        "UPDATE submissions SET updated_at = ? WHERE audit_id = ?",
                        (time.time(), audit_id),
                    )
                    self._conn.execute(
                        "INSERT INTO submission_chunks (audit_id, start_off,"
                        " end_off, seq, data) VALUES (?, ?, ?, ?, ?)",
                        (audit_id, start, end, next_seq, sqlite3.Binary(data)),
                    )
        if pending is not None:
            raise pending
        return self.get_submission(audit_id)

    def get_submission(self, audit_id: str) -> Optional[dict]:
        with self._lock:
            row = self._get_submission_row(audit_id)
            if row is None:
                # 可能已通过整包路径冻结：给出不可变的 sealed 合成视图。
                audit = self._conn.execute(
                    "SELECT payload_sha256 FROM audits WHERE audit_id = ?",
                    (audit_id,),
                ).fetchone()
                if audit is None:
                    return None
                return {
                    "auditId": audit_id,
                    "state": "sealed",
                    "totalBytes": None,
                    "expectedSha256": audit["payload_sha256"],
                    "coveredRanges": [],
                    "receivedBytes": None,
                    "contiguousCoverage": None,
                    "firstGap": None,
                    "conflictRange": None,
                    "reason": None,
                }
            return self._state_from_row(row)

    def seal_submission(self, audit_id: str) -> SubmitOutcome:
        """用户确认封存。

        流程：无空洞 -> 拼装 -> 整体 SHA-256 比对 -> 严格 SuperBlob 解析与
        逐页复核 -> 同一立即事务写冻结审计并置 sealed。结构失败只留下该送检
        的拒绝原因，绝不写 audits。
        """
        row = self._get_submission_row(audit_id)
        if row is None:
            # 没有送检行：可能整包提交已先行冻结。存在审计则复用返回，否则 404。
            audit_row = self._get_audit_row(audit_id)
            if audit_row is not None:
                return self._existing_outcome(audit_id)
            raise SubmissionError("not_found", "该标识没有分段送检记录", 404)
        if row["state"] == "rejected":
            raise SubmissionError(
                "rejected",
                f"该分段送检已冻结为拒绝：{row['reason']}",
                409,
                self._state_from_row(row),
            )
        if row["state"] == "sealed":
            # 重复封存：复用对应冻结审计。
            return self._existing_outcome(audit_id)

        blob, digest, gap_state = self._assemble_if_complete(audit_id, row)
        if blob is None:
            first = gap_state["firstGap"]
            raise SubmissionError(
                "incomplete",
                f"覆盖不完整：[0, {row['total_bytes']}) 仍有空洞，"
                f"首个缺口 [{first[0]}, {first[1]})",
                409,
                gap_state,
            )
        if digest != row["expected_sha256"]:
            reason = (
                f"整体 SHA-256 不一致：声明 {row['expected_sha256']}，"
                f"拼装实得 {digest}"
            )
            self._freeze_rejected(audit_id, reason, None, "digest_mismatch")
        return self._seal_with_bytes(audit_id, blob, digest)

    # ---- 封存内部实现 --------------------------------------------------------
    def _assemble_if_complete(
        self, audit_id: str, row: sqlite3.Row
    ) -> tuple[Optional[bytes], Optional[str], Optional[dict]]:
        """读已持久化区段并拼装；有空洞则返回 (None, None, 视图)。"""
        total = row["total_bytes"]
        with self._lock:
            chunks = self._get_chunks(audit_id)
        ranges = [(s, e) for s, e, _ in chunks]
        merged, contiguous, first_gap = self._coverage(ranges, total)
        if contiguous != total:
            state = self._state_from_row(row, merged, contiguous, first_gap)
            return None, None, state
        blob = bytearray(total)
        for s, e, data in chunks:
            blob[s:e] = data
        return bytes(blob), hashlib.sha256(bytes(blob)).hexdigest(), None

    def _seal_with_bytes(self, audit_id: str, blob: bytes,
                         payload_sha: str) -> SubmitOutcome:
        """封存共用路径（分段封存与整包代为封存）。

        解析/复算在事务外完成（只读已持久化字节）；写审计与置 sealed 在
        同一立即事务内。事务内复核送检状态：若期间被并发冲突冻结则放弃；
        追加式区段在完整覆盖后不可能改变已覆盖字节，故拼装结果仍有效。
        """
        try:
            record = self._build_record(audit_id, blob, payload_sha)
        except codesig.CodeSignatureError as exc:
            row = self._get_submission_row(audit_id)
            if row is not None and row["state"] == "receiving":
                self._freeze_rejected(
                    audit_id, f"结构解析失败：{exc.message}", None, "unparseable"
                )
            raise SubmissionError(
                "unparseable", exc.message, 422, self.get_submission(audit_id)
            )

        record_json = json.dumps(record, sort_keys=True, ensure_ascii=False)
        try:
            with self._tx():
                # 与整包提交/另一连接的封存竞争：已有审计则复用，不重复生成。
                existing = self._get_audit_row(audit_id)
                if existing is not None:
                    if existing["payload_sha256"] == payload_sha:
                        self._mark_sealed_locked(audit_id)
                        out = json.loads(existing["result_json"])
                        out["replayed"] = True
                        return SubmitOutcome(
                            "returned_existing", record=out, http_status=200
                        )
                    raise _ConflictNow("审计标识已被不同字节的载荷占用（并发封存）")

                sub = self._get_submission_row(audit_id)
                if sub is not None:
                    if sub["state"] == "rejected":
                        # 最后一段冲突与封存并发：冲突优先，绝不产出成功审计。
                        raise _AbortSeal(
                            SubmissionError(
                                "conflict",
                                f"送检在封存期间被冲突冻结：{sub['reason']}",
                                409,
                                self._state_from_row(sub),
                            )
                        )
                    if sub["state"] == "sealed":
                        # 同连接/同进程内极端竞争：转复用。
                        existing = self._get_audit_row(audit_id)
                        out = json.loads(existing["result_json"])
                        out["replayed"] = True
                        return SubmitOutcome(
                            "returned_existing", record=out, http_status=200
                        )
                self._conn.execute(
                    "INSERT INTO audits (audit_id, payload_sha256, verdict,"
                    " result_json, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        audit_id,
                        payload_sha,
                        record["verdict"],
                        record_json,
                        record["createdAt"],
                    ),
                )
                if sub is not None:
                    self._mark_sealed_locked(audit_id)
        except _ConflictNow as exc:
            return SubmitOutcome("conflict", error=str(exc), http_status=409)
        except _AbortSeal as exc:
            raise exc.error
        except sqlite3.IntegrityError:
            # 跨连接 PRIMARY KEY 抢注：退化为复用（置 sealed）。
            with self._tx():
                existing = self._get_audit_row(audit_id)
                if existing is None:
                    raise
                if existing["payload_sha256"] != payload_sha:
                    return SubmitOutcome(
                        "conflict",
                        error="审计标识已被不同字节的载荷占用（并发封存）",
                        http_status=409,
                    )
                sub = self._get_submission_row(audit_id)
                if sub is not None and sub["state"] == "receiving":
                    self._mark_sealed_locked(audit_id)
            out = json.loads(existing["result_json"])
            out["replayed"] = True
            return SubmitOutcome(
                "returned_existing", record=out, http_status=200
            )
        return SubmitOutcome("created", record=record, http_status=201)

    def _existing_outcome(self, audit_id: str) -> SubmitOutcome:
        row = self._get_audit_row(audit_id)
        if row is None:
            # 已 sealed 却无审计在正常路径下不可达；防御性报错而非产出新结论。
            raise SubmissionError(
                "sealed", "送检已封存但缺少冻结审计，请联系管理员", 409
            )
        out = json.loads(row["result_json"])
        out["replayed"] = True
        return SubmitOutcome("returned_existing", record=out, http_status=200)

    def _freeze_rejected(self, audit_id: str, reason: str,
                         conflict: Optional[tuple[int, int]], code: str) -> None:
        with self._tx():
            row = self._get_submission_row(audit_id)
            if row is None:
                # 无送检可冻结：直接 404（无需提交，事务内抛错仅回滚空操作）。
                raise SubmissionError("not_found", "该标识没有分段送检记录", 404)
            if row["state"] == "sealed":
                raise SubmissionError(
                    "sealed", "送检已封存，不能改为拒绝", 409,
                    self._state_from_row(row),
                )
            self._set_rejected_locked(audit_id, reason, conflict)
            state = self._build_state(audit_id)
        # 事务提交后再抛出，确保拒绝原因确实持久化。
        raise SubmissionError(
            code, reason, 422 if code == "unparseable" else 409, state
        )

    def _set_rejected_locked(self, audit_id: str, reason: str,
                             conflict: Optional[tuple[int, int]]) -> None:
        cs = ce = None
        if conflict is not None:
            cs, ce = conflict
        self._conn.execute(
            "UPDATE submissions SET state = 'rejected', reason = ?,"
            " conflict_start = ?, conflict_end = ?, updated_at = ?"
            " WHERE audit_id = ?",
            (reason, cs, ce, time.time(), audit_id),
        )

    def _mark_sealed_locked(self, audit_id: str) -> None:
        self._conn.execute(
            "UPDATE submissions SET state = 'sealed', reason = NULL,"
            " conflict_start = NULL, conflict_end = NULL,"
            " sealed_audit_id = ?, updated_at = ? WHERE audit_id = ?",
            (audit_id, time.time(), audit_id),
        )

    def _build_record(self, audit_id: str, blob: bytes,
                      payload_sha: str) -> dict:
        view = codesig.parse_superblob(blob)
        result = codesig.verify_pages(blob, view)
        return {
            "frozen": True,
            "auditId": audit_id,
            "payloadSha256": payload_sha,
            "createdAt": time.time(),
            **result.to_public_dict(),
        }

    # ---- 只读辅助 ------------------------------------------------------------
    def _get_audit_row(self, audit_id: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT payload_sha256, result_json FROM audits WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()

    def _get_submission_row(self, audit_id: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM submissions WHERE audit_id = ?", (audit_id,)
        ).fetchone()

    def _get_chunk_rows(self, audit_id: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT start_off, end_off, seq, data FROM submission_chunks"
            " WHERE audit_id = ? ORDER BY start_off ASC, end_off ASC",
            (audit_id,),
        ).fetchall()

    def _get_chunks(self, audit_id: str) -> list[tuple[int, int, bytes]]:
        return [
            (r["start_off"], r["end_off"], bytes(r["data"]))
            for r in self._get_chunk_rows(audit_id)
        ]

    @staticmethod
    def _first_conflict_range(start: int, end: int, data: bytes,
                              chunks: list[tuple[int, int, bytes]]
                              ) -> Optional[tuple[int, int]]:
        """返回新区间与已收区段首个逐字节冲突的半开区间，无冲突返回 None。

        只检查相交部分；逐字节比较，报告第一个不一致字节起的连续冲突段。
        """
        for c_start, c_end, c_data in chunks:
            lo, hi = max(start, c_start), min(end, c_end)
            if lo >= hi:
                continue  # 不相交
            old_part = c_data[lo - c_start : hi - c_start]
            new_part = data[lo - start : hi - start]
            if old_part == new_part:
                continue
            for k in range(hi - lo):
                if old_part[k] != new_part[k]:
                    first = lo + k
                    last = first
                    while last + 1 < hi and old_part[last + 1 - lo] \
                            != new_part[last + 1 - start]:
                        last += 1
                    return first, last + 1
        return None

    @staticmethod
    def _coverage(ranges: list[tuple[int, int]], total: int
                  ) -> tuple[list[tuple[int, int]], int, Optional[tuple[int, int]]]:
        """合并区间；返回（合并区间、从 0 起的连续覆盖字节数、首个缺口）。"""
        merged: list[list[int]] = []
        for s, e in sorted(ranges):
            if merged and s <= merged[-1][1]:
                if e > merged[-1][1]:
                    merged[-1][1] = e
            else:
                merged.append([s, e])
        contiguous = 0
        for s, e in merged:
            if s <= contiguous:
                if e > contiguous:
                    contiguous = e
            else:
                return [(a, b) for a, b in merged], contiguous, (contiguous, s)
        if contiguous < total:
            return [(a, b) for a, b in merged], contiguous, (contiguous, total)
        return [(a, b) for a, b in merged], contiguous, None

    def _state_for_sealed(self, audit_id: str, digest: str,
                          total: Optional[int]) -> dict:
        # 冻结审计先于送检行存在（或整包路径已封存）时的合成视图。
        return {
            "auditId": audit_id,
            "state": "sealed",
            "totalBytes": total,
            "expectedSha256": digest,
            "coveredRanges": [[0, total]] if total is not None else [],
            "receivedBytes": total,
            "contiguousCoverage": total,
            "firstGap": None,
            "conflictRange": None,
            "reason": None,
        }

    def _state_from_row(self, row: sqlite3.Row,
                        merged: Optional[list[tuple[int, int]]] = None,
                        contiguous: Optional[int] = None,
                        first_gap: Optional[tuple[int, int]] = None) -> dict:
        total = row["total_bytes"]
        if merged is None:
            ranges = [
                (r["start_off"], r["end_off"])
                for r in self._get_chunk_rows(row["audit_id"])
            ]
            merged, contiguous, first_gap = self._coverage(ranges, total)
        received = sum(e - s for s, e in merged)
        conflict = None
        if row["conflict_start"] is not None:
            conflict = [row["conflict_start"], row["conflict_end"]]
        return {
            "auditId": row["audit_id"],
            "state": row["state"],
            "totalBytes": total,
            "expectedSha256": row["expected_sha256"],
            "coveredRanges": [[s, e] for s, e in merged],
            "receivedBytes": received,
            "contiguousCoverage": contiguous,
            "firstGap": list(first_gap) if first_gap is not None else None,
            "conflictRange": conflict,
            "reason": row["reason"],
        }

    def _build_state(self, audit_id: str) -> dict:
        row = self._get_submission_row(audit_id)
        assert row is not None
        return self._state_from_row(row)


class _ConflictNow(Exception):
    """事务内发现标识竞争，触发回滚并返回 409。"""


class _AbortSeal(Exception):
    """封存事务内发现送检已被并发冻结，触发回滚并把内部错误抛给调用方。"""

    def __init__(self, error: SubmissionError):
        super().__init__(error.message)
        self.error = error
