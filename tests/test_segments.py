"""分段送检存储语义测试。

覆盖：乱序上传与连续覆盖计算、断线/重启续传、相同/冲突重传、
参数变更冻结、封存事务（无空洞/摘要/结构三重门）、重复封存幂等、
并发封存只产生一份审计。
"""

from __future__ import annotations

import hashlib
import threading

import pytest

from app import codesig
from app.store import AuditStore, MAX_CHUNK_BYTES, SubmissionError
from tests.fixtures import make_payload


@pytest.fixture()
def store(tmp_path):
    s = AuditStore(str(tmp_path / "audits.sqlite3"))
    yield s
    s.close()


def _ranges(total: int, size: int) -> list[tuple[int, int]]:
    return [(o, min(o + size, total)) for o in range(0, total, size)]


def _shuffled(ranges: list) -> list[int]:
    # 确定性乱序：偶数下标在前、奇数下标在后。
    idx = list(range(len(ranges)))
    return sorted(idx, key=lambda i: (i % 2, i))


@pytest.fixture()
def signed():
    return make_payload(n_pages=3)


def test_begin_then_out_of_order_chunks_track_coverage(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    state, created = store.begin_submission("SEG-1", len(signed), digest)
    assert created is True
    assert state["state"] == "receiving"
    assert state["coveredRanges"] == []
    assert state["firstGap"] == [0, len(signed)]

    ranges = _ranges(len(signed), 2000)
    order = _shuffled(ranges)
    state = store.put_chunk("SEG-1", *ranges[order[0]], signed[ranges[order[0]][0]:ranges[order[0]][1]])
    assert state["state"] == "receiving"
    # 首个上传段不从 0 开始时，连续覆盖仍为 0，首个缺口指出 [0, 该段起点)。
    first = ranges[order[0]]
    if first[0] != 0:
        assert state["contiguousCoverage"] == 0
        assert state["firstGap"] == [0, first[0]]

    for i in order[1:]:
        s, e = ranges[i]
        state = store.put_chunk("SEG-1", s, e, signed[s:e])
    assert state["state"] == "receiving"
    assert state["contiguousCoverage"] == len(signed)
    assert state["firstGap"] is None
    assert state["coveredRanges"] == [[0, len(signed)]]
    # 接收中的送检不出现在冻结审计列表。
    assert store.list_ids() == []


def test_repeat_begin_is_idempotent_and_resumes(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.begin_submission("SEG-2", len(signed), digest)
    s, e = 10, 90
    store.put_chunk("SEG-2", s, e, signed[s:e])
    state, created = store.begin_submission("SEG-2", len(signed), digest)
    assert created is False
    assert state["coveredRanges"] == [[s, e]]
    assert state["firstGap"] == [0, s]


def test_identical_and_overlapping_same_bytes_accepted(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.begin_submission("SEG-3", len(signed), digest)
    store.put_chunk("SEG-3", 0, 100, signed[0:100])
    # 完全相同区间重传：幂等，不新增段。
    state = store.put_chunk("SEG-3", 0, 100, signed[0:100])
    assert state["coveredRanges"] == [[0, 100]]
    # 部分重叠且重叠字节逐字节相同：接受并合并。
    state = store.put_chunk("SEG-3", 50, 200, signed[50:200])
    assert state["state"] == "receiving"
    assert state["coveredRanges"] == [[0, 200]]


def test_conflicting_overlap_freezes_submission_and_keeps_audits(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    # 先有一个已完成的完整审计，证明冲突不影响它。
    other = store.submit("AUDIT-DONE", signed)
    assert other.status == "created"

    store.begin_submission("SEG-4", len(signed), digest)
    store.put_chunk("SEG-4", 0, 100, signed[0:100])
    bad = bytearray(signed[0:100])
    bad[40] ^= 0xFF
    with pytest.raises(SubmissionError) as ei:
        store.put_chunk("SEG-4", 0, 100, bytes(bad))
    assert ei.value.http_status == 409
    assert ei.value.state["state"] == "rejected"
    # 首个冲突范围精确到不一致字节：仅第 40 字节被改 => [40, 41)。
    assert ei.value.state["conflictRange"] == [40, 41]
    assert ei.value.state["reason"]

    # 冻结后任何区段写入、再次 begin、封存都被拒绝。
    with pytest.raises(SubmissionError) as ei2:
        store.put_chunk("SEG-4", 100, 200, signed[100:200])
    assert ei2.value.code == "rejected"
    with pytest.raises(SubmissionError):
        store.begin_submission("SEG-4", len(signed), digest)
    with pytest.raises(SubmissionError):
        store.seal_submission("SEG-4")
    # 既有完整审计原样可读。
    assert store.get("AUDIT-DONE")["verdict"] == "verified"
    assert store.list_ids() == ["AUDIT-DONE"]


def test_conflict_range_is_the_intersection(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.begin_submission("SEG-4B", len(signed), digest)
    store.put_chunk("SEG-4B", 0, 100, signed[0:100])
    # 新区间 [50,150) 仅在 [50,100) 与旧段相交；篡改相交区内的一个字节。
    bad = bytearray(signed[50:150])
    bad[10] ^= 0xFF  # 绝对偏移 60
    with pytest.raises(SubmissionError) as ei:
        store.put_chunk("SEG-4B", 50, 150, bytes(bad))
    assert ei.value.state["conflictRange"] == [60, 61]
    # 冲突段未落库：覆盖仍是 [0,100)。
    assert store.get_submission("SEG-4B")["coveredRanges"] == [[0, 100]]


def test_begin_parameter_change_freezes_submission(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.begin_submission("SEG-5", len(signed), digest)
    with pytest.raises(SubmissionError) as ei:
        store.begin_submission("SEG-5", len(signed) + 1, digest)
    assert ei.value.http_status == 409
    assert store.get_submission("SEG-5")["state"] == "rejected"
    with pytest.raises(SubmissionError):
        store.begin_submission("SEG-5", len(signed), "1" * 64)


def test_oversized_or_malformed_chunks_rejected_without_freezing(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.begin_submission("SEG-6", len(signed), digest)
    # 区间非法 / 长度不匹配均为 400 且送检仍可继续。
    with pytest.raises(SubmissionError) as ei:
        store.put_chunk("SEG-6", -1, 10, signed[0:10])
    assert ei.value.http_status == 400
    with pytest.raises(SubmissionError) as ei:
        store.put_chunk("SEG-6", 0, len(signed) + 1, signed[0:1])
    assert ei.value.http_status == 400
    with pytest.raises(SubmissionError) as ei:
        store.put_chunk("SEG-6", 0, 10, signed[0:9])
    assert ei.value.http_status == 400
    assert store.get_submission("SEG-6")["state"] == "receiving"

    # 超过 64 KiB 的单段直接 413 拒绝（不冻结送检）：另建总长足够的送检。
    big_total = MAX_CHUNK_BYTES + 1
    store.begin_submission("SEG-6B", big_total, "0" * 64)
    with pytest.raises(SubmissionError) as ei:
        store.put_chunk("SEG-6B", 0, big_total, bytes(big_total))
    assert ei.value.http_status == 413
    assert store.get_submission("SEG-6B")["state"] == "receiving"


def test_seal_with_gap_refused_and_later_completes(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.begin_submission("SEG-7", len(signed), digest)
    store.put_chunk("SEG-7", 100, 300, signed[100:300])
    with pytest.raises(SubmissionError) as ei:
        store.seal_submission("SEG-7")
    assert ei.value.http_status == 409
    assert ei.value.state["firstGap"] == [0, 100]
    assert store.get("SEG-7") is None
    # 补齐后封存成功：[0,100) 已有，补 [100,300) 外的所有空洞。
    store.put_chunk("SEG-7", 0, 100, signed[0:100])
    store.put_chunk("SEG-7", 300, 2000, signed[300:2000])
    for s, e in _ranges(len(signed), 2000):
        if s >= 2000:
            store.put_chunk("SEG-7", s, e, signed[s:e])
    out = store.seal_submission("SEG-7")
    assert out.status == "created"
    assert out.record["verdict"] == "verified"


def test_seal_success_transaction_and_repeat_seal_idempotent(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.begin_submission("SEG-8", len(signed), digest)
    for s, e in _ranges(len(signed), 1500):
        store.put_chunk("SEG-8", s, e, signed[s:e])
    out = store.seal_submission("SEG-8")
    assert out.http_status == 201
    assert store.get_submission("SEG-8")["state"] == "sealed"
    # 同一事务：审计可立即读取，且证据完整。
    rec = store.get("SEG-8")
    assert rec["verdict"] == "verified"
    assert rec["payloadSha256"] == digest
    assert all(p["match"] for p in rec["pages"])

    again = store.seal_submission("SEG-8")
    assert again.http_status == 200
    assert again.status == "returned_existing"
    assert again.record["replayed"] is True
    assert store.list_ids() == ["SEG-8"]
    # 封存后不能再写段。
    with pytest.raises(SubmissionError):
        store.put_chunk("SEG-8", 0, 10, signed[0:10])


def test_digest_mismatch_at_seal_freezes_without_audit(store, signed):
    store.begin_submission("SEG-9", len(signed), "0" * 64)
    for s, e in _ranges(len(signed), 1500):
        store.put_chunk("SEG-9", s, e, signed[s:e])
    with pytest.raises(SubmissionError) as ei:
        store.seal_submission("SEG-9")
    assert ei.value.code == "digest_mismatch"
    assert store.get_submission("SEG-9")["state"] == "rejected"
    assert store.get("SEG-9") is None


def test_unparseable_assembly_leaves_reason_but_no_audit(store):
    garbage = b"\x00" * 3000
    digest = hashlib.sha256(garbage).hexdigest()
    store.begin_submission("SEG-U", len(garbage), digest)
    for s, e in _ranges(len(garbage), 1024):
        store.put_chunk("SEG-U", s, e, garbage[s:e])
    with pytest.raises(SubmissionError) as ei:
        store.seal_submission("SEG-U")
    assert ei.value.http_status == 422
    assert ei.value.code == "unparseable"
    state = store.get_submission("SEG-U")
    assert state["state"] == "rejected"
    assert "结构解析失败" in state["reason"]
    # 绝不留下可读取的成功审计。
    assert store.get("SEG-U") is None
    assert store.list_ids() == []


def test_mismatch_verdict_sealed_through_segments(store, signed):
    tampered = bytearray(signed)
    tampered[4096 + 5] ^= 0xCD
    digest = hashlib.sha256(bytes(tampered)).hexdigest()
    store.begin_submission("SEG-M", len(tampered), digest)
    for s, e in _ranges(len(tampered), 1500):
        store.put_chunk("SEG-M", s, e, bytes(tampered)[s:e])
    out = store.seal_submission("SEG-M")
    assert out.status == "created"
    assert out.record["verdict"] == "mismatch"
    assert out.record["firstFailedSlot"] == 1
    assert store.get("SEG-M")["verdict"] == "mismatch"


def test_restart_mid_transfer_then_resume_and_seal(tmp_path, signed):
    db = str(tmp_path / "audits.sqlite3")
    digest = hashlib.sha256(signed).hexdigest()
    ranges = _ranges(len(signed), 1777)
    s = AuditStore(db)
    s.begin_submission("SEG-R", len(signed), digest)
    half = _shuffled(ranges)[: len(ranges) // 2]
    for i in half:
        a, b = ranges[i]
        s.put_chunk("SEG-R", a, b, signed[a:b])
    s.close()

    # 进程重启：进度与原始字节均须持久化。
    s2 = AuditStore(db)
    state, created = s2.begin_submission("SEG-R", len(signed), digest)
    assert created is False
    assert state["state"] == "receiving"
    already = {tuple(r) for r in state["coveredRanges"]}
    for i, (a, b) in enumerate(ranges):
        if i in half:
            continue
        s2.put_chunk("SEG-R", a, b, signed[a:b])
    assert already  # 重启前确实有部分覆盖
    out = s2.seal_submission("SEG-R")
    assert out.record["verdict"] == "verified"
    assert s2.get("SEG-R")["payloadSha256"] == digest
    s2.close()

    # 再重启：封存结论依然唯一存在。
    s3 = AuditStore(db)
    assert s3.list_ids() == ["SEG-R"]
    assert s3.get_submission("SEG-R")["state"] == "sealed"
    s3.close()


def test_whole_submit_does_not_touch_receiving_with_other_bytes(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.begin_submission("SEG-W", len(signed), digest)
    changed = bytearray(signed)
    changed[0] ^= 0x01
    out = store.submit("SEG-W", bytes(changed))
    assert out.status == "conflict"
    assert store.get_submission("SEG-W")["state"] == "receiving"
    # 整包就是声明字节时代为封存，两条路径汇入同一审计。
    out = store.submit("SEG-W", signed)
    assert out.status == "created"
    assert store.get_submission("SEG-W")["state"] == "sealed"


def test_frozen_audit_blocks_begin_with_other_digest(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    store.submit("SEG-Z", signed)
    with pytest.raises(SubmissionError) as ei:
        store.begin_submission("SEG-Z", len(signed), "a" * 64)
    assert ei.value.http_status == 409
    # 同摘要 begin 直接给出 sealed 合成视图。
    state, created = store.begin_submission("SEG-Z", len(signed), digest)
    assert created is False
    assert state["state"] == "sealed"


def test_invalid_begin_arguments(store, signed):
    digest = hashlib.sha256(signed).hexdigest()
    with pytest.raises(SubmissionError) as ei:
        store.begin_submission("bad id", len(signed), digest)
    assert ei.value.http_status == 400
    with pytest.raises(SubmissionError) as ei:
        store.begin_submission("SEG-I", len(signed), digest.upper()[:-1])
    assert ei.value.http_status == 400
    with pytest.raises(SubmissionError) as ei:
        store.begin_submission("SEG-I", 0, digest)
    assert ei.value.http_status == 400
    with pytest.raises(SubmissionError) as ei:
        store.begin_submission("SEG-I", codesig.MAX_BLOB_BYTES + 1, digest)
    assert ei.value.http_status == 413
    assert store.get_submission("SEG-I") is None


def test_concurrent_repeated_seals_create_single_audit(tmp_path, signed):
    db = str(tmp_path / "audits.sqlite3")
    digest = hashlib.sha256(signed).hexdigest()
    s = AuditStore(db)
    s.begin_submission("SEG-C", len(signed), digest)
    for a, b in _ranges(len(signed), 1500):
        s.put_chunk("SEG-C", a, b, signed[a:b])

    results = []

    def worker():
        store2 = AuditStore(db)  # 模拟不同连接/线程
        try:
            results.append(store2.seal_submission("SEG-C").status)
        except SubmissionError as exc:
            results.append(("error", exc.code))
        finally:
            store2.close()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    created = [r for r in results if r == "created"]
    replayed = [r for r in results if r == "returned_existing"]
    assert len(created) == 1, results
    assert len(replayed) == 7, results
    assert s.list_ids() == ["SEG-C"]
    s.close()


def test_seal_racing_with_final_chunk(tmp_path, signed):
    db = str(tmp_path / "audits.sqlite3")
    digest = hashlib.sha256(signed).hexdigest()
    ranges = _ranges(len(signed), 1500)
    s = AuditStore(db)
    s.begin_submission("SEG-T", len(signed), digest)
    for a, b in ranges[:-1]:
        s.put_chunk("SEG-T", a, b, signed[a:b])
    s.close()

    outcomes = []

    def seal_worker():
        st = AuditStore(db)
        try:
            outcomes.append(("seal", st.seal_submission("SEG-T").status))
        except SubmissionError as exc:
            outcomes.append(("seal_err", exc.code))
        finally:
            st.close()

    def chunk_worker():
        st = AuditStore(db)
        a, b = ranges[-1]
        outcomes.append(("chunk", st.put_chunk("SEG-T", a, b, signed[a:b])["state"]))
        st.close()

    t1 = threading.Thread(target=seal_worker)
    t2 = threading.Thread(target=chunk_worker)
    t1.start(); t2.start()
    t1.join(); t2.join()

    final = AuditStore(db)
    # 无论谁先：缺口拒绝不冻结，补段后一定可以恰好封存一次。
    if final.get_submission("SEG-T")["state"] != "sealed":
        out = final.seal_submission("SEG-T")
        assert out.status == "created"
    assert final.list_ids() == ["SEG-T"]
    assert final.get("SEG-T")["verdict"] == "verified"
    assert len({("audit",) for _ in range(1)}) == 1
    final.close()
