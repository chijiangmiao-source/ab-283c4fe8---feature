"""分段送检存储语义测试。

覆盖：乱序区段、连续覆盖/首个缺口、相同区段重传、重叠冲突冻结、
断线（关闭重开）续传、封存事务（新审计/复用/重复封存/并发封存）、
整体摘要不符与结构解析失败只留拒绝原因，以及既有完整审计不受影响。
"""

from __future__ import annotations

import hashlib
import threading

import pytest

from app.store import AuditStore, MAX_SEGMENT_BYTES
from tests.fixtures import make_payload


@pytest.fixture()
def store(tmp_path):
    path = str(tmp_path / "audits.sqlite3")
    s = AuditStore(path)
    yield s
    s.close()


def _open(store: AuditStore, audit_id: str, payload: bytes):
    return store.init_submission(
        audit_id, len(payload), hashlib.sha256(payload).hexdigest()
    )


def _put(store: AuditStore, audit_id: str, payload: bytes, start: int, end: int):
    return store.put_segment(audit_id, start, end, payload[start:end])


def test_init_creates_receiving_and_idempotent_reopen(store):
    payload = make_payload(n_pages=2)
    out = _open(store, "SEG-1", payload)
    assert out.status == "created"
    assert out.http_status == 201
    st = out.state
    assert st["status"] == "receiving"
    assert st["totalBytes"] == len(payload)
    assert st["firstGap"] == 0
    assert st["coveredRanges"] == []

    again = _open(store, "SEG-1", payload)
    assert again.status == "opened"
    assert again.http_status == 200
    assert again.state["status"] == "receiving"


def test_init_conflict_when_total_or_digest_changes_freezes(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-2", payload)
    _put(store, "SEG-2", payload, 0, 50)
    other = hashlib.sha256(b"x" * len(payload)).hexdigest()
    out = store.init_submission("SEG-2", len(payload), other)
    assert out.status == "rejected"
    assert out.http_status == 409
    assert out.state["status"] == "rejected"
    out2 = store.init_submission("SEG-2", len(payload) + 1,
                                 hashlib.sha256(payload).hexdigest())
    assert out2.status == "rejected"
    # 已冻结：之后即使参数改回原值也仍是 rejected。
    assert _open(store, "SEG-2", payload).status == "rejected"
    assert store.get("SEG-2") is None  # 没有成功审计


def test_invalid_init_params(store):
    payload = make_payload(n_pages=1)
    assert _open(store, "bad id", payload).status == "invalid"
    out = store.init_submission("SEG-X", len(payload), "nothex")
    assert out.status == "invalid"
    out = store.init_submission("SEG-X", 0, hashlib.sha256(payload).hexdigest())
    assert out.status == "invalid"
    out = store.init_submission(
        "SEG-X", 2 * 1024 * 1024 + 1, hashlib.sha256(payload).hexdigest()
    )
    assert out.status == "invalid"
    assert out.http_status == 413
    assert store.get_submission("SEG-X") is None


def test_out_of_order_segments_report_contiguous_coverage_and_gap(store):
    payload = make_payload(n_pages=3)
    _open(store, "SEG-3", payload)
    n = len(payload)

    out = _put(store, "SEG-3", payload, n - 100, n)  # 先传尾部
    assert out.status == "stored"
    assert out.state["contiguousBytes"] == 0
    assert out.state["firstGap"] == 0
    assert out.state["coveredRanges"] == [[n - 100, n]]

    out = _put(store, "SEG-3", payload, 0, 50)  # 头部
    assert out.state["contiguousBytes"] == 50
    assert out.state["firstGap"] == 50

    out = _put(store, "SEG-3", payload, 50, n - 100)  # 中间补齐
    assert out.state["firstGap"] is None
    assert out.state["contiguousBytes"] == n
    assert out.state["coveredRanges"] == [[0, n]]


def test_exact_same_segment_reupload_is_idempotent(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-4", payload)
    first = _put(store, "SEG-4", payload, 10, 80)
    assert first.status == "stored"
    second = _put(store, "SEG-4", payload, 10, 80)
    assert second.status == "stored"
    assert second.state["coveredRanges"] == [[10, 80]]


def test_overlapping_same_bytes_merge(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-5", payload)
    _put(store, "SEG-5", payload, 0, 100)
    _put(store, "SEG-5", payload, 50, 150)  # 重叠 [50,100) 字节相同
    _put(store, "SEG-5", payload, 100, 200)  # 相邻
    st = store.get_submission("SEG-5")
    assert st["coveredRanges"] == [[0, 200]]


def test_overlapping_conflicting_bytes_freezes_rejected(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-6", payload)
    _put(store, "SEG-6", payload, 0, 100)
    # 伪造与已收区段在 [50,100) 不同的字节。
    evil = b"\xAA" * 100
    out = store.put_segment("SEG-6", 50, 150, evil)
    assert out.status == "rejected"
    assert out.http_status == 409
    assert out.state["status"] == "rejected"
    assert out.state["conflictRange"] == [50, 100]
    assert "[50,100)" in out.error

    # 冻结后任何区段、重开、封存都被拒绝，且状态不再变化。
    assert _put(store, "SEG-6", payload, 200, 250).status == "rejected"
    assert _open(store, "SEG-6", payload).status == "rejected"
    seal_out = store.seal_submission("SEG-6")
    assert seal_out.status == "rejected"
    assert store.get("SEG-6") is None  # 没有留下成功审计


def test_segment_validation_does_not_freeze(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-7", payload)
    n = len(payload)
    assert store.put_segment("SEG-7", -1, 10, payload[0:10]).status == "invalid"
    assert store.put_segment("SEG-7", 5, 5, b"").status == "invalid"
    assert store.put_segment("SEG-7", 0, n + 1, payload + b"\x00").status == "invalid"
    assert store.put_segment("SEG-7", 0, 10, payload[0:9]).status == "invalid"
    big = b"\x00" * (MAX_SEGMENT_BYTES + 1)
    # 送检总长允许 2 MiB：单独建一个足够大的送检来触发单段 64 KiB 上限。
    store.init_submission(
        "SEG-7B", 100000, hashlib.sha256(b"z" * 100000).hexdigest()
    )
    out = store.put_segment("SEG-7B", 0, len(big), big)
    assert out.status == "invalid"
    assert out.http_status == 413
    # 参数错误不冻结送检。
    assert store.get_submission("SEG-7")["status"] == "receiving"


def test_put_and_seal_unknown_submission_404(store):
    payload = make_payload(n_pages=1)
    assert store.put_segment("NOPE", 0, 1, b"x").status == "not_found"
    assert store.seal_submission("NOPE").status == "not_found"


def test_seal_with_gap_is_incomplete_and_stays_receiving(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-8", payload)
    n = len(payload)
    _put(store, "SEG-8", payload, 0, 100)
    _put(store, "SEG-8", payload, 200, n)
    out = store.seal_submission("SEG-8")
    assert out.status == "incomplete"
    assert out.http_status == 409
    assert out.state["firstGap"] == 100
    assert store.get_submission("SEG-8")["status"] == "receiving"


def test_unordered_seal_creates_verified_audit_transactionally(store):
    payload = make_payload(n_pages=3)
    _open(store, "SEG-9", payload)
    n = len(payload)
    # 乱序：尾、中、头。
    _put(store, "SEG-9", payload, n - 50, n)
    _put(store, "SEG-9", payload, 100, n - 50)
    _put(store, "SEG-9", payload, 0, 100)
    out = store.seal_submission("SEG-9")
    assert out.status == "sealed_created"
    assert out.http_status == 201
    assert out.record["verdict"] == "verified"
    assert out.state["status"] == "sealed"
    assert out.state["frozenAuditId"] == "SEG-9"
    # 同一事务后：审计可读，且 payloadSha256 一致。
    frozen = store.get("SEG-9")
    assert frozen is not None
    assert frozen["payloadSha256"] == hashlib.sha256(payload).hexdigest()
    assert frozen["pages"] == out.record["pages"]


def test_repeat_seal_returns_same_audit(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-10", payload)
    n = len(payload)
    _put(store, "SEG-10", payload, 0, n // 2)
    _put(store, "SEG-10", payload, n // 2, n)
    first = store.seal_submission("SEG-10")
    second = store.seal_submission("SEG-10")
    assert second.status == "sealed_reused"
    assert second.http_status == 200
    assert second.record["codeDirectorySha256"] == \
        first.record["codeDirectorySha256"]
    assert store.list_ids() == ["SEG-10"]


def test_restart_resumes_receiving_and_seals(tmp_path):
    path = str(tmp_path / "audits.sqlite3")
    payload = make_payload(n_pages=2)
    s1 = AuditStore(path)
    _open(s1, "SEG-11", payload)
    n = len(payload)
    _put(s1, "SEG-11", payload, n - 10, n)
    _put(s1, "SEG-11", payload, 0, 10)
    s1.close()

    # 模拟进程重启：区段与覆盖范围必须持久化。
    s2 = AuditStore(path)
    st = s2.get_submission("SEG-11")
    assert st["status"] == "receiving"
    assert st["coveredRanges"] == [[0, 10], [n - 10, n]]
    assert st["firstGap"] == 10
    _put(s2, "SEG-11", payload, 10, n - 10)
    out = s2.seal_submission("SEG-11")
    assert out.status == "sealed_created"
    assert out.record["verdict"] == "verified"
    s2.close()

    # 再次重启：sealed 状态与冻结审计都在。
    s3 = AuditStore(path)
    assert s3.get_submission("SEG-11")["status"] == "sealed"
    assert s3.get("SEG-11")["verdict"] == "verified"
    assert s3.seal_submission("SEG-11").status == "sealed_reused"
    s3.close()


def test_sha256_mismatch_at_seal_freezes_rejected(store):
    payload = make_payload(n_pages=2)
    # 以一个错误摘要建立送检，但上传的是真实 payload 全部字节。
    wrong = hashlib.sha256(b"different-bytes").hexdigest()
    store.init_submission("SEG-12", len(payload), wrong)
    n = len(payload)
    _put(store, "SEG-12", payload, 0, n // 2)
    _put(store, "SEG-12", payload, n // 2, n)
    out = store.seal_submission("SEG-12")
    assert out.status == "rejected"
    assert out.http_status == 409
    assert "SHA-256" in out.error
    assert store.get_submission("SEG-12")["status"] == "rejected"
    assert store.get("SEG-12") is None


def test_structure_failure_at_seal_only_leaves_rejection(store):
    # 字节完整、摘要一致，但内容不是合法 SuperBlob。
    payload = b"\x00" * 300
    _open(store, "SEG-13", payload)
    _put(store, "SEG-13", payload, 0, 150)
    _put(store, "SEG-13", payload, 150, 300)
    out = store.seal_submission("SEG-13")
    assert out.status == "rejected"
    assert out.http_status == 422
    assert "封存结构复核失败" in out.error
    assert store.get_submission("SEG-13")["status"] == "rejected"
    assert store.get("SEG-13") is None
    # 列表里没有成功审计。
    assert store.list_ids() == []


def test_sealed_page_evidence_matches_direct_submit(store):
    payload = make_payload(n_pages=3)
    direct = store.submit("SEG-DIRECT", payload)
    _open(store, "SEG-SEG", payload)
    n = len(payload)
    # 乱序分段（后段先传）。
    cut = n // 2
    _put(store, "SEG-SEG", payload, cut, n)
    _put(store, "SEG-SEG", payload, 0, cut)
    sealed = store.seal_submission("SEG-SEG")
    assert sealed.record["verdict"] == direct.record["verdict"]
    assert sealed.record["pages"] == direct.record["pages"]
    assert sealed.record["codeDirectorySha256"] == \
        direct.record["codeDirectorySha256"]


def test_seal_reuses_existing_same_digest_audit(store):
    payload = make_payload(n_pages=2)
    direct = store.submit("SEG-14", payload)
    out = _open(store, "SEG-14", payload)
    assert out.status == "sealed_reused"
    assert out.record["codeDirectorySha256"] == \
        direct.record["codeDirectorySha256"]
    assert store.get_submission("SEG-14")["status"] == "sealed"
    assert store.list_ids() == ["SEG-14"]


def test_segment_flow_cannot_disturb_existing_different_audit(store):
    payload = make_payload(n_pages=2)
    store.submit("SEG-15", payload)
    other_digest = hashlib.sha256(b"x" * len(payload)).hexdigest()
    out = store.init_submission("SEG-15", len(payload), other_digest)
    assert out.status == "conflict"
    assert out.http_status == 409
    kept = store.get("SEG-15")
    assert kept["payloadSha256"] == hashlib.sha256(payload).hexdigest()
    assert store.get_submission("SEG-15") is None


def test_concurrent_seals_create_single_audit(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-16", payload)
    n = len(payload)
    _put(store, "SEG-16", payload, 0, n)
    results = []

    def seal():
        results.append(store.seal_submission("SEG-16"))

    threads = [threading.Thread(target=seal) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    statuses = sorted(r.status for r in results)
    assert statuses[0] in ("sealed_created", "sealed_reused")
    assert set(statuses) <= {"sealed_created", "sealed_reused"}
    assert statuses.count("sealed_created") == 1
    assert store.list_ids() == ["SEG-16"]
    digests = {r.record["codeDirectorySha256"] for r in results}
    assert digests == {store.get("SEG-16")["codeDirectorySha256"]}


def test_tampered_page_through_segments_freezes_mismatch_audit(store):
    # 摘要对应的是被篡改后的字节：结构合法但页哈希不符，mismatch 仍应
    # 成为完整、可读的冻结结论（区别于结构失败 -> rejected）。
    payload = bytearray(make_payload(n_pages=3))
    payload[4096 + 5] ^= 0x77
    payload = bytes(payload)
    _open(store, "SEG-TAMPER", payload)
    n = len(payload)
    _put(store, "SEG-TAMPER", payload, 0, n // 2)
    _put(store, "SEG-TAMPER", payload, n // 2, n)
    out = store.seal_submission("SEG-TAMPER")
    assert out.status == "sealed_created"
    assert out.record["verdict"] == "mismatch"
    assert out.record["firstFailedSlot"] == 1
    frozen = store.get("SEG-TAMPER")
    assert frozen["verdict"] == "mismatch"
    assert frozen["pages"][1]["match"] is False
    assert store.get_submission("SEG-TAMPER")["status"] == "sealed"


def test_payload_over_64kib_requires_multiple_segments(store):
    payload = make_payload(n_pages=17)  # 16*4096+37 = 65573 字节
    assert len(payload) > MAX_SEGMENT_BYTES
    _open(store, "SEG-BIG", payload)
    n = len(payload)
    # 乱序且每段不超过 64 KiB。
    _put(store, "SEG-BIG", payload, MAX_SEGMENT_BYTES, n)
    _put(store, "SEG-BIG", payload, 0, MAX_SEGMENT_BYTES)
    st = store.get_submission("SEG-BIG")
    assert st["firstGap"] is None
    out = store.seal_submission("SEG-BIG")
    assert out.status == "sealed_created"
    assert out.record["verdict"] == "verified"
    assert out.record["codeSlots"] == 17


def test_segment_upload_concurrent_with_seal(store):
    payload = make_payload(n_pages=2)
    _open(store, "SEG-17", payload)
    n = len(payload)
    _put(store, "SEG-17", payload, 0, n - 1)  # 差一字节

    seal_holder = {}

    def do_seal():
        seal_holder["out"] = store.seal_submission("SEG-17")

    t = threading.Thread(target=do_seal)
    t.start()
    t.join(timeout=5)
    # 缺口存在时封存不得挂起，直接 incomplete。
    assert seal_holder["out"].status == "incomplete"
    last = _put(store, "SEG-17", payload, n - 1, n)
    assert last.state["firstGap"] is None
    out = store.seal_submission("SEG-17")
    assert out.status == "sealed_created"
    assert store.get("SEG-17")["verdict"] == "verified"
    assert len(store.get("SEG-17")["pages"]) == out.record["codeSlots"]
