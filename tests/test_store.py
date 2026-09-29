"""冻结审计存储语义测试：幂等、复用拒绝、解析失败不落库。"""

from __future__ import annotations

import hashlib

import pytest

from app import codesig
from app.store import AuditStore
from tests.fixtures import make_payload


@pytest.fixture()
def store(tmp_path):
    s = AuditStore(str(tmp_path / "audits.sqlite3"))
    yield s
    s.close()


def test_first_submit_freezes_and_can_reread(store):
    payload = make_payload()
    out = store.submit("SAT-001", payload)
    assert out.status == "created"
    assert out.http_status == 201
    rec = out.record
    assert rec["frozen"] is True
    assert rec["verdict"] == "verified"
    assert rec["auditId"] == "SAT-001"
    assert rec["payloadSha256"] == hashlib.sha256(payload).hexdigest()
    assert store.get("SAT-001")["verdict"] == "verified"


def test_same_id_same_bytes_returns_original_audit(store):
    payload = make_payload()
    first = store.submit("SAT-002", payload)
    second = store.submit("SAT-002", payload)
    assert second.status == "returned_existing"
    assert second.http_status == 200
    a, b = first.record, second.record
    # 结论与证据逐字节一致（replayed 标记除外）。
    a.pop("replayed", None)
    assert b.pop("replayed", None) is True
    assert a == b
    assert store.list_ids() == ["SAT-002"]


def test_reused_id_with_different_bytes_rejected_and_record_kept(store):
    payload = make_payload()
    store.submit("SAT-003", payload)

    changed = bytearray(payload)
    changed[123] ^= 0x5A  # 修改代码区
    out = store.submit("SAT-003", bytes(changed))
    assert out.status == "conflict"
    assert out.http_status == 409
    assert "标识" in (out.error or "")

    kept = store.get("SAT-003")
    assert kept["payloadSha256"] == hashlib.sha256(payload).hexdigest()
    assert kept["verdict"] == "verified"
    assert store.list_ids() == ["SAT-003"]


def test_tampered_page_freezes_mismatch_and_points_first_failure(store):
    payload = bytearray(make_payload(n_pages=3))
    payload[4096 + 7] ^= 0xFF
    out = store.submit("SAT-004", bytes(payload))
    assert out.status == "created"
    rec = out.record
    assert rec["verdict"] == "mismatch"
    assert rec["firstFailedSlot"] == 1
    assert not rec["pages"][1]["match"]
    # mismatch 也是完整冻结结论，可重复读取。
    assert store.get("SAT-004")["verdict"] == "mismatch"


def test_unparseable_leaves_no_success_nor_any_record(store):
    before = store.list_ids()
    out = store.submit("SAT-BAD", b"\x00" * 64)
    assert out.status == "unparseable"
    assert out.http_status == 422
    assert store.list_ids() == before
    assert store.get("SAT-BAD") is None


def test_unsupported_hash_type_leaves_no_record(store):
    from tests.fixtures import build_signed_payload

    bad = build_signed_payload(bytes(range(256)) * 20, page_exp=8, hash_type=1)
    out = store.submit("SAT-SHA1", bad)
    assert out.status == "unparseable"
    assert store.get("SAT-SHA1") is None
    assert store.list_ids() == []


def test_rejected_id_can_still_be_used_after_bad_structure(store):
    # 结构失败不占用标识；之后同标识提交合法载荷应成功创建。
    out = store.submit("SAT-RETRY", b"not a signature at all")
    assert out.status == "unparseable"
    ok = store.submit("SAT-RETRY", make_payload())
    assert ok.status == "created"
    assert ok.record["verdict"] == "verified"


@pytest.mark.parametrize("bad_id", ["", "id with space", "中文字符", "a" * 129, "/etc"])
def test_invalid_audit_id(store, bad_id):
    out = store.submit(bad_id, make_payload())
    assert out.status == "invalid"
    assert out.http_status == 400


def test_oversized_payload_rejected_before_parsing(store):
    out = store.submit("SAT-BIG", b"\x00" * (codesig.MAX_BLOB_BYTES + 1))
    assert out.status == "invalid"
    assert out.http_status == 413
    assert store.list_ids() == []


def test_empty_payload_rejected(store):
    out = store.submit("SAT-EMPTY", b"")
    assert out.status == "invalid"
    assert store.list_ids() == []


def test_distinct_ids_distinct_records(store):
    p1 = make_payload(n_pages=2)
    p2 = make_payload(n_pages=3)
    store.submit("SAT-A", p1)
    store.submit("SAT-B", p2)
    assert store.get("SAT-A")["codeSlots"] == 2
    assert store.get("SAT-B")["codeSlots"] == 3
