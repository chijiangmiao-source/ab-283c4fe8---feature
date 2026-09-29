"""分段送检 HTTP 端到端测试。

对应 Compose 验收：乱序分段、重启续传、冲突重传冻结、封存后分页证据，
以及分段接口与既有整包接口共存时的语义不变性。
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from app.server import build_server
from tests.fixtures import make_payload


def _make_server(tmp_path, name="audits.sqlite3"):
    httpd = build_server("127.0.0.1", 0, str(tmp_path / name))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    return httpd, t, f"http://{host}:{port}"


@pytest.fixture()
def server(tmp_path):
    httpd, t, base = _make_server(tmp_path)
    yield base
    httpd.shutdown()
    httpd.store.close()
    httpd.server_close()
    t.join(timeout=5)


def _req(base, method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _b64(chunk: bytes) -> str:
    return base64.b64encode(chunk).decode()


def _init(base, audit_id, payload):
    return _req(base, "PUT", f"/api/submissions/{audit_id}", {
        "totalBytes": len(payload),
        "expectedSha256": hashlib.sha256(payload).hexdigest(),
    })


def _seg(base, audit_id, payload, start, end, raw=None):
    data = raw if raw is not None else payload[start:end]
    return _req(base, "PUT", f"/api/submissions/{audit_id}/segments", {
        "start": start, "end": end, "dataBase64": _b64(data),
    })


def _seal(base, audit_id):
    return _req(base, "POST", f"/api/submissions/{audit_id}/seal", {})


def test_full_out_of_order_flow_and_sealed_page_evidence(server):
    payload = make_payload(n_pages=3)
    n = len(payload)
    audit_id = "HTTP-SEG-1"

    status, st = _init(server, audit_id, payload)
    assert status == 201
    assert st["status"] == "receiving"
    assert st["firstGap"] == 0

    # 乱序上传：最后一段、第一段、中间段。
    third = n // 3
    status, st = _seg(server, audit_id, payload, 2 * third, n)
    assert status == 200
    assert st["firstGap"] == 0  # 只有尾部，连续覆盖仍为 0

    status, st = _seg(server, audit_id, payload, 0, third)
    assert st["contiguousBytes"] == third
    assert st["firstGap"] == third

    status, st = _seg(server, audit_id, payload, third, 2 * third)
    assert status == 200
    assert st["firstGap"] is None
    assert st["coveredRanges"] == [[0, n]]

    # 断线后读取已收到的连续覆盖范围。
    status, st = _req(server, "GET", f"/api/submissions/{audit_id}")
    assert status == 200
    assert st["contiguousBytes"] == n
    assert st["receivedBytes"] == n

    # 封存 -> 冻结审计，分页证据齐全。
    status, sealed = _seal(server, audit_id)
    assert status == 201
    assert sealed["status"] == "sealed"
    assert sealed["verdict"] == "verified"
    assert sealed["sealOutcome"] == "sealed_created"
    assert [p["slot"] for p in sealed["pages"]] == [0, 1, 2]
    assert all(p["match"] for p in sealed["pages"])

    # 冻结审计可用既有整包读取接口读取，语义一致。
    status, frozen = _req(server, "GET", f"/api/audits/{audit_id}")
    assert status == 200
    assert frozen["verdict"] == "verified"
    assert frozen["pages"] == sealed["pages"]
    assert frozen["payloadSha256"] == hashlib.sha256(payload).hexdigest()


def test_seal_with_gap_remains_receiving(server):
    payload = make_payload(n_pages=2)
    n = len(payload)
    _init(server, "HTTP-SEG-2", payload)
    _seg(server, "HTTP-SEG-2", payload, 0, 100)
    status, st = _seal(server, "HTTP-SEG-2")
    assert status == 409
    assert st["status"] == "receiving"
    assert st["firstGap"] == 100
    # 审计尚不可读。
    status, _ = _req(server, "GET", "/api/audits/HTTP-SEG-2")
    assert status == 404


def test_conflicting_retransmit_freezes_and_reports_range(server):
    payload = make_payload(n_pages=2)
    audit_id = "HTTP-SEG-3"
    _init(server, audit_id, payload)
    _seg(server, audit_id, payload, 0, 1000)
    # 相同区段、逐字节相同 -> 可重传。
    status, st = _seg(server, audit_id, payload, 500, 1000)
    assert status == 200
    # 相交但字节不同 -> 冻结 rejected。
    evil = bytes(b ^ 0xFF for b in payload[500:1500])
    status, st = _seg(server, audit_id, payload, 500, 1500, raw=evil)
    assert status == 409
    assert st["status"] == "rejected"
    assert st["conflictRange"] == [500, 1000]
    assert st["reason"]

    # 冻结后再传段、封存均拒绝。
    status, st2 = _seg(server, audit_id, payload, 2000, 2100)
    assert status == 409 and st2["status"] == "rejected"
    status, st2 = _seal(server, audit_id)
    assert status == 409 and st2["status"] == "rejected"
    # 不存在成功审计。
    status, _ = _req(server, "GET", "/api/audits/HTTP-SEG-3")
    assert status == 404


def test_repeat_seal_is_idempotent_single_audit(server):
    payload = make_payload(n_pages=2)
    audit_id = "HTTP-SEG-4"
    _init(server, audit_id, payload)
    n = len(payload)
    _seg(server, audit_id, payload, 0, n // 2)
    _seg(server, audit_id, payload, n // 2, n)
    s1, r1 = _seal(server, audit_id)
    s2, r2 = _seal(server, audit_id)
    assert s1 == 201 and s2 == 200
    assert r1["codeDirectorySha256"] == r2["codeDirectorySha256"]
    assert r2["sealOutcome"] == "sealed_reused"
    status, listing = _req(server, "GET", "/api/audits")
    assert listing["auditIds"] == [audit_id]


def test_segment_and_oneshot_apis_coexist(server):
    # 既有整包接口语义不变。
    payload = make_payload(n_pages=2)
    status, rec = _req(server, "POST", "/api/audits", {
        "auditId": "HTTP-SEG-ONESHOT",
        "payloadBase64": _b64(payload),
    })
    assert status == 201 and rec["verdict"] == "verified"

    # 分段送检不能用不同摘要占用同标识。
    wrong = hashlib.sha256(b"q" * len(payload)).hexdigest()
    status, body = _req(server, "PUT", "/api/submissions/HTTP-SEG-ONESHOT", {
        "totalBytes": len(payload), "expectedSha256": wrong,
    })
    assert status == 409
    assert body["status"] == "conflict"

    # 同摘要分段“封存”复用同一份审计，不产生第二份。
    status, body = _req(server, "PUT", "/api/submissions/HTTP-SEG-ONESHOT", {
        "totalBytes": len(payload),
        "expectedSha256": hashlib.sha256(payload).hexdigest(),
    })
    assert status == 200
    assert body["status"] == "sealed"
    assert body["verdict"] == "verified"
    status, listing = _req(server, "GET", "/api/audits")
    assert listing["auditIds"] == ["HTTP-SEG-ONESHOT"]


def test_structure_failure_at_seal_leaves_only_rejection(server):
    raw = b"\x01" * 400
    audit_id = "HTTP-SEG-GARBAGE"
    _init(server, audit_id, raw)
    _seg(server, audit_id, raw, 0, 200)
    _seg(server, audit_id, raw, 200, 400)
    status, body = _seal(server, audit_id)
    assert status == 422
    assert body["status"] == "rejected"
    assert "封存结构复核失败" in body["error"]
    status, st = _req(server, "GET", f"/api/submissions/{audit_id}")
    assert st["status"] == "rejected"
    status, _ = _req(server, "GET", f"/api/audits/{audit_id}")
    assert status == 404


def test_restart_resumes_submission_then_seals(tmp_path):
    db = str(tmp_path / "audits.sqlite3")
    payload = make_payload(n_pages=2)
    n = len(payload)

    httpd1, t1, base1 = _make_server(tmp_path, "audits.sqlite3")
    _init(base1, "HTTP-SEG-R", payload)
    # 乱序发两段，留下中间空洞后“断线”。
    _seg(base1, "HTTP-SEG-R", payload, n - 20, n)
    _seg(base1, "HTTP-SEG-R", payload, 0, 20)
    httpd1.shutdown()
    httpd1.store.close()
    httpd1.server_close()
    t1.join(timeout=5)

    # 进程重启：重新读取已收连续覆盖范围。
    httpd2, t2, base2 = _make_server(tmp_path, "audits.sqlite3")
    try:
        status, st = _req(base2, "GET", "/api/submissions/HTTP-SEG-R")
        assert status == 200
        assert st["status"] == "receiving"
        assert st["coveredRanges"] == [[0, 20], [n - 20, n]]
        assert st["firstGap"] == 20
        # 幂等重开参数一致。
        status, _ = _init(base2, "HTTP-SEG-R", payload)
        assert status == 200
        # 补齐缺口并封存。
        status, st = _seg(base2, "HTTP-SEG-R", payload, 20, n - 20)
        assert st["firstGap"] is None
        status, sealed = _seal(base2, "HTTP-SEG-R")
        assert status == 201
        assert sealed["verdict"] == "verified"
        assert all(p["match"] for p in sealed["pages"])
    finally:
        httpd2.shutdown()
        httpd2.store.close()
        httpd2.server_close()
        t2.join(timeout=5)


def test_segment_64kib_limit_enforced_over_http(server):
    total = 200000
    status, _ = _req(server, "PUT", "/api/submissions/HTTP-SEG-LIMIT", {
        "totalBytes": total,
        "expectedSha256": hashlib.sha256(b"\x00" * total).hexdigest(),
    })
    assert status == 201
    big = b"\x00" * 65537  # 区间在总长内，但单段超过 64 KiB
    status, body = _req(
        server, "PUT", "/api/submissions/HTTP-SEG-LIMIT/segments",
        {"start": 0, "end": 65537, "dataBase64": _b64(big)},
    )
    assert status == 413
    assert body["outcome"] == "invalid"
    assert "64 KiB" in body["error"]
    # 送检未被冻结，仍可读取。
    status, st = _req(server, "GET", "/api/submissions/HTTP-SEG-LIMIT")
    assert st["status"] == "receiving"


def test_get_unknown_submission_404(server):
    status, body = _req(server, "GET", "/api/submissions/nope")
    assert status == 404


def test_bad_segment_base64_rejected(server):
    payload = make_payload(n_pages=1)
    _init(server, "HTTP-SEG-BADB64", payload)
    status, body = _req(
        server, "PUT", "/api/submissions/HTTP-SEG-BADB64/segments",
        {"start": 0, "end": 4, "dataBase64": "@@@"},
    )
    assert status == 400
    assert "Base64" in body["error"]
    # 送检未被冻结。
    status, st = _req(server, "GET", "/api/submissions/HTTP-SEG-BADB64")
    assert st["status"] == "receiving"
