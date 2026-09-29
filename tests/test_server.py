"""HTTP 端到端测试：真实 socket 上的健康状态、提交、冻结读取与幂等。"""

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
from tests.fixtures import make_payload, build_signed_payload


@pytest.fixture()
def server(tmp_path):
    httpd = build_server("127.0.0.1", 0, str(tmp_path / "audits.sqlite3"))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    base = f"http://{host}:{port}"
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


def _post_payload(base, audit_id, payload):
    return _req(
        base, "POST", "/api/audits",
        {"auditId": audit_id, "payloadBase64": base64.b64encode(payload).decode()},
    )


def test_healthz_reports_ok(server):
    status, body = _req(server, "GET", "/healthz")
    assert status == 200
    assert body["status"] == "ok"
    assert body["supportedHashType"] == "sha256"
    assert body["maxPayloadBytes"] == 2 * 1024 * 1024


def test_index_page_served(server):
    with urllib.request.urlopen(server + "/", timeout=5) as resp:
        html = resp.read().decode()
    assert "签封目录分页审计" in html
    assert "payloadBase64" in html


def test_submit_verify_replay_and_get(server):
    payload = make_payload(n_pages=3)
    status, rec = _post_payload(server, "HTTP-1", payload)
    assert status == 201
    assert rec["verdict"] == "verified"
    assert rec["pageSize"] == 4096
    assert rec["codeSlots"] == 3
    assert [p["slot"] for p in rec["pages"]] == [0, 1, 2]
    assert all(p["match"] for p in rec["pages"])
    assert rec["codeDirectorySha256"]
    assert rec["payloadSha256"] == hashlib.sha256(payload).hexdigest()

    # 同标识同字节重传：返回原审计。
    status2, rec2 = _post_payload(server, "HTTP-1", payload)
    assert status2 == 200
    assert rec2.get("replayed") is True
    assert rec2["pages"] == rec["pages"]
    assert rec2["codeDirectorySha256"] == rec["codeDirectorySha256"]

    # GET 冻结结论一致。
    status3, rec3 = _req(server, "GET", "/api/audits/HTTP-1")
    assert status3 == 200
    assert rec3["verdict"] == "verified"
    assert rec3["pages"] == rec["pages"]


def test_reused_id_different_bytes_conflict_keeps_record(server):
    payload = make_payload()
    _post_payload(server, "HTTP-2", payload)
    changed = bytearray(payload)
    changed[0] ^= 0xFF
    status, body = _post_payload(server, "HTTP-2", bytes(changed))
    assert status == 409
    assert "标识" in body["error"]
    status, kept = _req(server, "GET", "/api/audits/HTTP-2")
    assert kept["payloadSha256"] == hashlib.sha256(payload).hexdigest()


def test_tampered_page_is_mismatch_with_first_failed_slot(server):
    payload = bytearray(make_payload(n_pages=3))
    payload[4096 + 2] ^= 0xAB  # slot 1
    status, rec = _post_payload(server, "HTTP-3", bytes(payload))
    assert status == 201
    assert rec["verdict"] == "mismatch"
    assert rec["firstFailedSlot"] == 1
    assert not rec["pages"][1]["match"]
    assert rec["pages"][1]["declared"] != rec["pages"][1]["actual"]


def test_malformed_structure_returns_422_and_no_record(server):
    status, body = _post_payload(server, "HTTP-BAD", b"\x00" * 128)
    assert status == 422
    assert body["status"] == "unparseable"
    status, _ = _req(server, "GET", "/api/audits/HTTP-BAD")
    assert status == 404


def test_bad_base64_rejected(server):
    status, body = _req(
        server, "POST", "/api/audits",
        {"auditId": "HTTP-X", "payloadBase64": "@@@not-base64@@@"},
    )
    assert status == 400
    assert "Base64" in body["error"]


def test_unknown_audit_404(server):
    status, body = _req(server, "GET", "/api/audits/nope")
    assert status == 404


def test_list_audits(server):
    _post_payload(server, "HTTP-L1", make_payload(n_pages=1))
    _post_payload(server, "HTTP-L2", make_payload(n_pages=2))
    status, body = _req(server, "GET", "/api/audits")
    assert status == 200
    assert set(body["auditIds"]) == {"HTTP-L1", "HTTP-L2"}
