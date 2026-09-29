"""分段送检 HTTP 端到端测试：真实 socket 上的 begin / 乱序区段 /
断线续传 / 冲突冻结 / 封存分页证据 / 重复封存。
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


def _begin(base, audit_id, payload):
    return _req(
        base, "POST", f"/api/audits/{audit_id}/segments/begin",
        {"totalBytes": len(payload),
         "expectedSha256": hashlib.sha256(payload).hexdigest()},
    )


def _chunk(base, audit_id, s, e, payload):
    return _req(
        base, "PUT", f"/api/audits/{audit_id}/segments/{s}/{e}",
        {"chunkBase64": base64.b64encode(payload[s:e]).decode()},
    )


def _ranges(total, size):
    return [(o, min(o + size, total)) for o in range(0, total, size)]


def _out_of_order(ranges):
    idx = list(range(len(ranges)))
    return sorted(idx, key=lambda i: (i % 2, i))


def test_segmented_out_of_order_resume_and_seal_evidence(server):
    payload = make_payload(n_pages=3)
    digest = hashlib.sha256(payload).hexdigest()
    aid = "HTTP-SEG-1"

    status, st = _begin(server, aid, payload)
    assert status == 201
    assert st["state"] == "receiving"
    assert st["firstGap"] == [0, len(payload)]

    # 重复 begin：200 幂等恢复。
    status, st = _begin(server, aid, payload)
    assert status == 200

    ranges = _ranges(len(payload), 1000)
    order = _out_of_order(ranges)

    # “断线”：只传乱序后的一半区段。
    half = order[: len(order) // 2]
    last = None
    for i in half:
        s, e = ranges[i]
        status, last = _chunk(server, aid, s, e, payload)
        assert status == 200
    assert last["contiguousCoverage"] < len(payload)
    assert last["firstGap"] is not None

    # 断线后读取已收到的连续覆盖范围。
    status, state = _req(server, "GET", f"/api/audits/{aid}/segments")
    assert status == 200
    assert state["state"] == "receiving"
    assert state["firstGap"] is not None
    assert state["coveredRanges"] == last["coveredRanges"]

    # 封存有空洞 => 409 且给出首个缺口，不产生审计。
    status, err = _req(server, "POST", f"/api/audits/{aid}/seal", {})
    assert status == 409
    assert err["status"] == "incomplete"
    assert err["state"]["firstGap"] is not None
    status, _ = _req(server, "GET", f"/api/audits/{aid}")
    assert status == 404

    # 续传其余区段（仍按乱序顺序）。
    for i in order[len(half):]:
        s, e = ranges[i]
        status, last = _chunk(server, aid, s, e, payload)
        assert status == 200
    assert last["contiguousCoverage"] == len(payload)
    assert last["firstGap"] is None

    # 相同区段重传：幂等 200。
    s, e = ranges[0]
    status, st2 = _chunk(server, aid, s, e, payload)
    assert status == 200
    assert st2["coveredRanges"] == last["coveredRanges"]

    # 封存 => 201 + 分页证据完整（空请求体）。
    status, rec = _req(server, "POST", f"/api/audits/{aid}/seal", None)
    assert status == 201, rec
    assert rec["verdict"] == "verified"
    assert rec["payloadSha256"] == digest
    assert rec["codeSlots"] == 3
    assert all(p["match"] for p in rec["pages"])
    assert [p["slot"] for p in rec["pages"]] == [0, 1, 2]

    # 送检状态 sealed，冻结审计可读。
    status, state = _req(server, "GET", f"/api/audits/{aid}/segments")
    assert status == 200
    assert state["state"] == "sealed"
    status, frozen = _req(server, "GET", f"/api/audits/{aid}")
    assert status == 200
    assert frozen["pages"] == rec["pages"]

    # 重复封存 => 200 replayed，同一份审计。
    status, again = _req(server, "POST", f"/api/audits/{aid}/seal", None)
    assert status == 200
    assert again["replayed"] is True
    assert again["pages"] == rec["pages"]

    # 封存后再写段 => 409。
    status, err = _chunk(server, aid, s, e, payload)
    assert status == 409
    assert err["status"] == "sealed"


def test_conflicting_retransmit_freezes_without_audit(server):
    payload = make_payload(n_pages=2)
    aid = "HTTP-SEG-2"
    _begin(server, aid, payload)
    _chunk(server, aid, 0, 200, payload)

    bad = bytearray(payload[0:200])
    bad[10] ^= 0x77
    status, err = _req(
        server, "PUT", f"/api/audits/{aid}/segments/0/200",
        {"chunkBase64": base64.b64encode(bytes(bad)).decode()},
    )
    assert status == 409
    assert err["status"] == "conflict"
    assert err["state"]["state"] == "rejected"
    assert err["state"]["conflictRange"] == [10, 11]

    # 之后再 begin / 写段 / 封存都被拒绝。
    status, err2 = _begin(server, aid, payload)
    assert status == 409
    status, err2 = _chunk(server, aid, 200, 400, payload)
    assert status == 409
    assert err2["status"] == "rejected"
    status, err2 = _req(server, "POST", f"/api/audits/{aid}/seal", None)
    assert status == 409
    status, _ = _req(server, "GET", f"/api/audits/{aid}")
    assert status == 404
    # 送检视图仍可读取，显示 rejected 与冲突范围。
    status, st = _req(server, "GET", f"/api/audits/{aid}/segments")
    assert status == 200
    assert st["state"] == "rejected"
    assert st["conflictRange"] == [10, 11]
    assert st["reason"]


def test_unparseable_assembly_rejects_submission_no_audit(server):
    garbage = b"\xab" * 1500
    aid = "HTTP-SEG-3"
    _begin(server, aid, garbage)
    for s, e in _ranges(len(garbage), 512):
        status, _ = _chunk(server, aid, s, e, garbage)
        assert status == 200
    status, err = _req(server, "POST", f"/api/audits/{aid}/seal", None)
    assert status == 422
    assert err["status"] == "unparseable"
    assert err["state"]["state"] == "rejected"
    status, _ = _req(server, "GET", f"/api/audits/{aid}")
    assert status == 404


def test_begin_validation_errors(server):
    payload = make_payload(n_pages=1)
    # 标识非法（空格经 URL 编码）。
    status, err = _req(
        server, "POST", "/api/audits/bad%20id/segments/begin",
        {"totalBytes": len(payload),
         "expectedSha256": hashlib.sha256(payload).hexdigest()},
    )
    assert status == 400
    # 摘要非法。
    status, err = _req(
        server, "POST", "/api/audits/HTTP-SEG-4/segments/begin",
        {"totalBytes": len(payload), "expectedSha256": "xyz"},
    )
    assert status == 400
    # 总长超 2 MiB。
    status, err = _req(
        server, "POST", "/api/audits/HTTP-SEG-5/segments/begin",
        {"totalBytes": 2 * 1024 * 1024 + 1,
         "expectedSha256": "0" * 64},
    )
    assert status == 413


def test_chunk_endpoint_validation(server):
    payload = make_payload(n_pages=1)
    aid = "HTTP-SEG-6"
    _begin(server, aid, payload)
    # 未 begin 的标识。
    status, err = _chunk(server, "HTTP-SEG-NOPE", 0, 10, payload)
    assert status == 404
    # 端点数与 base64 长度不一致。
    status, err = _req(
        server, "PUT", f"/api/audits/{aid}/segments/0/10",
        {"chunkBase64": base64.b64encode(payload[0:9]).decode()},
    )
    assert status == 400
    # 非数字端点。
    status, err = _req(
        server, "PUT", f"/api/audits/{aid}/segments/a/b",
        {"chunkBase64": base64.b64encode(payload[0:1]).decode()},
    )
    assert status == 400
    # 缺少字段。
    status, err = _req(
        server, "PUT", f"/api/audits/{aid}/segments/0/10",
        {"nope": 1},
    )
    assert status == 400


def test_segmented_tampered_page_seals_mismatch(server):
    payload = bytearray(make_payload(n_pages=3))
    payload[4096 + 3] ^= 0x13
    payload = bytes(payload)
    aid = "HTTP-SEG-7"
    _begin(server, aid, payload)
    for i, (s, e) in enumerate(_ranges(len(payload), 900)):
        _chunk(server, aid, s, e, payload)
    status, rec = _req(server, "POST", f"/api/audits/{aid}/seal", None)
    assert status == 201
    assert rec["verdict"] == "mismatch"
    assert rec["firstFailedSlot"] == 1
    assert not rec["pages"][1]["match"]
    # mismatch 结论同样冻结、可读。
    status, frozen = _req(server, "GET", f"/api/audits/{aid}")
    assert status == 200
    assert frozen["verdict"] == "mismatch"


def test_chunk_larger_than_64kib_rejected(server):
    aid = "HTTP-SEG-8"
    total = 70000
    _begin(server, aid, bytes(total))
    # begin 用的是占位摘要；这里只验证单段大小门。
    big = bytes(64 * 1024 + 1)
    status, err = _req(
        server, "PUT", f"/api/audits/{aid}/segments/0/{len(big)}",
        {"chunkBase64": base64.b64encode(big).decode()},
    )
    assert status == 413
    assert "64 KiB" in err["error"]
