"""verify 阶段的 HTTP 冒烟脚本。

由 compose 的 verify 服务在 audit 服务健康后执行，确认：
1. /healthz 健康；
2. 提交合法切片 -> verified，且分页证据按页升序、逐页一致；
3. GET 读取到冻结审计（结论与摘要一致）；
4. 同标识同字节重传 -> 200 + replayed（幂等，返回原审计）；
5. 同标识不同字节 -> 409 拒绝，既有记录保留；
6. 被替换页 -> mismatch 且指出首个失败槽；
7. 结构解析失败 -> 422，且读不到任何记录；
8. 分段送检：乱序上传、覆盖范围/首个缺口、冲突重传冻结、封存后分页证据；
9. 分段送检：进程重启（同库重建服务）后读取已收覆盖范围并续传封存。

任一断言失败即以非零退出码退出。
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import threading
import urllib.error
import urllib.request

sys.path.insert(0, ".")
from app.server import build_server  # noqa: E402
from tests.fixtures import make_payload  # noqa: E402


def request(base, method, path, body=None, expect=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, payload = resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        status, payload = exc.code, json.loads(exc.read().decode())
    if expect is not None and status != expect:
        raise AssertionError(f"{method} {path} 期望 {expect}，实际 {status}: {payload}")
    return status, payload


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://audit:8080"
    print(f"[smoke] target = {base}")

    # 1. 健康状态
    _, health = request(base, "GET", "/healthz", expect=200)
    assert health["status"] == "ok", health
    assert health["supportedHashType"] == "sha256", health
    print("[smoke] healthz ok")

    # 2. 合法切片 -> verified + 分页证据
    payload = make_payload(n_pages=3)
    body = {
        "auditId": "SMOKE-VERIFIED-01",
        "payloadBase64": base64.b64encode(payload).decode(),
    }
    status, rec = request(base, "POST", "/api/audits", body, expect=201)
    assert rec["verdict"] == "verified", rec
    assert rec["pageSize"] == 4096, rec
    assert rec["codeSlots"] == 3, rec
    assert rec["coveredBytes"] == rec["codeLimit"], rec
    slots = [p["slot"] for p in rec["pages"]]
    assert slots == sorted(slots) == [0, 1, 2], slots
    assert all(p["match"] for p in rec["pages"]), rec
    cd_digest = rec["codeDirectorySha256"]
    p_digest = rec["payloadSha256"]
    assert p_digest == hashlib.sha256(payload).hexdigest()
    print(f"[smoke] verified: cd={cd_digest[:16]}… pages=3")

    # 3. 读取冻结审计
    _, frozen = request(base, "GET", "/api/audits/SMOKE-VERIFIED-01", expect=200)
    assert frozen["frozen"] is True
    assert frozen["verdict"] == "verified"
    assert frozen["codeDirectorySha256"] == cd_digest
    assert frozen["pages"] == rec["pages"]
    print("[smoke] frozen audit re-read identical")

    # 4. 幂等：同标识同字节重传
    status, again = request(base, "POST", "/api/audits", body, expect=200)
    assert again.get("replayed") is True, again
    assert again["codeDirectorySha256"] == cd_digest
    assert again["pages"] == rec["pages"]
    print("[smoke] identical resubmission returned original audit (200)")

    # 5. 复用标识更换字节 -> 409，记录保留
    changed = bytearray(payload)
    changed[1234] ^= 0x5A
    conflict_body = {
        "auditId": "SMOKE-VERIFIED-01",
        "payloadBase64": base64.b64encode(bytes(changed)).decode(),
    }
    status, err = request(base, "POST", "/api/audits", conflict_body, expect=409)
    assert "标识" in err["error"], err
    _, kept = request(base, "GET", "/api/audits/SMOKE-VERIFIED-01", expect=200)
    assert kept["payloadSha256"] == p_digest, kept
    print("[smoke] reused-id/different-bytes rejected (409), record kept")

    # 6. 被替换页 -> mismatch，首个失败槽为 slot 1
    tampered = bytearray(payload)
    tampered[4096 + 9] ^= 0xFF
    body_bad = {
        "auditId": "SMOKE-MISMATCH-01",
        "payloadBase64": base64.b64encode(bytes(tampered)).decode(),
    }
    _, bad = request(base, "POST", "/api/audits", body_bad, expect=201)
    assert bad["verdict"] == "mismatch", bad
    assert bad["firstFailedSlot"] == 1, bad
    assert bad["pages"][0]["match"] and not bad["pages"][1]["match"], bad
    print("[smoke] replaced page -> mismatch, firstFailedSlot=1")

    # 7. 结构解析失败 -> 422 且不留记录
    garbage = {
        "auditId": "SMOKE-GARBAGE-01",
        "payloadBase64": base64.b64encode(b"\x00" * 256).decode(),
    }
    status, err = request(base, "POST", "/api/audits", garbage, expect=422)
    assert err["status"] == "unparseable", err
    request(base, "GET", "/api/audits/SMOKE-GARBAGE-01", expect=404)
    print("[smoke] unparseable payload -> 422 and no record stored")

    # 8. 分段送检：乱序上传、相同区段重传、冲突冻结、封存分页证据
    seg_payload = make_payload(n_pages=3)
    seg_id = "SMOKE-SEG-01"
    n = len(seg_payload)
    digest = hashlib.sha256(seg_payload).hexdigest()
    third = n // 3

    status, st = request(base, "PUT", f"/api/submissions/{seg_id}", {
        "totalBytes": n, "expectedSha256": digest,
    }, expect=201)
    assert st["status"] == "receiving", st
    assert st["firstGap"] == 0, st

    # 乱序：尾 -> 头 -> 中。
    _, st = request(base, "PUT", f"/api/submissions/{seg_id}/segments", {
        "start": 2 * third, "end": n,
        "dataBase64": base64.b64encode(seg_payload[2 * third:]).decode(),
    }, expect=200)
    assert st["firstGap"] == 0 and st["contiguousBytes"] == 0, st
    _, st = request(base, "PUT", f"/api/submissions/{seg_id}/segments", {
        "start": 0, "end": third,
        "dataBase64": base64.b64encode(seg_payload[:third]).decode(),
    }, expect=200)
    assert st["firstGap"] == third, st

    # 断线后读取已收到的连续覆盖范围。
    _, st = request(base, "GET", f"/api/submissions/{seg_id}", expect=200)
    assert st["contiguousBytes"] == third, st
    assert [0, third] in st["coveredRanges"], st

    # 相同区间/相交且逐字节相同 -> 允许重传。
    _, st = request(base, "PUT", f"/api/submissions/{seg_id}/segments", {
        "start": third // 2, "end": third,
        "dataBase64": base64.b64encode(seg_payload[third // 2:third]).decode(),
    }, expect=200)
    assert st["status"] == "receiving", st

    # 补齐中段。
    _, st = request(base, "PUT", f"/api/submissions/{seg_id}/segments", {
        "start": third, "end": 2 * third,
        "dataBase64": base64.b64encode(seg_payload[third:2 * third]).decode(),
    }, expect=200)
    assert st["firstGap"] is None, st

    # 封存 -> 冻结审计与逐页证据。
    status, sealed = request(base, "POST", f"/api/submissions/{seg_id}/seal", {}, expect=201)
    assert sealed["status"] == "sealed", sealed
    assert sealed["verdict"] == "verified", sealed
    assert sealed["sealOutcome"] == "sealed_created", sealed
    assert [p["slot"] for p in sealed["pages"]] == [0, 1, 2], sealed
    assert all(p["match"] for p in sealed["pages"]), sealed
    _, frozen = request(base, "GET", f"/api/audits/{seg_id}", expect=200)
    assert frozen["pages"] == sealed["pages"], frozen
    # 重复封存不产生第二份审计。
    _, again = request(base, "POST", f"/api/submissions/{seg_id}/seal", {}, expect=200)
    assert again["sealOutcome"] == "sealed_reused", again
    _, listing = request(base, "GET", "/api/audits", expect=200)
    assert listing["auditIds"].count(seg_id) == 1, listing
    print("[smoke] segmented out-of-order submit -> sealed, single frozen audit")

    # 8b. 冲突重传：重叠且字节不同 -> 送检冻结 rejected，无成功审计。
    conflict_id = "SMOKE-SEG-CONFLICT"
    request(base, "PUT", f"/api/submissions/{conflict_id}", {
        "totalBytes": n, "expectedSha256": digest,
    }, expect=201)
    request(base, "PUT", f"/api/submissions/{conflict_id}/segments", {
        "start": 0, "end": 1000,
        "dataBase64": base64.b64encode(seg_payload[:1000]).decode(),
    }, expect=200)
    evil = bytes(b ^ 0xFF for b in seg_payload[500:1500])
    status, st = request(base, "PUT", f"/api/submissions/{conflict_id}/segments", {
        "start": 500, "end": 1500,
        "dataBase64": base64.b64encode(evil).decode(),
    }, expect=409)
    assert st["status"] == "rejected", st
    assert st["conflictRange"] == [500, 1000], st
    request(base, "GET", f"/api/audits/{conflict_id}", expect=404)
    print("[smoke] overlapping conflict froze submission as rejected")

    # 9. 重启续传：在本地用同一 SQLite 文件重建服务，模拟进程重启。
    smoke_restart_resume(seg_payload)

    print("[smoke] ALL CHECKS PASSED")
    return 0


def smoke_restart_resume(payload: bytes) -> None:
    """乱序收两段后关闭服务；以同一数据库重启，读取覆盖范围并续传封存。"""
    tmp = tempfile.NamedTemporaryFile(prefix="smoke-seg-", suffix=".sqlite3", delete=False)
    tmp.close()
    db_path = tmp.name
    n = len(payload)
    digest = hashlib.sha256(payload).hexdigest()
    audit_id = "SMOKE-SEG-RESTART"

    httpd = build_server("127.0.0.1", 0, db_path)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    base1 = f"http://{host}:{port}"
    try:
        request(base1, "PUT", f"/api/submissions/{audit_id}", {
            "totalBytes": n, "expectedSha256": digest,
        }, expect=201)
        request(base1, "PUT", f"/api/submissions/{audit_id}/segments", {
            "start": n - 64, "end": n,
            "dataBase64": base64.b64encode(payload[n - 64:]).decode(),
        }, expect=200)
        request(base1, "PUT", f"/api/submissions/{audit_id}/segments", {
            "start": 0, "end": 64,
            "dataBase64": base64.b64encode(payload[:64]).decode(),
        }, expect=200)
    finally:
        httpd.shutdown()
        httpd.store.close()
        httpd.server_close()
        t.join(timeout=5)

    # 进程重启：区段与连续覆盖范围必须可重新读取。
    httpd2 = build_server("127.0.0.1", 0, db_path)
    t2 = threading.Thread(target=httpd2.serve_forever, daemon=True)
    t2.start()
    host, port = httpd2.server_address
    base2 = f"http://{host}:{port}"
    try:
        _, st = request(base2, "GET", f"/api/submissions/{audit_id}", expect=200)
        assert st["status"] == "receiving", st
        assert st["coveredRanges"] == [[0, 64], [n - 64, n]], st
        assert st["firstGap"] == 64, st
        # 幂等重开（同参数）。
        request(base2, "PUT", f"/api/submissions/{audit_id}", {
            "totalBytes": n, "expectedSha256": digest,
        }, expect=200)
        # 续传补齐并封存。
        request(base2, "PUT", f"/api/submissions/{audit_id}/segments", {
            "start": 64, "end": n - 64,
            "dataBase64": base64.b64encode(payload[64:n - 64]).decode(),
        }, expect=200)
        _, sealed = request(
            base2, "POST", f"/api/submissions/{audit_id}/seal", {}, expect=201
        )
        assert sealed["verdict"] == "verified", sealed
        assert all(p["match"] for p in sealed["pages"]), sealed
    finally:
        httpd2.shutdown()
        httpd2.store.close()
        httpd2.server_close()
        t2.join(timeout=5)
    print("[smoke] restart resume: coverage re-read and submission sealed")


if __name__ == "__main__":
    raise SystemExit(main())
