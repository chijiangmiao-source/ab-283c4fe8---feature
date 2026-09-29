"""verify 阶段的 HTTP 冒烟脚本。

由 compose 的 verify 服务在 audit 服务健康后执行，确认：
1. /healthz 健康；
2. 提交合法切片 -> verified，且分页证据按页升序、逐页一致；
3. GET 读取到冻结审计（结论与摘要一致）；
4. 同标识同字节重传 -> 200 + replayed（幂等，返回原审计）；
5. 同标识不同字节 -> 409 拒绝，既有记录保留；
6. 被替换页 -> mismatch 且指出首个失败槽；
7. 结构解析失败 -> 422，且读不到任何记录。

任一断言失败即以非零退出码退出。
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, ".")
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

    print("[smoke] ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
