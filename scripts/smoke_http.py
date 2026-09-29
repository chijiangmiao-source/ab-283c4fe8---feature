"""verify 阶段的 HTTP 冒烟脚本。

由 compose 的 verify 服务在 audit 服务健康后执行，确认：

一次性整包提交（原语义）：
1. /healthz 健康；
2. 提交合法切片 -> verified，且分页证据按页升序、逐页一致；
3. GET 读取到冻结审计（结论与摘要一致）；
4. 同标识同字节重传 -> 200 + replayed（幂等，返回原审计）；
5. 同标识不同字节 -> 409 拒绝，既有记录保留；
6. 被替换页 -> mismatch 且指出首个失败槽；
7. 结构解析失败 -> 422，且读不到任何记录。

分段送检（新语义）：
8. begin -> 乱序上传全部 64 KiB 以内区段 -> seal，分页证据完整且可重复读；
9. 重复封存 -> 200 replayed，不产生第二份审计；
10. 冲突重传 -> 409 且送检冻结 rejected、给出冲突范围，审计读不到；
11. 进程重启续传：本脚本在本地拉起 app.server 子进程，乱序传一半区段后
    终止进程，重新启动后已收连续覆盖仍在，续传并封存成功。

任一断言失败即以非零退出码退出。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, ".")
from tests.fixtures import make_payload  # noqa: E402

CHUNK_RAW = 1000  # 冒烟分段大小：1000 B（远小于 64 KiB 上限，形成多段乱序）


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


def chunk_ranges(total: int, size: int = CHUNK_RAW):
    return [(o, min(o + size, total)) for o in range(0, total, size)]


def out_of_order_indexes(ranges):
    # 确定性乱序：偶数段在前、奇数段在后。
    idx = list(range(len(ranges)))
    return sorted(idx, key=lambda i: (i % 2, i))


def begin(base, audit_id, raw):
    return request(
        base, "POST", f"/api/audits/{audit_id}/segments/begin",
        {"totalBytes": len(raw),
         "expectedSha256": hashlib.sha256(raw).hexdigest()},
    )


def put_chunk(base, audit_id, s, e, raw):
    return request(
        base, "PUT", f"/api/audits/{audit_id}/segments/{s}/{e}",
        {"chunkBase64": base64.b64encode(raw[s:e]).decode()},
    )


def upload_indexes(base, audit_id, raw, ranges, indexes):
    last = None
    for i in indexes:
        s, e = ranges[i]
        status, last = put_chunk(base, audit_id, s, e, raw)
        assert status == 200, last
    return last


# ---------------------------------------------------------------------------
# 分段送检：乱序、封存分页证据、重复封存、冲突重传
# ---------------------------------------------------------------------------

def smoke_segmented(base):
    raw = make_payload(n_pages=3)
    digest = hashlib.sha256(raw).hexdigest()
    aid = "SMOKE-SEG-OK-01"

    status, st = begin(base, aid, raw)
    assert status == 201, st
    assert st["state"] == "receiving"
    assert st["firstGap"] == [0, len(raw)]
    # 断线重连后重新 begin：200 幂等恢复。
    status, st = begin(base, aid, raw)
    assert status == 200 and st["state"] == "receiving", st

    ranges = chunk_ranges(len(raw))
    order = out_of_order_indexes(ranges)
    st = upload_indexes(base, aid, raw, ranges, order)
    assert st["state"] == "receiving", st
    assert st["contiguousCoverage"] == len(raw), st
    assert st["firstGap"] is None, st
    print(f"[smoke] segmented: {len(ranges)} chunks uploaded out of order,"
          f" contiguous={st['contiguousCoverage']}")

    # 相同区间逐字节重传：幂等，覆盖不变。
    s, e = ranges[0]
    status, again = put_chunk(base, aid, s, e, raw)
    assert status == 200 and again["coveredRanges"] == st["coveredRanges"], again

    # 封存 => 201，分页证据与整包路径一致。
    status, rec = request(base, "POST", f"/api/audits/{aid}/seal", None, expect=201)
    assert rec["verdict"] == "verified", rec
    assert rec["pageSize"] == 4096 and rec["codeSlots"] == 3, rec
    assert rec["payloadSha256"] == digest, rec
    assert [p["slot"] for p in rec["pages"]] == [0, 1, 2], rec
    assert all(p["match"] for p in rec["pages"]), rec
    cd_digest = rec["codeDirectorySha256"]

    status, state = request(base, "GET", f"/api/audits/{aid}/segments", expect=200)
    assert state["state"] == "sealed", state
    status, frozen = request(base, "GET", f"/api/audits/{aid}", expect=200)
    assert frozen["frozen"] is True and frozen["verdict"] == "verified", frozen
    assert frozen["codeDirectorySha256"] == cd_digest, frozen
    assert frozen["pages"] == rec["pages"], frozen
    print("[smoke] segmented seal produced frozen audit with page evidence")

    # 重复封存 => 200 replayed，同一份审计。
    status, reseal = request(base, "POST", f"/api/audits/{aid}/seal", None, expect=200)
    assert reseal.get("replayed") is True, reseal
    assert reseal["pages"] == rec["pages"], reseal
    # 封存后再写段被拒绝。
    status, err = put_chunk(base, aid, s, e, raw)
    assert status == 409 and err["status"] == "sealed", err
    print("[smoke] repeated seal returned original audit; post-seal chunk refused")


def smoke_segment_conflict(base):
    raw = make_payload(n_pages=2)
    aid = "SMOKE-SEG-CONFLICT-01"
    begin(base, aid, raw)
    request(base, "PUT", f"/api/audits/{aid}/segments/0/200",
            {"chunkBase64": base64.b64encode(raw[0:200]).decode()}, expect=200)

    bad = bytearray(raw[0:200])
    bad[33] ^= 0xA5
    status, err = request(
        base, "PUT", f"/api/audits/{aid}/segments/0/200",
        {"chunkBase64": base64.b64encode(bytes(bad)).decode()},
    )
    assert status == 409, err
    assert err["status"] == "conflict", err
    assert err["state"]["state"] == "rejected", err
    assert err["state"]["conflictRange"] == [33, 34], err
    print("[smoke] conflicting retransmit froze submission as rejected")

    status, st = request(base, "GET", f"/api/audits/{aid}/segments", expect=200)
    assert st["state"] == "rejected" and st["conflictRange"] == [33, 34], st
    # 不留下可读取的成功审计。
    request(base, "GET", f"/api/audits/{aid}", expect=404)
    # 拒绝后续传/封存都被拒绝。
    status, err2 = put_chunk(base, aid, 200, 400, raw)
    assert status == 409 and err2["status"] == "rejected", err2
    request(base, "POST", f"/api/audits/{aid}/seal", None, expect=409)
    print("[smoke] rejected submission stays frozen and has no audit")


# ---------------------------------------------------------------------------
# 进程重启续传：脚本内拉起/重启 app.server 子进程，走真实 HTTP
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


def _wait_healthy(base: str, proc: subprocess.Popen) -> None:
    deadline = time.time() + 15
    last_err = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"audit 子进程提前退出 code={proc.returncode}")
        try:
            request(base, "GET", "/healthz")
            return
        except OSError as exc:  # 启动窗口期连接被拒
            last_err = exc
            time.sleep(0.2)
    raise AssertionError(f"audit 子进程未在时限内就绪：{last_err}")


def _start_server(db_path: str):
    port = _free_port()
    env = dict(os.environ)
    env.update(
        AUDIT_HOST="127.0.0.1",
        AUDIT_PORT=str(port),
        AUDIT_DB=db_path,
        PYTHONPATH=os.pathsep.join(
            p for p in [os.getcwd(), env.get("PYTHONPATH")] if p
        ),
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.server"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_healthy(base, proc)
    except Exception:
        proc.kill()
        proc.wait(timeout=5)
        raise
    return proc, base


def smoke_restart_resume(tmp_dir: str):
    db_path = os.path.join(tmp_dir, "restart.sqlite3")
    raw = make_payload(n_pages=3)
    digest = hashlib.sha256(raw).hexdigest()
    aid = "SMOKE-SEG-RESTART-01"
    ranges = chunk_ranges(len(raw))
    order = out_of_order_indexes(ranges)
    half = order[: len(order) // 2]

    proc, base = _start_server(db_path)
    try:
        status, st = begin(base, aid, raw)
        assert status == 201, st
        st = upload_indexes(base, aid, raw, ranges, half)
        covered_before = [tuple(r) for r in st["coveredRanges"]]
        contiguous_before = st["contiguousCoverage"]
        assert covered_before, "模拟断线前应已收到部分区段"
        print(f"[smoke] restart: uploaded {len(half)} chunks before process kill"
              f" (contiguous={contiguous_before})")
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # 进程重启：同一份 DB 文件，进度必须仍可读取。
    proc, base = _start_server(db_path)
    try:
        status, st = request(base, "GET", f"/api/audits/{aid}/segments", expect=200)
        assert st["state"] == "receiving", st
        assert [tuple(r) for r in st["coveredRanges"]] == covered_before, st
        assert st["contiguousCoverage"] == contiguous_before, st
        # begin 幂等恢复后续传。
        status, st = begin(base, aid, raw)
        assert status == 200, st
        st = upload_indexes(base, aid, raw, ranges, order[len(half):])
        assert st["contiguousCoverage"] == len(raw) and st["firstGap"] is None, st

        status, rec = request(base, "POST", f"/api/audits/{aid}/seal", None, expect=201)
        assert rec["verdict"] == "verified", rec
        assert rec["payloadSha256"] == digest, rec
        assert all(p["match"] for p in rec["pages"]), rec
        print("[smoke] restart: resumed after process restart and sealed verified")
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # 再重启一次：封存结论依然存在且唯一可读。
    proc, base = _start_server(db_path)
    try:
        status, frozen = request(base, "GET", f"/api/audits/{aid}", expect=200)
        assert frozen["verdict"] == "verified" and frozen["payloadSha256"] == digest
        status, st = request(base, "GET", f"/api/audits/{aid}/segments", expect=200)
        assert st["state"] == "sealed", st
        status, ids = request(base, "GET", "/api/audits", expect=200)
        assert ids["auditIds"].count(aid) == 1, ids
        print("[smoke] restart: single frozen audit survived second restart")
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://audit:8080"
    tmp_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp"
    print(f"[smoke] target = {base}")

    # 1. 健康状态
    _, health = request(base, "GET", "/healthz", expect=200)
    assert health["status"] == "ok", health
    assert health["supportedHashType"] == "sha256", health
    assert health["maxChunkBytes"] == 64 * 1024, health
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

    # 8-10. 分段送检：乱序 + 封存证据、重复封存、冲突重传
    smoke_segmented(base)
    smoke_segment_conflict(base)

    # 11. 进程重启续传（本地子进程 + 独立 DB）
    smoke_restart_resume(tmp_dir)

    print("[smoke] ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
