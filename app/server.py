"""审计 HTTP 服务（仅依赖标准库）。

路由：
  GET  /                     粘贴页面（Base64 Mach-O 切片 + 稳定审计标识）
  POST /api/audits           提交载荷（JSON: auditId, payloadBase64）
  GET  /api/audits           列出已有审计标识
  GET  /api/audits/<id>      读取冻结审计
  GET  /healthz              健康状态

宿主机端口通过环境变量 AUDIT_HOST / AUDIT_PORT 配置（compose 再映射到宿主端口）。
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import codesig
from .store import AuditStore

MAX_BODY_BYTES = 4 * 1024 * 1024  # Base64 文本上限（解码后 <= 2 MiB）

INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>签封目录分页审计</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 980px; padding: 0 1rem; }
  textarea { width: 100%; height: 160px; font-family: ui-monospace, monospace; font-size: 12px; }
  input[type=text] { width: 280px; }
  button { padding: .4rem 1rem; margin-right: .5rem; }
  .ok { color: #0a7d28; font-weight: 700; }
  .bad { color: #c62828; font-weight: 700; }
  .frozen { color: #555; font-size: 12px; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: 12px; }
  th, td { border: 1px solid #888; padding: .2rem .45rem; word-break: break-all; }
  th { background: rgba(128,128,128,.15); }
  tr.mismatch { background: rgba(198,40,40,.12); }
  .mono { font-family: ui-monospace, monospace; }
  .banner { padding: .6rem .8rem; border-radius: 6px; margin: .8rem 0; }
  .banner.verified { background: rgba(10,125,40,.12); }
  .banner.mismatch, .banner.error { background: rgba(198,40,40,.12); }
  .meta div { margin: .15rem 0; }
  details { margin-top: .6rem; }
</style>
</head>
<body>
<h1>签封目录分页审计</h1>
<p>粘贴不超过 2 MiB 的 <strong>Base64 Mach-O 切片</strong>（单个大端 SuperBlob，
内含 SHA-256 CodeDirectory）与稳定审计标识。结论冻结后，同标识同字节重传返回原审计；
复用标识更换字节将被拒绝。</p>

<form id="f">
  <p><label>审计标识：<input type="text" name="auditId" required
    placeholder="例如 SAT-2026-PAYLOAD-07"></label></p>
  <p><label>Base64 载荷：<textarea name="payloadBase64" required></textarea></label></p>
  <button type="submit" id="submitBtn">提交并冻结审计</button>
  <button type="button" id="readBtn">按标识读取既有审计</button>
</form>

<div id="out"></div>

<script>
const out = document.getElementById('out');

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

function showError(msg) {
  out.innerHTML = `<div class="banner error"><strong>未形成审计结论：</strong>${esc(msg)}</div>`;
}

function render(rec) {
  const passed = rec.verdict === 'verified';
  const cls = passed ? 'ok' : 'bad';
  const word = passed ? '通过（逐页全部一致）' : '不通过（存在被替换/不符的页）';
  let banner = `<div class="banner ${esc(rec.verdict)}">
      <span class="${cls}">冻结结论：${esc(word)}</span>`;
  if (!passed && rec.firstFailedSlot !== null)
    banner += `　首个失败槽：<strong>slot ${rec.firstFailedSlot}</strong>`;
  if (rec.replayed) banner += `　<span class="frozen">（同标识同字节重传，返回原审计）</span>`;
  banner += `</div>`;

  const meta = `<div class="meta">
    <div>审计标识：<strong>${esc(rec.auditId)}</strong></div>
    <div>载荷 SHA-256：<span class="mono">${esc(rec.payloadSha256 || '')}</span></div>
    <div>CodeDirectory SHA-256（代码目录摘要）：<span class="mono">${esc(rec.codeDirectorySha256)}</span></div>
    <div>页大小：<strong>${rec.pageSize}</strong> 字节（2 的 ${Math.round(Math.log2(rec.pageSize))} 次幂）</div>
    <div>codeLimit（声明可执行字节）：<strong>${rec.codeLimit}</strong></div>
    <div>代码槽数 / 实际复算覆盖字节：<strong>${rec.codeSlots}</strong> 页 /
      <strong>${rec.coveredBytes}</strong> 字节</div>
    <div class="frozen">记录冻结：${rec.frozen ? '是' : '否'}；
      生成时间：${rec.createdAt ? new Date(rec.createdAt*1000).toISOString() : '-'}</div>
  </div>`;

  const rows = rec.pages.map(p => `
    <tr class="${p.match ? '' : 'mismatch'}">
      <td>${p.slot}</td><td class="mono">${p.offset}</td>
      <td>${p.match ? '✓ 一致' : '<strong>✗ 不符</strong>'}${p.hole ? '（槽为全零占位）' : ''}</td>
      <td class="mono">${esc(p.declared)}</td>
      <td class="mono">${esc(p.actual)}</td>
    </tr>`).join('');
  const table = `
    <details open><summary>按页升序的摘要比对证据（${rec.pages.length} 页）</summary>
    <table><thead><tr><th>槽/页号</th><th>字节偏移</th><th>比对</th>
      <th>CodeDirectory 声明 SHA-256</th><th>原始字节复算 SHA-256</th></tr></thead>
      <tbody>${rows}</tbody></table></details>`;

  out.innerHTML = banner + meta + table;
}

async function readExisting() {
  const id = document.forms.f.auditId.value.trim();
  if (!id) { showError('请输入审计标识'); return; }
  const r = await fetch('/api/audits/' + encodeURIComponent(id));
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { showError(data.error || ('HTTP ' + r.status)); return; }
  render(data);
}

document.getElementById('readBtn').onclick = readExisting;
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  out.textContent = '解析并逐页复算中…';
  const body = {
    auditId: document.forms.f.auditId.value.trim(),
    payloadBase64: document.forms.f.payloadBase64.value.replace(/\\s+/g, '')
  };
  const r = await fetch('/api/audits', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { showError(data.error || ('HTTP ' + r.status)); return; }
  render(data);
});
</script>
</body>
</html>
"""


def _decode_base64(text: str) -> bytes:
    """严格 Base64 解码：仅允许字母表字符与标准 = 填充（调用前已去空白）。"""
    if not text or len(text) % 4 != 0:
        raise ValueError("Base64 长度非法（须为 4 的倍数并带标准填充）")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Base64 解码失败：含非字母表字符或填充错误")
    if len(raw) == 0:
        raise ValueError("Base64 解码后为空载荷")
    if len(raw) > codesig.MAX_BLOB_BYTES:
        raise ValueError(
            f"解码后载荷 {len(raw)} 字节，超过 {codesig.MAX_BLOB_BYTES}（2 MiB）上限"
        )
    return raw


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "CodeDirAudit/1.0"

    @property
    def store(self) -> AuditStore:
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:  # 安静一点
        return

    # ---- 响应辅助 ------------------------------------------------------------
    def _json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # ---- 路由 ----------------------------------------------------------------
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._html(200, INDEX_HTML)
            return
        if path == "/healthz" or path == "/api/health":
            ids = self.store.list_ids()
            self._json(
                200,
                {
                    "status": "ok",
                    "service": "codedirectory-page-audit",
                    "frozenAudits": len(ids),
                    "maxPayloadBytes": codesig.MAX_BLOB_BYTES,
                    "supportedHashType": "sha256",
                },
            )
            return
        if path == "/api/audits":
            self._json(200, {"auditIds": self.store.list_ids()})
            return
        if path.startswith("/api/audits/"):
            audit_id = path[len("/api/audits/") :]
            if not audit_id or "/" in audit_id:
                self._json(404, {"error": "未知路径"})
                return
            record = self.store.get(audit_id)
            if record is None:
                self._json(404, {"error": f"审计标识 {audit_id!r} 不存在"})
                return
            self._json(200, record)
            return
        self._json(404, {"error": "未知路径"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path != "/api/audits":
            self._json(404, {"error": "未知路径"})
            return
        length_hdr = self.headers.get("Content-Length")
        try:
            length = int(length_hdr) if length_hdr is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            self._json(411, {"error": "需要 Content-Length"})
            return
        if length > MAX_BODY_BYTES:
            self._json(413, {"error": "请求体超过 4 MiB 上限"})
            return
        raw_body = self.rfile.read(length)

        try:
            payload = json.loads(raw_body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("请求体必须是 JSON 对象")
            audit_id = payload.get("auditId")
            b64_text = payload.get("payloadBase64")
            if not isinstance(b64_text, str):
                raise ValueError("payloadBase64 必须是字符串")
            b64_text = "".join(b64_text.split())  # 仅去除空白
            blob = _decode_base64(b64_text)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": f"请求格式不合法：{exc}"})
            return

        outcome = self.store.submit(str(audit_id) if audit_id is not None else "", blob)
        if outcome.status in ("created", "returned_existing"):
            assert outcome.record is not None
            self._json(outcome.http_status, outcome.record)
        else:
            self._json(outcome.http_status, {"error": outcome.error, "status": outcome.status})


def build_server(host: str, port: int, db_path: str) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), AuditHandler)
    httpd.store = AuditStore(db_path)  # type: ignore[attr-defined]
    httpd.daemon_threads = True
    return httpd


def main() -> int:
    host = os.environ.get("AUDIT_HOST", "0.0.0.0")
    port = int(os.environ.get("AUDIT_PORT", "8080"))
    db_path = os.environ.get("AUDIT_DB", "/data/audits.sqlite3")
    httpd = build_server(host, port, db_path)
    try:
        print(f"audit service listening on {host}:{port} (db={db_path})", flush=True)
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.store.close()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
