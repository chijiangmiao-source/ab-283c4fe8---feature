"""审计 HTTP 服务（仅依赖标准库）。

路由：
  GET  /                     粘贴页面（整包提交或分段送检）
  POST /api/audits           一次性整包提交（JSON: auditId, payloadBase64）
  GET  /api/audits           列出已有审计标识
  GET  /api/audits/<id>      读取冻结审计
  PUT  /api/submissions/<id>           建立/重开分段送检（totalBytes, expectedSha256）
  GET  /api/submissions/<id>           读取送检状态（receiving/sealed/rejected、覆盖范围、首个缺口）
  PUT  /api/submissions/<id>/segments  上传一个 Base64 区段（start, end, dataBase64）
  POST /api/submissions/<id>/seal      确认封存：拼装、整体摘要复核、严格结构复核并冻结
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
from .store import AuditStore, MAX_SEGMENT_BYTES

MAX_BODY_BYTES = 4 * 1024 * 1024  # Base64 文本上限（整包解码后 <= 2 MiB）
MAX_SEGMENT_BODY_BYTES = MAX_SEGMENT_BYTES * 2  # 64 KiB 原始字节的 Base64 文本余量

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

<hr>
<h2>分段送检（可乱序、断线续传）</h2>
<p>以同一审计标识、总字节数与预期载荷 SHA-256 建立送检后，可乱序提交不超过
64 KiB 的 Base64 区段（半开区间 [start,end)）。重叠区段只有逐字节相同才接受；
任一重叠冲突、总长或摘要变更都会冻结该送检为 rejected。封存时仅在
0 至总长无空洞且整体 SHA-256 一致后，才执行严格结构复核并生成冻结审计。</p>
<form id="sf">
  <p><label>审计标识：<input type="text" name="auditId" required
    placeholder="例如 SAT-2026-PAYLOAD-07"></label></p>
  <p><label>总字节数：<input type="number" name="totalBytes" min="1"
    max="2097152" required style="width:140px"></label>
     <label>预期载荷 SHA-256：<input type="text" name="expectedSha256" required
    style="width:440px" placeholder="64 位十六进制"></label></p>
  <p>
    <button type="submit" id="segInitBtn">建立 / 重开送检</button>
    <button type="button" id="segStatusBtn">读取接收状态</button>
    <button type="button" id="segSealBtn">确认封存</button>
  </p>
  <p><label>区段起点 start：<input type="number" name="start" min="0"
    style="width:110px"></label>
     <label>区段终点 end（不含）：<input type="number" name="end" min="1"
    style="width:110px"></label></p>
  <p><label>区段 Base64（解码后 ≤ 64 KiB）：
    <textarea name="dataBase64" style="height:90px"></textarea></label></p>
  <p><button type="button" id="segPutBtn">提交该区段</button></p>
</form>

<div id="subout"></div>

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

// ---- 分段送检 ---------------------------------------------------------------
const subout = document.getElementById('subout');

function subPath(suffix) {
  const id = encodeURIComponent(document.forms.sf.auditId.value.trim());
  return '/api/submissions/' + id + (suffix || '');
}

function showSubError(msg) {
  subout.insertAdjacentHTML('afterbegin',
    `<div class="banner error"><strong>送检操作失败：</strong>${esc(msg)}</div>`);
}

const LIFECYCLE = new Set(['receiving', 'sealed', 'rejected']);

function renderSub(st, errMsg) {
  if (!st || !LIFECYCLE.has(st.status)) { subout.textContent = ''; return; }
  let html = '';
  if (errMsg) html += `<div class="banner error"><strong>送检操作失败：</strong>${esc(errMsg)}</div>`;
  const cls = st.status === 'sealed' ? 'verified'
    : st.status === 'rejected' ? 'mismatch' : 'error';
  const word = st.status === 'sealed' ? '已封存（sealed）'
    : st.status === 'rejected' ? '已冻结拒绝（rejected）'
    : '接收中（receiving）';
  html += `<div class="banner ${cls}"><strong>${esc(word)}</strong>`
    + `　已收 <strong>${st.receivedBytes ?? 0}</strong> / ${st.totalBytes} 字节`
    + `，自 0 起连续覆盖 <strong>${st.contiguousBytes ?? 0}</strong> 字节`;
  if (st.status === 'receiving' && st.firstGap !== null && st.firstGap !== undefined)
    html += `　首个缺口：<strong>[${st.firstGap}, …)</strong>`;
  if (st.status === 'rejected' && st.reason)
    html += `<div>拒绝原因：${esc(st.reason)}</div>`;
  if (st.conflictRange)
    html += `<div>冲突范围：<strong>[${st.conflictRange[0]}, ${st.conflictRange[1]})</strong></div>`;
  html += '</div>';
  const ranges = (st.coveredRanges || []).map(r => `[${r[0]}, ${r[1]})`).join('，');
  html += `<div class="meta"><div>预期 SHA-256：<span class="mono">${esc(st.expectedSha256 || '')}</span></div>`
    + `<div>已收区间（合并后）：${esc(ranges || '（无）')}</div></div>`;
  if (st.audit || st.verdict) html += '<p class="frozen">封存完成：冻结审计已生成/复用，可在上方按标识读取逐页证据。</p>';
  subout.innerHTML = html;
}

async function subJson(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: {'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const data = await r.json().catch(() => ({}));
  return {ok: r.ok, status: r.status, data};
}

document.getElementById('sf').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    totalBytes: Number(document.forms.sf.totalBytes.value),
    expectedSha256: document.forms.sf.expectedSha256.value.replace(/\\s+/g, '')
  };
  const {ok, data} = await subJson('PUT', subPath(), body);
  if (!ok) { renderSub(data, data.error || '建立送检失败'); return; }
  renderSub(data);
});

document.getElementById('segStatusBtn').onclick = async () => {
  const {ok, status, data} = await subJson('GET', subPath());
  if (!ok) { renderSub(null); showSubError(data.error || ('HTTP ' + status)); return; }
  renderSub(data);
};

document.getElementById('segPutBtn').onclick = async () => {
  const body = {
    start: Number(document.forms.sf.start.value),
    end: Number(document.forms.sf.end.value),
    dataBase64: document.forms.sf.dataBase64.value.replace(/\\s+/g, '')
  };
  const {ok, data} = await subJson('PUT', subPath('/segments'), body);
  if (!ok) { renderSub(data, data.error || '区段提交失败'); return; }
  renderSub(data);
};

document.getElementById('segSealBtn').onclick = async () => {
  const {ok, data} = await subJson('POST', subPath('/seal'), {});
  if (!ok) { renderSub(data, data.error || '封存失败'); return; }
  renderSub(data);
  if (data.verdict) render(data);
};
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


def _decode_base64_segment(text: str) -> bytes:
    """区段 Base64 解码：严格字母表与填充；64 KiB 上限由存储层统一执行。"""
    if not text or len(text) % 4 != 0:
        raise ValueError("Base64 长度非法（须为 4 的倍数并带标准填充）")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Base64 解码失败：含非字母表字符或填充错误")
    if len(raw) == 0:
        raise ValueError("Base64 解码后为空区段")
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
        if path.startswith("/api/submissions/"):
            self._route_submission_read(path)
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
        if path.startswith("/api/submissions/") and path.endswith("/seal"):
            audit_id = path[len("/api/submissions/") : -len("/seal")]
            if not audit_id or "/" in audit_id:
                self._json(404, {"error": "未知路径"})
                return
            # 封存请求无请求体；仍消费掉可能存在的 Content-Length，保持连接干净。
            self._drain_body()
            outcome = self.store.seal_submission(audit_id)
            self._answer_submission(outcome)
            return
        if path != "/api/audits":
            self._json(404, {"error": "未知路径"})
            return
        raw_body = self._read_json_body(MAX_BODY_BYTES, allow_empty=False)
        if raw_body is None:
            return

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

    def do_PUT(self) -> None:
        path = urlsplit(self.path).path
        if not path.startswith("/api/submissions/"):
            self._json(404, {"error": "未知路径"})
            return
        rest = path[len("/api/submissions/") :]
        if rest.endswith("/segments"):
            audit_id = rest[: -len("/segments")]
            if not audit_id or "/" in audit_id:
                self._json(404, {"error": "未知路径"})
                return
            self._handle_segment_put(audit_id)
            return
        audit_id = rest
        if not audit_id or "/" in audit_id:
            self._json(404, {"error": "未知路径"})
            return
        self._handle_submission_init(audit_id)

    # ---- 分段送检处理 --------------------------------------------------------
    def _read_json_body(self, max_bytes: int, allow_empty: bool) -> object:
        """读取并做长度限制的 JSON 请求体；出错时已自行写回错误响应。"""
        length_hdr = self.headers.get("Content-Length")
        try:
            length = int(length_hdr) if length_hdr is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            self._json(411, {"error": "需要 Content-Length"})
            return None
        if length == 0 and allow_empty:
            return b""
        if length == 0:
            self._json(400, {"error": "请求体为空"})
            return None
        if length > max_bytes:
            self._json(413, {"error": f"请求体超过 {max_bytes} 字节上限"})
            return None
        return self.rfile.read(length)

    def _drain_body(self) -> None:
        length_hdr = self.headers.get("Content-Length")
        try:
            length = int(length_hdr) if length_hdr is not None else 0
        except ValueError:
            length = 0
        if length > 0:
            self.rfile.read(min(length, MAX_BODY_BYTES))

    def _handle_submission_init(self, audit_id: str) -> None:
        raw_body = self._read_json_body(MAX_BODY_BYTES, allow_empty=False)
        if raw_body is None:
            return
        try:
            payload = json.loads(raw_body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("请求体必须是 JSON 对象")
            total = payload.get("totalBytes")
            digest = payload.get("expectedSha256")
            if not isinstance(total, int) or isinstance(total, bool):
                raise ValueError("totalBytes 必须为整数")
            if not isinstance(digest, str):
                raise ValueError("expectedSha256 必须为十六进制字符串")
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": f"请求格式不合法：{exc}"})
            return
        outcome = self.store.init_submission(audit_id, total, "".join(digest.split()))
        self._answer_submission(outcome)

    def _handle_segment_put(self, audit_id: str) -> None:
        raw_body = self._read_json_body(MAX_SEGMENT_BODY_BYTES, allow_empty=False)
        if raw_body is None:
            return
        try:
            payload = json.loads(raw_body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("请求体必须是 JSON 对象")
            start = payload.get("start")
            end = payload.get("end")
            b64_text = payload.get("dataBase64")
            if not isinstance(b64_text, str):
                raise ValueError("dataBase64 必须是字符串")
            b64_text = "".join(b64_text.split())
            data = _decode_base64_segment(b64_text)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": f"请求格式不合法：{exc}"})
            return
        outcome = self.store.put_segment(audit_id, start, end, data)
        self._answer_submission(outcome)

    def _route_submission_read(self, path: str) -> None:
        audit_id = path[len("/api/submissions/") :]
        if not audit_id or "/" in audit_id:
            self._json(404, {"error": "未知路径"})
            return
        state = self.store.get_submission(audit_id)
        if state is None:
            self._json(404, {"error": f"送检 {audit_id!r} 不存在"})
            return
        self._json(200, state)

    def _answer_submission(self, outcome) -> None:
        body: dict = {}
        if outcome.state is not None:
            body.update(outcome.state)
        if outcome.record is not None:
            body["audit"] = outcome.record
        if outcome.error is not None:
            body["error"] = outcome.error
            # state 存在时 status 保持送检生命周期（receiving/sealed/rejected），
            # 操作结果另放在 outcome；无 state 时才用 status 承载错误类别。
            if outcome.state is None:
                body["status"] = outcome.status
            else:
                body["outcome"] = outcome.status
        elif outcome.status in ("sealed_created", "sealed_reused") and outcome.record is not None:
            # 封存成功时顶层直接给出冻结审计字段，便于与整包接口一致地读取。
            body.update(outcome.record)
            body["sealOutcome"] = outcome.status
        self._json(outcome.http_status, body)


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
