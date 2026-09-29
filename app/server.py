"""审计 HTTP 服务（仅依赖标准库）。

路由：
  GET  /                     粘贴页面（整包提交 + 分段送检）
  POST /api/audits           一次性整包提交（JSON: auditId, payloadBase64）
  GET  /api/audits           列出已有审计标识
  GET  /api/audits/<id>      读取冻结审计
  POST /api/audits/<id>/segments/begin
                             开始/恢复分段送检（JSON: totalBytes, expectedSha256）
  PUT  /api/audits/<id>/segments/<start>/<end>
                             上传半开区间 [start,end) 区段（JSON: chunkBase64）
  GET  /api/audits/<id>/segments
                             读取送检进度（receiving/sealed/rejected、首个缺口/冲突）
  POST /api/audits/<id>/seal 确认封存
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
from urllib.parse import unquote, urlsplit

from . import codesig
from .store import MAX_CHUNK_BYTES, AuditStore, SubmissionError

MAX_BODY_BYTES = 4 * 1024 * 1024  # 整包 Base64 文本上限（解码后 <= 2 MiB）
# 单段原始字节 <= 64 KiB；这里只做请求体宽裕上限，解码后由存储层严格卡 64 KiB。
MAX_CHUNK_BODY_BYTES = 128 * 1024

INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>签封目录分页审计</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 980px; padding: 0 1rem; }
  textarea { width: 100%; height: 140px; font-family: ui-monospace, monospace; font-size: 12px; }
  input[type=text] { width: 280px; }
  button { padding: .4rem 1rem; margin-right: .5rem; margin-top: .3rem; }
  .ok { color: #0a7d28; font-weight: 700; }
  .bad { color: #c62828; font-weight: 700; }
  .warn { color: #b26a00; font-weight: 700; }
  .frozen { color: #555; font-size: 12px; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: 12px; }
  th, td { border: 1px solid #888; padding: .2rem .45rem; word-break: break-all; }
  th { background: rgba(128,128,128,.15); }
  tr.mismatch { background: rgba(198,40,40,.12); }
  .mono { font-family: ui-monospace, monospace; }
  .banner { padding: .6rem .8rem; border-radius: 6px; margin: .8rem 0; }
  .banner.verified, .banner.sealed { background: rgba(10,125,40,.12); }
  .banner.mismatch, .banner.error, .banner.rejected { background: rgba(198,40,40,.12); }
  .banner.receiving { background: rgba(178,106,0,.12); }
  .meta div { margin: .15rem 0; }
  details { margin-top: .6rem; }
  section { border: 1px solid rgba(128,128,128,.4); border-radius: 8px; padding: 1rem 1.2rem; margin: 1.2rem 0; }
  h2 { font-size: 1.05rem; margin-top: 0; }
  .ranges { font-family: ui-monospace, monospace; font-size: 12px; word-break: break-all; }
</style>
</head>
<body>
<h1>签封目录分页审计</h1>
<p>粘贴不超过 2 MiB 的 <strong>Base64 Mach-O 切片</strong>（单个大端 SuperBlob，
内含 SHA-256 CodeDirectory）与稳定审计标识。结论冻结后，同标识同字节重传返回原审计；
复用标识更换字节将被拒绝。大文件可使用下方<strong>分段送检</strong>：按半开区间
乱序上传不超过 64 KiB 的区段，断线后可读取已收连续覆盖范围并续传，确认封存后
才拼装、复算并冻结。</p>

<section>
<h2>一次性整包提交</h2>
<form id="f">
  <p><label>审计标识：<input type="text" name="auditId" required
    placeholder="例如 SAT-2026-PAYLOAD-07"></label></p>
  <p><label>Base64 载荷：<textarea name="payloadBase64" required></textarea></label></p>
  <button type="submit" id="submitBtn">提交并冻结审计</button>
  <button type="button" id="readBtn">按标识读取既有审计</button>
</form>
</section>

<section>
<h2>分段送检（乱序 / 断线续传）</h2>
<form id="sf">
  <p><label>审计标识：<input type="text" name="auditId" required
    placeholder="例如 SAT-2026-SEG-07"></label></p>
  <p><label>Base64 载荷（浏览器计算总字节数与 SHA-256）：
    <textarea name="payloadBase64" required></textarea></label></p>
  <button type="button" id="segBeginBtn">1. 开始/恢复分段送检</button>
  <button type="button" id="segHalfBtn">2. 仅乱序上传约一半区段（模拟断线）</button>
  <button type="button" id="segRestBtn">3. 续传其余区段</button>
  <button type="button" id="segAllBtn">2′. 乱序上传全部区段</button>
  <button type="button" id="segStateBtn">读取送检进度</button>
  <button type="button" id="segSealBtn">4. 确认封存并冻结审计</button>
</form>
</section>

<div id="out"></div>

<script>
const out = document.getElementById('out');

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

async function api(method, path, body) {
  const opt = {method, headers: {}};
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  return {ok: r.ok, status: r.status, data};
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
  if (rec.replayed) banner += `　<span class="frozen">（同标识同字节重传/重复封存，返回原审计）</span>`;
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

// ---- 分段送检 -------------------------------------------------------------
// 已解析的待送载荷与每段（原始字节）切分，下标即段号。
let segBytes = null;     // Uint8Array
let segRanges = [];      // [[start,end), ...]
let segDigest = null;
const SEG_RAW = 16 * 1024;  // 每段 16 KiB 原始字节（< 64 KiB 上限）

function b64ToBytes(text) {
  const clean = text.replace(/\\s+/g, '');
  const bin = atob(clean);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

async function digestHex(bytes) {
  const buf = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function segForm() {
  const id = document.forms.sf.auditId.value.trim();
  return {id};
}

// 浏览器自带 btoa 对 UTF-8 安全：逐字节编码。
function bytesToB64(u8, start, end) {
  let s = '';
  for (let i = start; i < end; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

async function ensureParsed() {
  const txt = document.forms.sf.payloadBase64.value;
  if (!txt.trim()) throw new Error('请填写 Base64 载荷');
  segBytes = b64ToBytes(txt);
  segDigest = await digestHex(segBytes);
  segRanges = [];
  for (let off = 0; off < segBytes.length; off += SEG_RAW)
    segRanges.push([off, Math.min(off + SEG_RAW, segBytes.length)]);
}

async function loadSeg() {
  const {id} = segForm();
  if (!id) { showError('请输入审计标识'); return null; }
  await ensureParsed();
  const r = await api('POST', `/api/audits/${encodeURIComponent(id)}/segments/begin`,
    {totalBytes: segBytes.length, expectedSha256: segDigest});
  if (!r.ok) { showError((r.data.error || ('HTTP ' + r.status)) + (r.data.state ? renderStateText(r.data.state) : '')); return null; }
  renderState(r.data, r.status === 201 ? '分段送检已开始' : '已恢复既有分段送检');
  return r.data;
}

function renderStateText(st) {
  let extra = '';
  if (st.firstGap) extra += `；首个缺口 [${st.firstGap[0]}, ${st.firstGap[1]})`;
  if (st.conflictRange) extra += `；冲突范围 [${st.conflictRange[0]}, ${st.conflictRange[1]})`;
  if (st.reason) extra += `；原因：${st.reason}`;
  return extra;
}

function renderState(st, title) {
  const cls = st.state === 'sealed' ? 'sealed' : st.state;
  const word = {receiving: '接收中（receiving）', sealed: '已封存（sealed）', rejected: '已拒绝（rejected）'}[st.state] || st.state;
  let html = `<div class="banner ${cls}"><strong>${esc(title || '送检状态')}：${esc(word)}</strong>`;
  html += `<div>总字节：${esc(st.totalBytes)}；已接收（合并后）：${esc(st.receivedBytes)}`
    + `；自 0 起连续覆盖：<strong>${esc(st.contiguousCoverage)}</strong></div>`;
  if (st.firstGap) html += `<div class="warn">首个缺口：<strong>[${st.firstGap[0]}, ${st.firstGap[1]})</strong></div>`;
  if (st.conflictRange) html += `<div class="bad">冲突范围：<strong>[${st.conflictRange[0]}, ${st.conflictRange[1]})</strong></div>`;
  if (st.reason) html += `<div>原因：${esc(st.reason)}</div>`;
  html += `</div><details><summary>已接收半开区间（${(st.coveredRanges||[]).length} 段）</summary>
    <div class="ranges">${esc((st.coveredRanges||[]).map(r => '['+r[0]+','+r[1]+')').join(' '))}</div></details>`;
  out.innerHTML = html;
}

// 乱序：偶数段在前、奇数段在后。
function shuffledIndexes(onlyHalf) {
  const evens = [], odds = [];
  segRanges.forEach((_, i) => (i % 2 ? odds : evens).push(i));
  if (onlyHalf) return evens;
  return evens.concat(odds);
}

async function upload(indexes) {
  const {id} = segForm();
  let st = null;
  for (const i of indexes) {
    const [s, e] = segRanges[i];
    const r = await api('PUT',
      `/api/audits/${encodeURIComponent(id)}/segments/${s}/${e}`,
      {chunkBase64: bytesToB64(segBytes, s, e)});
    if (!r.ok) {
      showError((r.data.error || ('HTTP ' + r.status)) + (r.data.state ? renderStateText(r.data.state) : ''));
      if (r.data.state) renderState(r.data.state, '区段被拒绝，送检已冻结');
      return null;
    }
    st = r.data;
  }
  if (st) renderState(st, `已上传 ${indexes.length} 个乱序区段`);
  return st;
}

document.getElementById('segBeginBtn').onclick = loadSeg;
document.getElementById('segHalfBtn').onclick = async () => {
  if (await loadSeg()) await upload(shuffledIndexes(true));
};
document.getElementById('segRestBtn').onclick = async () => {
  const st = await loadSeg();  // 恢复：begin 幂等返回既有覆盖
  if (st) await upload(shuffledIndexes(false));
};
document.getElementById('segAllBtn').onclick = async () => {
  if (await loadSeg()) await upload(shuffledIndexes(false));
};
document.getElementById('segStateBtn').onclick = async () => {
  const {id} = segForm();
  if (!id) { showError('请输入审计标识'); return; }
  const r = await api('GET', `/api/audits/${encodeURIComponent(id)}/segments`);
  if (!r.ok) { showError(r.data.error || ('HTTP ' + r.status)); return; }
  renderState(r.data, '送检进度');
};
document.getElementById('segSealBtn').onclick = async () => {
  const {id} = segForm();
  if (!id) { showError('请输入审计标识'); return; }
  const r = await api('POST', `/api/audits/${encodeURIComponent(id)}/seal`);
  if (!r.ok) {
    showError((r.data.error || ('HTTP ' + r.status)) + (r.data.state ? renderStateText(r.data.state) : ''));
    if (r.data.state) renderState(r.data.state, '封存被拒绝');
    return;
  }
  render(r.data);
};

// ---- 一次性整包 -----------------------------------------------------------
async function readExisting() {
  const id = document.forms.f.auditId.value.trim();
  if (!id) { showError('请输入审计标识'); return; }
  const r = await api('GET', '/api/audits/' + encodeURIComponent(id));
  if (!r.ok) { showError(r.data.error || ('HTTP ' + r.status)); return; }
  render(r.data);
}

document.getElementById('readBtn').onclick = readExisting;
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  out.textContent = '解析并逐页复算中…';
  const body = {
    auditId: document.forms.f.auditId.value.trim(),
    payloadBase64: document.forms.f.payloadBase64.value.replace(/\\s+/g, '')
  };
  const r = await api('POST', '/api/audits', body);
  if (!r.ok) { showError(r.data.error || ('HTTP ' + r.status)); return; }
  render(r.data);
});
</script>
</body>
</html>
"""


class _BodyTooLarge(Exception):
    """解码后的载荷超过相应上限（整包 2 MiB / 单段 64 KiB）。"""


def _decode_base64(text: str, max_bytes: int = codesig.MAX_BLOB_BYTES) -> bytes:
    """严格 Base64 解码：仅允许字母表字符与标准 = 填充（调用前已去空白）。"""
    if not text or len(text) % 4 != 0:
        raise ValueError("Base64 长度非法（须为 4 的倍数并带标准填充）")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Base64 解码失败：含非字母表字符或填充错误")
    if len(raw) == 0:
        raise ValueError("Base64 解码后为空载荷")
    if len(raw) > max_bytes:
        raise _BodyTooLarge(
            f"Base64 解码后 {len(raw)} 字节，超过 {max_bytes} 字节上限"
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

    def _read_json_body(self, max_bytes: int) -> dict:
        length_hdr = self.headers.get("Content-Length")
        try:
            length = int(length_hdr) if length_hdr is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            raise ValueError("需要 Content-Length")
        if length > max_bytes:
            raise _BodyTooLarge(f"请求体超过 {max_bytes} 字节上限")
        raw_body = self.rfile.read(length)
        payload = json.loads(raw_body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return payload

    def _submission_error(self, exc: SubmissionError) -> None:
        body: dict = {"error": exc.message, "status": exc.code}
        if exc.state is not None:
            body["state"] = exc.state
        self._json(exc.http_status, body)

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
                    "maxChunkBytes": MAX_CHUNK_BYTES,
                    "supportedHashType": "sha256",
                },
            )
            return
        if path == "/api/audits":
            self._json(200, {"auditIds": self.store.list_ids()})
            return
        if path.startswith("/api/audits/"):
            rest = unquote(path[len("/api/audits/") :])
            if rest.endswith("/segments"):
                audit_id = rest[: -len("/segments")]
                if not audit_id or "/" in audit_id:
                    self._json(404, {"error": "未知路径"})
                    return
                state = self.store.get_submission(audit_id)
                if state is None:
                    self._json(404, {"error": f"审计标识 {audit_id!r} 没有送检记录"})
                    return
                self._json(200, state)
                return
            audit_id = rest
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
        if path == "/api/audits":
            self._post_whole()
            return
        if path.startswith("/api/audits/"):
            rest = unquote(path[len("/api/audits/") :])
            if rest.endswith("/segments/begin"):
                self._post_begin(rest[: -len("/segments/begin")])
                return
            if rest.endswith("/seal"):
                self._post_seal(rest[: -len("/seal")])
                return
        self._json(404, {"error": "未知路径"})

    def do_PUT(self) -> None:
        path = urlsplit(self.path).path
        prefix = "/api/audits/"
        suffix_mid = "/segments/"
        if not path.startswith(prefix):
            self._json(404, {"error": "未知路径"})
            return
        rest = unquote(path[len(prefix) :])
        if suffix_mid not in rest or rest.endswith(suffix_mid):
            self._json(404, {"error": "未知路径"})
            return
        audit_id, tail = rest.split(suffix_mid, 1)
        if not audit_id or "/" in audit_id or "/" not in tail:
            self._json(404, {"error": "未知路径"})
            return
        start_text, end_text = tail.split("/", 1)
        if "/" in end_text:
            self._json(404, {"error": "未知路径"})
            return
        try:
            start = int(start_text)
            end = int(end_text)
        except ValueError:
            self._json(400, {"error": "区段端点必须为非负整数"})
            return
        self._put_chunk(audit_id, start, end)

    # ---- 整包提交（原语义不变）----------------------------------------------
    def _post_whole(self) -> None:
        try:
            payload = self._read_json_body(MAX_BODY_BYTES)
            audit_id = payload.get("auditId")
            b64_text = payload.get("payloadBase64")
            if not isinstance(b64_text, str):
                raise ValueError("payloadBase64 必须是字符串")
            b64_text = "".join(b64_text.split())  # 仅去除空白
            blob = _decode_base64(b64_text)
        except _BodyTooLarge as exc:
            self._json(413, {"error": str(exc)})
            return
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": f"请求格式不合法：{exc}"})
            return

        outcome = self.store.submit(str(audit_id) if audit_id is not None else "", blob)
        if outcome.status in ("created", "returned_existing"):
            assert outcome.record is not None
            self._json(outcome.http_status, outcome.record)
        else:
            self._json(outcome.http_status, {"error": outcome.error, "status": outcome.status})

    # ---- 分段送检 ------------------------------------------------------------
    def _post_begin(self, audit_id: str) -> None:
        if not audit_id or "/" in audit_id:
            self._json(404, {"error": "未知路径"})
            return
        try:
            payload = self._read_json_body(4096)
            state, created = self.store.begin_submission(
                audit_id,
                payload.get("totalBytes"),
                payload.get("expectedSha256"),
            )
        except _BodyTooLarge as exc:
            self._json(413, {"error": str(exc)})
            return
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": f"请求格式不合法：{exc}"})
            return
        except SubmissionError as exc:
            self._submission_error(exc)
            return
        self._json(201 if created else 200, state)

    def _put_chunk(self, audit_id: str, start: int, end: int) -> None:
        try:
            payload = self._read_json_body(MAX_CHUNK_BODY_BYTES)
            b64_text = payload.get("chunkBase64")
            if not isinstance(b64_text, str):
                raise ValueError("chunkBase64 必须是字符串")
            b64_text = "".join(b64_text.split())
            data = _decode_base64(b64_text, max_bytes=MAX_CHUNK_BYTES)
            state = self.store.put_chunk(audit_id, start, end, data)
        except _BodyTooLarge:
            self._json(
                413,
                {"error": f"单段超过 {MAX_CHUNK_BYTES} 字节（64 KiB）上限"},
            )
            return
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": f"请求格式不合法：{exc}"})
            return
        except SubmissionError as exc:
            self._submission_error(exc)
            return
        self._json(200, state)

    def _post_seal(self, audit_id: str) -> None:
        if not audit_id or "/" in audit_id:
            self._json(404, {"error": "未知路径"})
            return
        # 封存不接受任何载荷参数：允许空请求体；非空时必须是合法 JSON 对象。
        length_hdr = self.headers.get("Content-Length")
        try:
            length = int(length_hdr) if length_hdr is not None else 0
        except ValueError:
            length = -1
        if length < 0:
            self._json(400, {"error": "Content-Length 非法"})
            return
        if length > 4096:
            self._json(413, {"error": "请求体超过 4096 字节上限"})
            return
        if length > 0:
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw.decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("请求体必须是 JSON 对象")
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": f"请求格式不合法：{exc}"})
                return
        try:
            outcome = self.store.seal_submission(audit_id)
        except SubmissionError as exc:
            self._submission_error(exc)
            return
        assert outcome.record is not None
        self._json(outcome.http_status, outcome.record)


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
