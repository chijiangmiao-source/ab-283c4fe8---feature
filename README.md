# 签封目录分页审计（CodeDirectory Page Audit）

星载载荷上线前，审查员需核对供应商固件内嵌的签封目录是否**逐页覆盖可执行字节**，
防止查看器只显示“签名存在”却漏掉被替换的页面。本服务接收不超过 2 MiB 的
Base64 Mach-O 切片与稳定审计标识，严格解析其中**唯一一个大端 SuperBlob** 里的
**SHA-256 CodeDirectory**，按声明页长对原始字节逐页复算，给出冻结结论。

## 它校验什么（fail-closed）

仅接受一个大端 `CS_GenericBlob` SuperBlob（magic `0xFADE0CC0`）中的
SHA-256（hashType=2，hashSize=32）CodeDirectory（magic `0xFADE0C02`），并严格校验：

| 校验点 | 处理 |
| --- | --- |
| SuperBlob length、索引计数、偏移升序、偏移侵入索引表/越界 | 拒绝，不留结论 |
| SuperBlob 魔数在切片中位置唯一且全部结构校验通过 | 多义/多 SuperBlob 拒绝 |
| SuperBlob 延伸至切片末尾（其后不得有未声明字节） | 拒绝 |
| 各索引 blob（Requirements / Entitlements / DER / CMS）魔数白名单、长度恰好填满、无重叠缝隙 | 拒绝 |
| 仅一个 CodeDirectory，且其 `length` 与索引界定长度一致 | 拒绝 |
| 固定头部各版本字段（spare2、scatterOffset、teamOffset、spare3、codeLimit64、execSeg*、preEncryptOffset） | 非零/不一致/版本 >0x20600 拒绝 |
| 不支持的散列类型（非 SHA-256）、hashSize≠32 | 拒绝 |
| 不支持的页指数（`pageSize` 字段 <1 或 >16，即 2B～64KiB） | 拒绝 |
| 代码槽数必须恰好等于 `ceil(codeLimit/pageSize)`；`codeLimit` 不得越过签名起点 | 拒绝 |
| 哈希槽边界（特殊槽在 `hashOffset` 负偏移区，代码槽在其后，全部落在 CD length 内） | 拒绝 |
| ident NUL 结尾、不伸入哈希区 | 拒绝 |
| **逐页 SHA-256 复算**：`sha256(slice[slot*page .. min(+page,codeLimit)])` 与声明槽逐字节比较 | 任一页不符 => `mismatch`，指出**首个失败槽**，绝不记为通过 |

说明：代码槽若为 32 字节全零（`CS_HOLE`），其与任意页的 SHA-256 都不可能相等，
因此必判该页失败——未真正封页的位置不能被“签名存在”掩盖。

## 冻结语义

* **同标识 + 同字节**（以载荷 SHA-256 判定）重传 → **200 返回原审计**（幂等，带 `replayed` 标记）；
* **复用标识但字节不同** → **409 拒绝**，既有冻结记录原样保留；
* **结构解析失败** → **422**，**不写库**，不占用标识，绝不留下“成功结论”；
* `verified` 与 `mismatch` 都是完整、冻结、可重复读取的结论。

## 分段送检（乱序 / 断线续传）

大切片可分段提交：审查员以**同一审计标识、总字节数、预期载荷 SHA-256** 开始送检，
随后把载荷切成**不超过 64 KiB** 的 Base64 区段，按**半开区间 `[start,end)` 乱序**
上传。每段的区间与原始字节在收到后立即写入 SQLite，断线或进程重启后用
`GET …/segments` 读取**自 0 起的连续覆盖范围与首个缺口**，重新 `begin`（幂等）后续传。

* 区间重叠时，重叠部分必须**逐字节相同**：完全相同的重传幂等去重；
* 任一重叠字节不一致 → 送检**永久冻结为 `rejected`**，响应与进度接口给出
  **首个冲突范围**；冲突段本身不落库；
* `begin` 时变更总字节数或预期摘要 → 同样冻结为 `rejected`；
* 冲突拒绝**不影响**任何已存在的完整冻结审计，也绝不产生可读取的成功审计；
* **确认封存**（`POST …/seal`）只在 `[0,totalBytes)` 无空洞、总长 ≤ 2 MiB、
  拼装字节整体 SHA-256 与预期摘要一致后，才进入严格 SuperBlob 解析与逐页复核；
  通过后在**同一立即事务**中生成（或复用）冻结审计并把送检置为 `sealed`；
* 结构解析失败只把该送检置为 `rejected`（原因可在进度接口读取），不写审计；
* 封存与最后一段并发、进程重启、重复封存都不会产生两份审计、漏页或改变页证据；
* 既有一次性整包提交与读取接口的语义完全不变；对进行中的同标识送检，整包提交
  仅在其字节恰为声明完整载荷时代为封存，否则 409。

送检进度字段：`state`（`receiving`/`sealed`/`rejected`）、`totalBytes`、
`expectedSha256`、`coveredRanges`（合并后的半开区间）、`receivedBytes`、
`contiguousCoverage`（自 0 起连续覆盖字节数）、`firstGap`、`conflictRange`、`reason`。

## API

| 方法 | 路径 | 说明 |
| --- | --- | ---
| GET | `/` | 粘贴页面（整包提交 + 分段送检控件） |
| POST | `/api/audits` | 提交 `{auditId, payloadBase64}` |
| GET | `/api/audits` | 已有审计标识列表 |
| GET | `/api/audits/<id>` | 读取冻结审计（结论、CD 摘要、页长、覆盖范围、逐页证据） |
| POST | `/api/audits/<id>/segments/begin` | 开始/恢复送检 `{totalBytes, expectedSha256}`（首次 201，恢复 200） |
| PUT | `/api/audits/<id>/segments/<start>/<end>` | 上传 `[start,end)` 区段 `{chunkBase64}`（原始字节 ≤ 64 KiB） |
| GET | `/api/audits/<id>/segments` | 送检进度：状态、覆盖区间、首个缺口或冲突范围 |
| POST | `/api/audits/<id>/seal` | 确认封存；无空洞且摘要一致后冻结审计（可空请求体） |
| GET | `/healthz` | 健康状态（含 `maxChunkBytes`） |

冻结审计字段：`verdict`（verified/mismatch）、`codeDirectorySha256`（代码目录摘要）、
`pageSize`、`codeLimit`、`codeSlots`、`coveredBytes`、`firstFailedSlot`、
`pages[]`（按页升序，每页含 slot/offset/declared/actual/match/hole）。

## 运行

```bash
# 宿主机端口可配置（默认 8080）
AUDIT_HOST_PORT=9090 docker compose up --build
# 浏览器访问 http://localhost:9090
```

环境变量：`AUDIT_HOST`（默认 0.0.0.0）、`AUDIT_PORT`（容器内，默认 8080）、
`AUDIT_DB`（默认 /data/audits.sqlite3）。

## 验证（compose verify）

`verify` 服务结合**代码测试**（pytest）、**构建检查**（镜像构建时 py_compile），
以及**提交后读取冻结审计与健康状态的 HTTP 冒烟**（`scripts/smoke_http.py`）
确认分页证据与幂等行为；执行完毕后退出，并以退出码报告结果：

```bash
docker compose up --build --abort-on-container-exit --exit-code-from verify
# verify 退出码 0 即全部通过；非零即失败
```

无 Docker 时可本地等价运行：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pytest
python -m pytest -q                                   # 代码测试
python -m py_compile app/*.py scripts/*.py            # 构建检查
AUDIT_PORT=18080 AUDIT_DB=/tmp/a.sqlite3 python -m app.server &
python scripts/smoke_http.py http://127.0.0.1:18080   # HTTP 冒烟，退出码报告结果
```

## 目录

```
app/codesig.py    大端 SuperBlob / SHA-256 CodeDirectory 严格解析 + 逐页复算
app/store.py      冻结审计 + 分段送检存储（SQLite，立即事务、乱序区段持久化、
                  重叠冲突冻结、无空洞/摘要/结构三重门封存、重复封存复用）
app/server.py     HTTP API + 粘贴页面（整包提交 + 分段送检，仅 Python 标准库）
tests/            80 项单元/HTTP 测试（含手工构造的真实结构夹具、并发封存、
                  重启续传）
scripts/smoke_http.py  compose verify 调用的 HTTP 冒烟（含乱序分段、进程重启
                       续传、冲突重传、封存分页证据）
docker-compose.yml     audit + verify 两个服务
```
