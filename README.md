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

## API

| 方法 | 路径 | 说明 |
| --- | --- | ---
| GET | `/` | 粘贴页面（Base64 切片 + 审计标识） |
| POST | `/api/audits` | 提交 `{auditId, payloadBase64}` |
| GET | `/api/audits` | 已有审计标识列表 |
| GET | `/api/audits/<id>` | 读取冻结审计（结论、CD 摘要、页长、覆盖范围、逐页证据） |
| GET | `/healthz` | 健康状态 |

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
app/store.py      冻结审计存储（SQLite，幂等/复用拒绝/失败不落库）
app/server.py     HTTP API + 粘贴页面（仅 Python 标准库）
tests/            55 项单元/HTTP 测试（含手工构造的真实结构夹具）
scripts/smoke_http.py  compose verify 调用的 HTTP 冒烟
docker-compose.yml     audit + verify 两个服务
```
