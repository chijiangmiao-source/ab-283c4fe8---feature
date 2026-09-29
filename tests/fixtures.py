"""测试夹具：手工构造大端 SuperBlob + SHA-256 CodeDirectory。

与真实 Mach-O 同构：载荷 = 代码字节 + SuperBlob，CodeDirectory 的代码槽对
载荷 [0, codeLimit) 按声明页长逐页哈希；SuperBlob 位于 codeLimit 之后，
其内索引偏移相对 SuperBlob 起点，解析器按绝对偏移读取。

CodeDirectory 头部（44 字节，version>=0x20100）：
  0  magic        4  length       8  version     12 flags
  16 hashOffset   20 identOffset  24 nSpecial    28 nCode
  32 codeLimit    36 hashSize(B)  37 hashType(B) 38 platform(B)
  39 pageSize(B)  40 scatterOffset(I)
其后为 ident(NUL 结尾)、特殊槽（hashOffset 的负偏移区）、代码槽。
"""

from __future__ import annotations

import hashlib
import struct
from typing import List, Optional

SB_MAGIC = 0xFADE0CC0
CD_MAGIC = 0xFADE0C02
HASH_SIZE = 32


def fixed_header_size(version: int) -> int:
    if version >= 0x20600:
        return 96  # + preEncryptOffset
    if version >= 0x20500:
        return 92  # + runtime + 3 字节填充
    if version >= 0x20400:
        return 88  # + execSegBase/Limit/Flags
    if version >= 0x20300:
        return 64  # + spare3 + codeLimit64
    if version >= 0x20200:
        return 52  # + teamOffset
    if version >= 0x20100:
        return 48  # + scatterOffset
    return 44  # 基础头部（含 spare2）


def build_header(
    version: int,
    cd_length: int,
    hash_offset: int,
    ident_off: int,
    n_special: int,
    n_code: int,
    code_limit: int,
    hash_size: int,
    hash_type: int,
    page_exp: int,
) -> bytes:
    """按 cs_blobs.h 布局构造 CodeDirectory 固定头部（大端、无填充）。"""
    h = struct.pack(
        ">IIIIIIII",
        CD_MAGIC, cd_length, version, 0, hash_offset, ident_off,
        n_special, n_code,
    )
    h += struct.pack(">IBBBB", code_limit, hash_size, hash_type, 0, page_exp)
    assert len(h) == 40
    h += struct.pack(">I", 0)  # spare2 @40（基础头部，必须为 0）
    if version >= 0x20100:
        h += struct.pack(">I", 0)  # scatterOffset @44
    if version >= 0x20200:
        h += struct.pack(">I", 0)  # teamOffset @48
    if version >= 0x20300:
        h += struct.pack(">I", 0)  # spare3 @52
        h += struct.pack(">Q", code_limit)  # codeLimit64 @56
    if version >= 0x20400:
        h += struct.pack(">QQQ", 0, 0, 0)  # execSeg @64/72/80
    if version >= 0x20500:
        h += struct.pack(">B3s", 0, b"\x00\x00\x00")  # runtime @88 + padding
    if version >= 0x20600:
        h += struct.pack(">I", 0)  # preEncryptOffset @92
    return h


def build_signed_payload(
    code: bytes,
    page_exp: int = 12,
    *,
    n_special: int = 2,
    hash_type: int = 2,
    hash_size: int = HASH_SIZE,
    code_limit: Optional[int] = None,
    n_code_override: Optional[int] = None,
    extra_slack: int = 0,
    ident: bytes = b"payload-test\x00",
    declared_hashes: Optional[List[bytes]] = None,
    version: int = 0x20400,
    tail: bytes = b"",
) -> bytes:
    """按 code 的分页哈希构造完整载荷 code + SuperBlob(+tail)。"""
    page_size = 1 << page_exp
    code_limit = len(code) if code_limit is None else code_limit
    n_pages = (code_limit + page_size - 1) // page_size
    n_pages_decl = n_code_override if n_code_override is not None else n_pages

    header = fixed_header_size(version)
    ident_off = header
    prefix = ident + bytes(n_special * hash_size)
    hash_offset = header + len(prefix)  # 指向代码槽 0（特殊槽在其负偏移区）

    if declared_hashes is None:
        code_hashes = b"".join(
            hashlib.sha256(
                code[s * page_size : min(s * page_size + page_size, code_limit)]
            ).digest()
            for s in range(n_pages_decl)
        )
    else:
        code_hashes = b"".join(declared_hashes)

    cd_body = prefix + code_hashes + bytes(extra_slack)
    cd_length = header + len(cd_body)

    cd = build_header(
        version, cd_length, hash_offset, ident_off, n_special, n_pages_decl,
        code_limit, hash_size, hash_type, page_exp,
    )
    cd += cd_body
    assert len(cd) == cd_length

    cd_offset_in_sb = 20  # SB 头 12 + 1 条索引 8
    sb_len = cd_offset_in_sb + len(cd)
    sb = struct.pack(">III", SB_MAGIC, sb_len, 1)
    sb += struct.pack(">II", 0, cd_offset_in_sb)
    sb += cd
    assert len(sb) == sb_len

    payload = code + sb + tail
    return payload


def make_payload(n_pages: int = 3, page_exp: int = 12, tail: bytes = b"") -> bytes:
    """生成含非整页尾的 code 并签名。"""
    page_size = 1 << page_exp
    code = bytes(
        (i * 7 + 3) & 0xFF for i in range(page_size * (n_pages - 1) + 37)
    )
    return build_signed_payload(code, page_exp=page_exp, tail=tail)


def wrap_blob(magic: int, body: bytes = b"") -> bytes:
    return struct.pack(">II", magic, 8 + len(body)) + body


def build_multi_blob_payload(
    code: bytes,
    page_exp: int = 12,
    *,
    extra: "list[tuple[int, bytes]] | None" = None,
) -> bytes:
    """构造含多个索引条目的 SuperBlob：CodeDirectory(slot0) + 附加 blob。

    extra 为 (slot_type, blob_bytes) 列表，按给定顺序紧密排布在 CD 之后。
    """
    page_size = 1 << page_exp
    code_limit = len(code)
    n_pages = (code_limit + page_size - 1) // page_size
    version = 0x20400
    header = fixed_header_size(version)
    ident = b"payload-test\x00"
    n_special = 2
    ident_off = header
    prefix = ident + bytes(n_special * HASH_SIZE)
    hash_offset = header + len(prefix)
    code_hashes = b"".join(
        hashlib.sha256(
            code[s * page_size : min(s * page_size + page_size, code_limit)]
        ).digest()
        for s in range(n_pages)
    )
    cd_body = prefix + code_hashes
    cd_len = header + len(cd_body)
    cd = build_header(
        version, cd_len, hash_offset, ident_off, n_special, n_pages,
        code_limit, HASH_SIZE, 2, page_exp,
    ) + cd_body

    entries: list[tuple[int, bytes]] = [(0, cd)]
    for slot_type, blob in extra or []:
        entries.append((slot_type, blob))

    table_size = 12 + 8 * len(entries)
    offset = table_size
    index = b""
    blobs = b""
    for slot_type, blob in entries:
        index += struct.pack(">II", slot_type, offset)
        blobs += blob
        offset += len(blob)

    sb_len = table_size + len(blobs)
    sb = struct.pack(">III", SB_MAGIC, sb_len, len(entries)) + index + blobs
    return code + sb

