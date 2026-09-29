"""大端 SuperBlob 与 SHA-256 CodeDirectory 的严格解析、逐页复算。

本模块只做两件事：

1. ``parse_superblob``：按 Apple Code Signing 结构（``CS_*`` 魔数、
   ``CS_CodeDirectory`` 类型、CodeDirectory slots/pageSize/codeLimit 等字段）
   严格校验长度、索引、偏移、哈希槽边界，取出唯一一个 SHA-256 CodeDirectory
   及其代码槽。
2. ``verify_pages``：以原始字节按声明页长复算全部代码槽，并给出按页升序的
   比对证据。任一页不符时返回首个失败槽，且结论恒为 ``mismatch``——
   调用方绝不能把部分比对结果记为通过。

参考：``<mach-o/loader.h>`` 旁的 cs_blobs.h 布局（所有多字节整数均为大端）。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional

# ---- 魔数与类型（cs_blobs.h） ------------------------------------------------
CS_MAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0  # SuperBlob
CS_MAGIC_CODEDIRECTORY = 0xFADE0C02  # CodeDirectory

# SuperBlob 中允许共存的其他 blob 魔数（仅用于结构合法性白名单）。
CS_MAGIC_REQUIREMENTS = 0xFADE0C01
CS_MAGIC_ENTITLEMENTS = 0xFADE0C71
CS_MAGIC_DER_ENTITLEMENTS = 0xFADE0C72
CS_MAGIC_BLOBWRAPPER = 0xFADE0B01  # CMS 签名包装
_KNOWN_BLOB_MAGICS = {
    CS_MAGIC_CODEDIRECTORY,
    CS_MAGIC_REQUIREMENTS,
    CS_MAGIC_ENTITLEMENTS,
    CS_MAGIC_DER_ENTITLEMENTS,
    CS_MAGIC_BLOBWRAPPER,
}

CSSLOT_CODEDIRECTORY = 0  # CodeDirectory 自身的特殊槽
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_APPLICATION = 4
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_SIGNATURESLOT = 0x10000  # CMS 签名
CSSLOT_IDENTIFICATIONSLOT = 0x10001

CS_HOLE = bytes(32)  # 未使用代码槽的占位：32 字节 0

# 只接受 SHA-256：CodeDirectory.hashType == 2 且哈希长度为 32。
SUPPORTED_HASHTYPE = 2
SHA256_DIGEST_LEN = 32

MAX_BLOB_BYTES = 2 * 1024 * 1024  # 与上传限制一致：2 MiB


class CodeSignatureError(ValueError):
    """结构解析 / 边界校验失败。message 面向审计记录与用户展示。"""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class CodeDirectory:
    """解析出的 CodeDirectory 视图（仍以 blob 为 backing buffer）。"""

    cd_offset: int  # CodeDirectory 在 blob 内的偏移
    cd_length: int  # 由 SuperBlob 索引声明的长度
    version: int
    flags: int
    hash_offset: int  # 特殊槽区起点（相对 CD 起点）
    ident_offset: int
    ident: str
    n_special_slots: int
    n_code_slots: int
    code_limit: int
    hash_type: int
    hash_size: int
    page_size: int  # 1 << pageSize 字段
    page_exp: int
    code_hashes: List[bytes]  # 长度 n_code_slots，逐条 32 字节
    raw: bytes  # CodeDirectory 原始字节（用于自身 CD 哈希等场景）

    @property
    def code_directory_digest(self) -> str:
        """CodeDirectory 自身的 SHA-256（sha256(cd 原始字节)，十六进制）。"""
        return hashlib.sha256(self.raw).hexdigest()


@dataclass(frozen=True)
class SuperBlobView:
    length: int  # 整段 Mach-O 切片长度
    signature_start: int  # SuperBlob 在切片中的偏移
    signature_end: int  # SuperBlob 声明的结尾
    code_directory: CodeDirectory


@dataclass
class PageEvidence:
    """按页升序的单页比对证据。"""

    slot: int  # 代码槽下标（从 0 起），即页号
    offset: int  # 该页在原始 Mach-O 切片中的字节偏移
    declared: str  # CD 中声明的哈希（十六进制）
    actual: str  # 按原始字节复算出的哈希（十六进制）
    match: bool
    is_hole: bool  # 声明槽是否为全零占位（CS_HOLE）


@dataclass
class VerificationResult:
    verdict: str  # "verified" | "mismatch"
    page_size: int
    code_limit: int
    n_code_slots: int
    covered_bytes: int  # 被代码槽实际覆盖的字节数（<= codeLimit）
    code_directory_digest: str
    pages: List[PageEvidence] = field(default_factory=list)
    first_failed_slot: Optional[int] = None

    @property
    def passed(self) -> bool:
        return self.verdict == "verified"

    def to_public_dict(self) -> dict:
        """供 API/页面展示：冻结结论、摘要、页长、覆盖范围、逐页证据。"""
        return {
            "verdict": self.verdict,
            "codeDirectorySha256": self.code_directory_digest,
            "pageSize": self.page_size,
            "codeLimit": self.code_limit,
            "codeSlots": self.n_code_slots,
            "coveredBytes": self.covered_bytes,
            "firstFailedSlot": self.first_failed_slot,
            "pages": [
                {
                    "slot": p.slot,
                    "offset": p.offset,
                    "declared": p.declared,
                    "actual": p.actual,
                    "match": p.match,
                    "hole": p.is_hole,
                }
                for p in self.pages
            ],
        }


def _u32(buf: bytes, off: int, what: str) -> int:
    if off < 0 or off + 4 > len(buf):
        raise CodeSignatureError(f"{what} 越界（offset={off}）")
    return int.from_bytes(buf[off : off + 4], "big")


_MAGIC_BYTES = CS_MAGIC_EMBEDDED_SIGNATURE.to_bytes(4, "big")


def parse_superblob(blob: bytes) -> SuperBlobView:
    """在完整 Mach-O 切片中严格定位并解析唯一的大端 SuperBlob。

    提交的是完整切片：代码页从偏移 0 开始，SuperBlob 嵌在 codeLimit 之后
    （Mach-O 里位于 LC_CODE_SIGNATURE 指向处）。因此：

    * SuperBlob 魔数必须恰好出现一次且能通过全部结构校验（防止代码区中
      偶然出现同名字节造成歧义）；
    * SuperBlob 的 length 字段、索引表、各 blob 偏移/边界逐一校验；
    * 仅接受一个 CodeDirectory，且其 codeLimit 不得越过签名起点
      （否则代码页与签名结构重叠）；
    * 签名结构须恰好延伸到切片末尾，禁止在其后追加未被声明的字节。
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise CodeSignatureError("载荷必须是原始字节")
    blob = bytes(blob)
    total = len(blob)
    if total == 0:
        raise CodeSignatureError("空载荷")
    if total > MAX_BLOB_BYTES:
        raise CodeSignatureError(
            f"载荷超过 {MAX_BLOB_BYTES} 字节（2 MiB）上限（实际 {total}）"
        )

    # 收集所有魔数候选位置，逐个做完整结构校验，恰好一个合法才接受。
    candidates = []
    pos = blob.find(_MAGIC_BYTES)
    while pos != -1:
        candidates.append(pos)
        pos = blob.find(_MAGIC_BYTES, pos + 1)
    if not candidates:
        raise CodeSignatureError(
            "切片中找不到大端 Embedded Signature SuperBlob（magic 0xFADE0CC0）"
        )

    valid_views: List[SuperBlobView] = []
    first_error = "未知结构错误"
    for sb_start in candidates:
        try:
            valid_views.append(_parse_at(blob, sb_start, total))
        except CodeSignatureError as exc:
            if not valid_views:
                first_error = exc.message
    if not valid_views:
        raise CodeSignatureError(f"SuperBlob 结构校验失败：{first_error}")
    if len(valid_views) > 1:
        raise CodeSignatureError(
            f"切片中出现 {len(valid_views)} 个可通过校验的 SuperBlob，位置歧义，拒绝"
        )
    return valid_views[0]


def _parse_at(blob: bytes, sb_start: int, total: int) -> SuperBlobView:
    if total - sb_start < 12:
        raise CodeSignatureError("载荷短于 SuperBlob 头部（12 字节）")

    sb_len = _u32(blob, sb_start + 4, "SuperBlob length")
    if sb_len < 12:
        raise CodeSignatureError(f"SuperBlob length {sb_len} 短于头部")
    sb_end = sb_start + sb_len
    if sb_end > total:
        raise CodeSignatureError(
            f"SuperBlob 越界：起点 {sb_start} + length {sb_len} = {sb_end}"
            f" 超过切片总长 {total}"
        )
    if sb_end != total:
        raise CodeSignatureError(
            f"SuperBlob 之后存在 {total - sb_end} 个未声明字节（签名须延伸至切片末尾）"
        )

    count = _u32(blob, sb_start + 8, "SuperBlob count")
    if count == 0:
        raise CodeSignatureError("SuperBlob 索引计数为 0")
    index_end = sb_start + 12 + count * 8
    if index_end > sb_end:
        raise CodeSignatureError(
            f"索引表越界（需要至 {index_end}，SuperBlob 终于 {sb_end}）"
        )

    cd_index: Optional[tuple] = None
    prev_offset: Optional[int] = None
    for i in range(count):
        ent = sb_start + 12 + i * 8
        slot_type = _u32(blob, ent, f"索引[{i}].type")
        offset = _u32(blob, ent + 4, f"索引[{i}].offset")
        if offset < 12 + count * 8:
            raise CodeSignatureError(
                f"索引[{i}] 偏移 {offset} 侵入索引表（表长 {12 + count * 8}）"
            )
        if offset >= sb_len:
            raise CodeSignatureError(
                f"索引[{i}] 偏移 {offset} 越界（SuperBlob length={sb_len}）"
            )
        # 内核解析器要求偏移严格升序。
        if prev_offset is not None and offset <= prev_offset:
            raise CodeSignatureError(
                f"索引[{i}] 偏移未严格升序（{prev_offset} -> {offset}）"
            )

        # 每个被索引的 blob 都必须有已知魔数且自报长度不越过下一 blob
        # （或 SuperBlob 结尾）——防止用畸形附加 blob 夹带未覆盖字节。
        abs_off = sb_start + offset
        if abs_off + 8 > sb_end:
            raise CodeSignatureError(f"索引[{i}] blob 头部越界")
        blob_magic = _u32(blob, abs_off, f"索引[{i}] blob magic")
        if blob_magic not in _KNOWN_BLOB_MAGICS:
            raise CodeSignatureError(
                f"索引[{i}] 未知 blob 魔数 0x{blob_magic:08X}"
            )
        blob_decl_len = _u32(blob, abs_off + 4, f"索引[{i}] blob length")
        if blob_decl_len < 8:
            raise CodeSignatureError(
                f"索引[{i}] blob length {blob_decl_len} 短于 8 字节头部"
            )
        boundary = sb_len
        if i + 1 < count:
            boundary = _u32(
                blob, sb_start + 12 + (i + 1) * 8 + 4, "下一索引偏移"
            )
        if offset + blob_decl_len != boundary:
            raise CodeSignatureError(
                f"索引[{i}] blob 自报长度 {blob_decl_len} 未恰好填满到"
                f"下一 blob/结尾（offset={offset}, 边界={boundary}）："
                "blob 之间不允许缝隙或重叠"
            )

        prev_offset = offset
        if slot_type == CSSLOT_CODEDIRECTORY:
            if cd_index is not None:
                raise CodeSignatureError("SuperBlob 中出现多个 CodeDirectory")
            cd_index = (i, offset)

    if cd_index is None:
        raise CodeSignatureError("SuperBlob 中没有 CodeDirectory（slot 0）")

    i, cd_rel = cd_index
    # 用下一条索引的偏移界定本 blob 末尾；最后一条则到 SuperBlob 结尾。
    next_rel = sb_len
    if i + 1 < count:
        next_rel = _u32(
            blob, sb_start + 12 + (i + 1) * 8 + 4, "下一索引偏移"
        )
    cd_len = next_rel - cd_rel
    if cd_len <= 0:
        raise CodeSignatureError("CodeDirectory 长度非正")

    cd = _parse_code_directory(blob, sb_start + cd_rel, cd_len)

    # 代码页取自切片 [0, codeLimit)，签名结构必须在代码覆盖区之后。
    if cd.code_limit > sb_start:
        raise CodeSignatureError(
            f"codeLimit {cd.code_limit} 越过签名起点 {sb_start}："
            "代码页与 SuperBlob 重叠"
        )
    return SuperBlobView(
        length=total,
        signature_start=sb_start,
        signature_end=sb_end,
        code_directory=cd,
    )



def _parse_code_directory(blob: bytes, off: int, length: int) -> CodeDirectory:
    total = len(blob)
    if length < 8:
        raise CodeSignatureError("CodeDirectory 短于 blob 头部（8 字节）")
    magic = _u32(blob, off, "CodeDirectory magic")
    if magic != CS_MAGIC_CODEDIRECTORY:
        raise CodeSignatureError(
            f"CodeDirectory 魔数错误（magic=0x{magic:08X}）"
        )
    cd_declared_len = _u32(blob, off + 4, "CodeDirectory length")
    if cd_declared_len != length:
        raise CodeSignatureError(
            f"CodeDirectory length {cd_declared_len} 与索引界定长度 {length} 不符"
        )
    if off + length > total:
        raise CodeSignatureError("CodeDirectory 超出 SuperBlob 边界")

    # CS_CodeDirectory 头部（cs_blobs.h，大端存储，无填充）：
    # 0  magic; 4 length; 8 version; 12 flags; 16 hashOffset;
    # 20 identOffset; 24 nSpecialSlots; 28 nCodeSlots; 32 codeLimit;
    # 36 hashSize(B); 37 hashType(B); 38 platform(B); 39 pageSize(B);
    # 40 spare2(I 必须为0); 44 scatterOffset(I); 48 teamOffset(I);
    # 52 spare3(I); 56 codeLimit64(u64)。
    if length < 44:
        raise CodeSignatureError(
            "CodeDirectory 短于固定头部（44 字节，缺少 spare2）"
        )
    version = _u32(blob, off + 8, "CodeDirectory version")
    flags = _u32(blob, off + 12, "CodeDirectory flags")
    hash_offset = _u32(blob, off + 16, "hashOffset")
    ident_offset = _u32(blob, off + 20, "identOffset")
    n_special = _u32(blob, off + 24, "nSpecialSlots")
    n_code = _u32(blob, off + 28, "nCodeSlots")
    code_limit = _u32(blob, off + 32, "codeLimit")
    hash_size = blob[off + 36]
    hash_type = blob[off + 37]
    # blob[off+38] = platform（0 也合法，不限制）
    page_exp = blob[off + 39]
    if _u32(blob, off + 40, "spare2") != 0:
        raise CodeSignatureError("CodeDirectory spare2 非零（必须为 0）")
    # v0x20100 起 scatterOffset 位于 44；非零表示另一套 scatter 向量分页
    # 方案，不在“按声明页长逐槽 SHA-256”的接受范围内。
    if version >= 0x20100:
        if length < 48:
            raise CodeSignatureError(
                f"CodeDirectory version 0x{version:X} 头部不足 48 字节"
            )
        scatter_offset = _u32(blob, off + 44, "scatterOffset")
        if scatter_offset != 0:
            raise CodeSignatureError(
                f"不支持的 scatter 分页向量（scatterOffset={scatter_offset}）"
            )
        fixed_header = 48
        # v0x20200 增加 teamOffset@48。
        if version >= 0x20200:
            if length < 52:
                raise CodeSignatureError(
                    f"CodeDirectory version 0x{version:X} 头部不足 52 字节"
                )
            fixed_header = 52
        # v0x20300 增加 spare3@52 与 codeLimit64@56（8 字节）：切片远小于
        # 4 GiB，codeLimit64 必须与 u32 codeLimit 一致，防止用高位扩展覆盖。
        if version >= 0x20300:
            if length < 64:
                raise CodeSignatureError(
                    f"CodeDirectory version 0x{version:X} 头部不足 64 字节"
                )
            code_limit64 = int.from_bytes(blob[off + 56 : off + 64], "big")
            if code_limit64 != code_limit:
                raise CodeSignatureError(
                    f"codeLimit64 {code_limit64} 与 codeLimit {code_limit} 不一致"
                )
            fixed_header = 64
        # v0x20400 增加 execSegBase@64 / execSegLimit@72 / execSegFlags@80。
        if version >= 0x20400:
            if length < 88:
                raise CodeSignatureError(
                    f"CodeDirectory version 0x{version:X} 头部不足 88 字节"
                )
            fixed_header = 88
        # v0x20500 增加 runtime@88（1 字节）+ 3 字节保留。
        if version >= 0x20500:
            if length < 92:
                raise CodeSignatureError(
                    f"CodeDirectory version 0x{version:X} 头部不足 92 字节"
                )
            fixed_header = 92
        # v0x20600 增加 preEncryptOffset@92；非零代表另一套预加密槽方案。
        if version >= 0x20600:
            if length < 96:
                raise CodeSignatureError(
                    f"CodeDirectory version 0x{version:X} 头部不足 96 字节"
                )
            if _u32(blob, off + 92, "preEncryptOffset") != 0:
                raise CodeSignatureError(
                    "不支持的非零 preEncryptOffset 预加密槽方案"
                )
            fixed_header = 96
        if version > 0x20600:
            raise CodeSignatureError(
                f"不支持的 CodeDirectory 版本 0x{version:X}（最高支持 0x20600）"
            )
    else:
        fixed_header = 44

    if hash_type != SUPPORTED_HASHTYPE:
        raise CodeSignatureError(
            f"不支持的散列类型 {hash_type}（仅接受 SHA-256=2）"
        )
    if hash_size != SHA256_DIGEST_LEN:
        raise CodeSignatureError(
            f"SHA-256 CodeDirectory 的 hashSize 应为 32，实际 {hash_size}"
        )
    if n_code == 0:
        raise CodeSignatureError("不支持的代码槽数：nCodeSlots=0")
    if n_special == 0:
        # Apple 工具始终至少保留 codeDirectory 自身槽；为严格起见拒绝异常结构。
        raise CodeSignatureError("nSpecialSlots=0：缺少 CodeDirectory 自身槽")
    if page_exp < 1 or page_exp > 16:
        raise CodeSignatureError(f"不支持的页指数 pageSize={page_exp}")
    page_size = 1 << page_exp
    if code_limit == 0:
        raise CodeSignatureError("codeLimit=0：没有可执行字节被声明覆盖")
    # 代码槽数必须恰好覆盖 codeLimit：codesign 对 ceil(codeLimit/pageSize) 页
    # 逐页哈希（最后一页按 codeLimit 截断）。多槽、少槽都意味着覆盖不完整。
    expected_slots = (code_limit + page_size - 1) // page_size
    if n_code != expected_slots:
        raise CodeSignatureError(
            f"代码槽数 {n_code} 与 codeLimit/pageSize 期望的 {expected_slots} 页不符"
            f"（codeLimit={code_limit}, pageSize={page_size}）"
        )
    if ident_offset < fixed_header or ident_offset >= length:
        raise CodeSignatureError(
            f"identOffset {ident_offset} 越界（固定头部 {fixed_header}，"
            f"CD 长度 {length}）"
        )

    # 哈希槽布局（cs_blobs.h）：hashOffset 指向代码槽 0；nSpecialSlots 个
    # 特殊槽位于其负偏移处，即特殊槽区为
    # [hashOffset - nSpecial*hashSize, hashOffset)，代码槽区为
    # [hashOffset, hashOffset + nCode*hashSize)。
    special_bytes = n_special * hash_size
    code_bytes = n_code * hash_size
    slots_start = hash_offset - special_bytes
    slots_end = hash_offset + code_bytes
    if slots_start < fixed_header:
        raise CodeSignatureError(
            f"特殊槽区起点 {slots_start} 侵入 CodeDirectory 固定头部"
            f"（{fixed_header} 字节）"
        )
    if slots_end > length:
        raise CodeSignatureError(
            f"哈希槽越界：hashOffset={hash_offset} 槽数="
            f"{n_special}+{n_code} 需要至 {slots_end}，CD 长度 {length}"
        )
    # ident 名字以 NUL 结尾，且不得伸入哈希区。
    if ident_offset >= slots_start:
        raise CodeSignatureError(
            f"identOffset {ident_offset} 伸入哈希槽区（起点 {slots_start}）"
        )
    ident_end = blob.find(b"\x00", off + ident_offset, off + slots_start)
    if ident_end < 0:
        raise CodeSignatureError("CodeDirectory ident 字符串缺少 NUL 结尾")
    ident = blob[off + ident_offset : ident_end].decode("utf-8", "replace")

    code_hashes: List[bytes] = []
    for s in range(n_code):
        start = off + hash_offset + s * hash_size
        code_hashes.append(blob[start : start + hash_size])

    raw = blob[off : off + length]
    return CodeDirectory(
        cd_offset=off,
        cd_length=length,
        version=version,
        flags=flags,
        hash_offset=hash_offset,
        ident_offset=ident_offset,
        ident=ident,
        n_special_slots=n_special,
        n_code_slots=n_code,
        code_limit=code_limit,
        hash_type=hash_type,
        hash_size=hash_size,
        page_size=page_size,
        page_exp=page_exp,
        code_hashes=code_hashes,
        raw=raw,
    )


def verify_pages(blob: bytes, view: Optional[SuperBlobView] = None) -> VerificationResult:
    """按声明页长用原始字节复算全部代码槽，返回逐页证据。

    最后一页按 ``codeLimit`` 截断；其后若有签名等附加字节，不属于代码覆盖
    范围。任一槽不符即记录首个失败槽，verdict 为 mismatch，且仍返回完整
    证据供审阅——但调用方不得将其记为通过。
    """
    if view is None:
        view = parse_superblob(blob)
    cd = view.code_directory
    page_size = cd.page_size

    pages: List[PageEvidence] = []
    first_failed: Optional[int] = None
    covered = 0
    for slot in range(cd.n_code_slots):
        start = slot * page_size
        end = min(start + page_size, cd.code_limit)
        declared = cd.code_hashes[slot]
        is_hole = declared == CS_HOLE
        if start >= cd.code_limit:
            # 理论上不可达：解析阶段已强制 nCodeSlots==ceil(codeLimit/page)。
            # 保留为防御性检查，一旦出现即为失败，绝不放过。
            actual_hex = ""
            is_match = False
        else:
            chunk = blob[start:end]
            covered += len(chunk)
            actual_digest = hashlib.sha256(chunk).digest()
            actual_hex = actual_digest.hex()
            # 直接与声明槽逐字节比较：即使声明槽是 32 个零（CS_HOLE），
            # sha256(任意页) 也不可能等于全零，故代码槽里的空槽必然失败。
            # 这正是防线——查看器不能因“槽存在/签名存在”就放过未真正封页
            # 的位置（被替换页的常见伪装就是空槽）。
            is_match = actual_digest == declared
        if not is_match and first_failed is None:
            first_failed = slot
        pages.append(
            PageEvidence(
                slot=slot,
                offset=start,
                declared=declared.hex(),
                actual=actual_hex,
                match=is_match,
                is_hole=is_hole,
            )
        )

    verdict = "verified" if first_failed is None else "mismatch"
    return VerificationResult(
        verdict=verdict,
        page_size=page_size,
        code_limit=cd.code_limit,
        n_code_slots=cd.n_code_slots,
        covered_bytes=covered,
        code_directory_digest=cd.code_directory_digest,
        pages=pages,
        first_failed_slot=first_failed,
    )
