"""codesig 解析与逐页复算的单元测试。"""

from __future__ import annotations

import base64
import hashlib
import struct

import pytest

from app import codesig
from tests.fixtures import SB_MAGIC, CD_MAGIC, build_signed_payload, make_payload


def test_valid_payload_parses_and_verifies():
    payload = make_payload(n_pages=3)
    view = codesig.parse_superblob(payload)
    cd = view.code_directory
    assert cd.hash_type == 2
    assert cd.hash_size == 32
    assert cd.page_size == 4096
    result = codesig.verify_pages(payload, view)
    assert result.passed
    assert result.verdict == "verified"
    assert result.n_code_slots == 3
    assert result.first_failed_slot is None
    assert result.covered_bytes == cd.code_limit
    assert len(result.pages) == 3
    assert [p.slot for p in result.pages] == [0, 1, 2]
    assert all(p.match for p in result.pages)
    # 代码目录摘要 = sha256(CD 原始字节)
    assert result.code_directory_digest == hashlib.sha256(cd.raw).hexdigest()


def test_small_page_exp_and_partial_last_page():
    payload = make_payload(n_pages=2, page_exp=8)
    view = codesig.parse_superblob(payload)
    assert view.code_directory.page_size == 256
    result = codesig.verify_pages(payload, view)
    assert result.passed
    last = result.pages[-1]
    assert last.offset + len_remainder(payload, view) == view.code_directory.code_limit


def len_remainder(payload, view):
    cd = view.code_directory
    return cd.code_limit - (cd.n_code_slots - 1) * cd.page_size


def test_replaced_middle_page_points_to_first_failed_slot_only():
    payload = bytearray(make_payload(n_pages=4))
    # 替换第 2 页（slot 1）内的一个字节；该位置处于代码区。
    payload[4096 + 10] ^= 0xFF
    tampered = bytes(payload)
    view = codesig.parse_superblob(tampered)
    result = codesig.verify_pages(tampered, view)
    assert not result.passed
    assert result.verdict == "mismatch"
    assert result.first_failed_slot == 1
    assert result.pages[0].match
    assert not result.pages[1].match
    assert result.pages[2].match
    # 被替换页给出双方摘要，未替换页双方仍相等。
    assert result.pages[1].declared != result.pages[1].actual


def test_first_failure_is_lowest_slot_even_if_later_also_bad():
    payload = bytearray(make_payload(n_pages=3))
    payload[10] ^= 0x01            # slot 0
    payload[4096 + 5] ^= 0x01     # slot 1
    result = codesig.verify_pages(bytes(payload), codesig.parse_superblob(bytes(payload)))
    assert result.first_failed_slot == 0


def test_unsupported_hash_type_rejected():
    code = bytes(range(256)) * 20
    bad = build_signed_payload(code, page_exp=8, hash_type=1)  # SHA-1
    with pytest.raises(codesig.CodeSignatureError, match="散列类型"):
        codesig.parse_superblob(bad)


def test_bad_hash_size_rejected():
    code = bytes(range(256)) * 20
    bad = build_signed_payload(code, page_exp=8, hash_size=20)
    with pytest.raises(codesig.CodeSignatureError, match="hashSize"):
        codesig.parse_superblob(bad)


@pytest.mark.parametrize("page_exp", [0, 17, 255])
def test_unsupported_page_exp_rejected(page_exp):
    # 夹具仍按 1<<page_exp 之外的方式构造；直接用小 code 触发。
    code = b"\x00" * 64
    with pytest.raises(codesig.CodeSignatureError):
        codesig.parse_superblob(
            build_signed_payload(code, page_exp=page_exp)
        )


def test_slot_count_mismatch_rejected():
    code = bytes(10000)
    # 声称 99 个槽，但 codeLimit/pageSize 只需要 3 页。
    bad = build_signed_payload(code, page_exp=12, n_code_override=99)
    with pytest.raises(codesig.CodeSignatureError, match="槽数"):
        codesig.parse_superblob(bad)


def test_too_few_slots_rejected():
    code = bytes(10000)
    bad = build_signed_payload(code, page_exp=12, n_code_override=1)
    with pytest.raises(codesig.CodeSignatureError, match="槽数"):
        codesig.parse_superblob(bad)


def test_codelimit_overlapping_signature_rejected():
    code = bytes(1000)
    # codeLimit 超过 code 实际长度，会越过签名起点。
    bad = build_signed_payload(code, page_exp=12, code_limit=len(code) + 300)
    with pytest.raises(codesig.CodeSignatureError, match="重叠|越界|槽数|越界"):
        codesig.parse_superblob(bad)


def test_trailing_bytes_after_superblob_rejected():
    payload = make_payload() + b"\x00\x00"
    with pytest.raises(codesig.CodeSignatureError, match="未声明字节"):
        codesig.parse_superblob(payload)


def test_bad_superblob_magic():
    with pytest.raises(codesig.CodeSignatureError, match="找不到"):
        codesig.parse_superblob(b"\x00" * 200)


def test_length_field_tampered():
    payload = bytearray(make_payload())
    # SuperBlob 起点 = 非签名代码长度；魔数后 4 字节是 length。
    # 找到 SuperBlob 起始位置。
    sb_start = payload.find(SB_MAGIC.to_bytes(4, "big"))
    struct.pack_into(">I", payload, sb_start + 4, len(payload) - sb_start + 8)
    with pytest.raises(codesig.CodeSignatureError, match="越界"):
        codesig.parse_superblob(bytes(payload))


def test_index_offset_out_of_bounds_rejected():
    payload = bytearray(make_payload())
    sb_start = payload.find(SB_MAGIC.to_bytes(4, "big"))
    # 第一条（唯一一条）索引的 offset 字段在 sb_start+16。
    struct.pack_into(">I", payload, sb_start + 16, 0xFFFFFF)
    with pytest.raises(codesig.CodeSignatureError):
        codesig.parse_superblob(bytes(payload))


def test_code_directory_magic_corrupted_rejected():
    payload = bytearray(make_payload())
    sb_start = payload.find(SB_MAGIC.to_bytes(4, "big"))
    cd_off = sb_start + 20
    assert struct.unpack_from(">I", payload, cd_off)[0] == CD_MAGIC
    struct.pack_into(">I", payload, cd_off, 0xDEADBEEF)
    with pytest.raises(codesig.CodeSignatureError):
        codesig.parse_superblob(bytes(payload))


def test_empty_and_oversized_rejected():
    with pytest.raises(codesig.CodeSignatureError, match="空载荷"):
        codesig.parse_superblob(b"")
    with pytest.raises(codesig.CodeSignatureError, match="2 MiB"):
        codesig.parse_superblob(b"\x00" * (2 * 1024 * 1024 + 1))


def test_declared_evidence_exposes_digests_in_page_order():
    payload = make_payload(n_pages=3)
    view = codesig.parse_superblob(payload)
    result = codesig.verify_pages(payload, view)
    public = result.to_public_dict()
    assert [p["slot"] for p in public["pages"]] == [0, 1, 2]
    page0 = payload[:4096]
    assert public["pages"][0]["actual"] == hashlib.sha256(page0).hexdigest()
    assert public["pages"][0]["declared"] == view.code_directory.code_hashes[0].hex()


def test_hole_slot_in_code_area_is_failure_not_silently_covered():
    """代码槽出现 32 字节零（CS_HOLE）必须判该页失败：
    sha256(任意页) != 全零，未真正封页的位置不得被“签名存在”掩盖。"""
    page_size = 256
    code = bytes((i * 13 + 1) & 0xFF for i in range(page_size * 2 + 10))
    n_pages = 3
    declared = []
    for s in range(n_pages):
        chunk = code[s * page_size : min((s + 1) * page_size, len(code))]
        declared.append(b"\x00" * 32 if s == 1 else hashlib.sha256(chunk).digest())
    payload = build_signed_payload(
        code, page_exp=8, declared_hashes=declared
    )
    view = codesig.parse_superblob(payload)  # 结构本身可解析
    result = codesig.verify_pages(payload, view)
    assert result.verdict == "mismatch"
    assert result.first_failed_slot == 1
    assert result.pages[1].is_hole is True
    assert result.pages[1].match is False


@pytest.mark.parametrize("version", [0x20100, 0x20200, 0x20300, 0x20400, 0x20500, 0x20600])
def test_supported_codedirectory_versions(version):
    code = bytes((i * 5) & 0xFF for i in range(600))
    payload = build_signed_payload(code, page_exp=8, version=version)
    view = codesig.parse_superblob(payload)
    assert view.code_directory.version == version
    assert codesig.verify_pages(payload, view).passed


def test_unknown_codedirectory_version_rejected():
    code = bytes(600)
    payload = build_signed_payload(code, page_exp=8, version=0x20700)
    with pytest.raises(codesig.CodeSignatureError, match="版本"):
        codesig.parse_superblob(payload)


def test_codelimit64_inconsistent_rejected():
    # 手工构造 v0x20300 CD，再篡改 codeLimit64（@CD+56）。
    code = bytes(600)
    payload = bytearray(build_signed_payload(code, page_exp=8, version=0x20300))
    sb_start = payload.find(SB_MAGIC.to_bytes(4, "big"))
    cd_off = sb_start + 20
    struct.pack_into(">Q", payload, cd_off + 56, 999999)
    with pytest.raises(codesig.CodeSignatureError, match="codeLimit64"):
        codesig.parse_superblob(bytes(payload))


def test_nonzero_scatter_offset_rejected():
    code = bytes(600)
    payload = bytearray(build_signed_payload(code, page_exp=8, version=0x20100))
    sb_start = payload.find(SB_MAGIC.to_bytes(4, "big"))
    cd_off = sb_start + 20
    struct.pack_into(">I", payload, cd_off + 44, 128)
    with pytest.raises(codesig.CodeSignatureError, match="scatter"):
        codesig.parse_superblob(bytes(payload))


def test_multi_blob_superblob_with_requirements_and_cms_accepted():
    from tests.fixtures import build_multi_blob_payload, wrap_blob

    page_size = 256
    code = bytes((i * 3 + 2) & 0xFF for i in range(page_size * 2 + 15))
    payload = build_multi_blob_payload(
        code,
        page_exp=8,
        extra=[
            (2, wrap_blob(0xFADE0C01, b"\x00\x00\x00\x00")),  # Requirements
            (0x10000, wrap_blob(0xFADE0B01, b"\x30\x82\x01\x00cms")),  # CMS
        ],
    )
    view = codesig.parse_superblob(payload)
    result = codesig.verify_pages(payload, view)
    assert result.passed
    assert result.n_code_slots == 3


def test_multi_blob_with_unknown_sibling_magic_rejected():
    from tests.fixtures import build_multi_blob_payload, wrap_blob

    code = bytes(600)
    payload = build_multi_blob_payload(
        code, page_exp=8, extra=[(5, wrap_blob(0xDEAD0001, b"x"))]
    )
    with pytest.raises(codesig.CodeSignatureError, match="未知 blob"):
        codesig.parse_superblob(payload)
