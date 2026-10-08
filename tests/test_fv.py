"""Firmware volume parsing: a synthetic FV built here byte by byte (so the
layout under test is explicit), plus the real OVMF image when available."""

import lzma
import struct
import uuid

import pytest

from uefi_mcp import fv
from uefi_mcp.boot import BootError, find_ovmf, find_qemu

FFS2 = uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3")  # gEfiFirmwareFileSystem2Guid


def section(stype: int, body: bytes) -> bytes:
    size = 4 + len(body)
    raw = size.to_bytes(3, "little") + bytes([stype]) + body
    return raw + b"\0" * (-len(raw) % 4)


def ffs(name: uuid.UUID, ftype: int, body: bytes) -> bytes:
    size = 24 + len(body)
    hdr = name.bytes_le + b"\0\0" + bytes([ftype, 0]) + size.to_bytes(3, "little") + b"\xf8"
    raw = hdr + body
    return raw + b"\xff" * (-len(raw) % 8)


def volume(files: bytes, length: int = 0x1000) -> bytes:
    hdr = bytearray(56 + 16)
    hdr[16:32] = FFS2.bytes_le
    struct.pack_into("<Q", hdr, 32, length)
    hdr[40:44] = b"_FVH"
    struct.pack_into("<HHH", hdr, 48, len(hdr), 0, 0)
    body = bytes(hdr) + files
    return body + b"\xff" * (length - len(body))


def ui(name: str) -> bytes:
    return section(0x15, (name + "\0").encode("utf-16-le"))


DRIVER = uuid.UUID("11111111-2222-3333-4444-555555555555")
APP = uuid.UUID("7C04A583-9E3E-4F1C-AD65-E05268D0B4D1")  # the EFI Shell's FILE_GUID


def test_files_ui_names_pad_and_end_of_files():
    pad = ffs(uuid.UUID(bytes=b"\xff" * 16), 0xF0, b"\0" * 16)  # PAD: all-FF *name*
    files = (ffs(DRIVER, 0x07, section(0x10, b"MZ...") + ui("MyDxe"))
             + pad
             + ffs(APP, 0x09, section(0x10, b"MZ...")))
    (v,) = fv.find_volumes(volume(files))
    names = [(f.type, f.name) for f in v.files]
    assert names[0] == ("DRIVER", "MyDxe")
    assert names[1][0] == "PAD"  # walking continued past the PAD file
    assert names[2] == ("APPLICATION", "Shell (by GUID)")  # no UI section: EDK2 name


def test_lzma_compressed_nested_volume():
    inner = volume(ffs(DRIVER, 0x07, ui("Nested")), length=0x400)
    payload = lzma.compress(section(0x17, inner), format=lzma.FORMAT_ALONE)
    guid_hdr = uuid.UUID(fv.LZMA_GUID).bytes_le + struct.pack("<HH", 4 + 20, 1)
    outer = volume(ffs(uuid.uuid4(), 0x0B, section(0x02, guid_hdr + payload)), length=0x2000)
    vols = fv.find_volumes(outer)
    all_files = [f for _, f in fv.walk(vols)]
    assert any(f.name == "Nested" for f in all_files)
    text = fv.describe(vols, query="nested")
    assert "nested (decompressed from the file above)" in text and "Nested" in text


def test_impossible_sizes_are_reported():
    bad = bytearray(volume(ffs(DRIVER, 0x07, ui("X"))))
    bad[0x48 + 20:0x48 + 23] = (0xFFFFF0).to_bytes(3, "little")  # first file's size
    with pytest.raises(fv.FvError, match="impossible size"):
        fv.find_volumes(bytes(bad))


def test_not_a_firmware_image(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\0" * 0x2000)
    with pytest.raises(fv.FvError, match="no firmware volume"):
        fv.load(str(p))


def _real_ovmf():
    try:
        code, _ = find_ovmf(find_qemu())
    except BootError:
        pytest.skip("QEMU/OVMF not installed")
    return code


def test_real_ovmf_image_has_core_drivers():
    vols = fv.load(_real_ovmf())
    names = {f.name for _, f in fv.walk(vols)}
    assert {"DxeCore", "BdsDxe", "PcdPeim"} <= names
    assert any(f.type == "PEIM" for _, f in fv.walk(vols))
