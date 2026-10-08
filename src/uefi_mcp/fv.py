"""Firmware volume (FV) and FFS file parsing, pure Python.

An OVMF image is a stack of firmware volumes. Each FV holds FFS files
(drivers, PEIMs, applications, raw data) made of sections; a section can
itself be an LZMA-compressed blob holding another FV - that is how OVMF
packs its main DXE volume - so parsing recurses through those.
Layouts follow the PI specification (Volume 3): EFI_FIRMWARE_VOLUME_HEADER,
EFI_FFS_FILE_HEADER(2), EFI_COMMON_SECTION_HEADER(2).
"""

from __future__ import annotations

import lzma
import os
import struct
import uuid
from dataclasses import dataclass, field

from . import edk2

FV_SIGNATURE = b"_FVH"
LZMA_GUID = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"
FILE_TYPES = {
    0x01: "RAW", 0x02: "FREEFORM", 0x03: "SECURITY_CORE", 0x04: "PEI_CORE", 0x05: "DXE_CORE",
    0x06: "PEIM", 0x07: "DRIVER", 0x08: "COMBINED_PEIM_DRIVER", 0x09: "APPLICATION",
    0x0A: "MM", 0x0B: "FIRMWARE_VOLUME_IMAGE", 0x0C: "COMBINED_MM_DXE", 0x0D: "MM_CORE",
    0x0E: "MM_STANDALONE", 0x0F: "MM_CORE_STANDALONE", 0xF0: "PAD",
}
SECTION_TYPES = {
    0x01: "COMPRESSION", 0x02: "GUID_DEFINED", 0x03: "DISPOSABLE", 0x10: "PE32", 0x11: "PIC",
    0x12: "TE", 0x13: "DXE_DEPEX", 0x14: "VERSION", 0x15: "USER_INTERFACE",
    0x16: "COMPATIBILITY16", 0x17: "FIRMWARE_VOLUME_IMAGE", 0x18: "FREEFORM_SUBTYPE_GUID",
    0x19: "RAW", 0x1B: "PEI_DEPEX", 0x1C: "MM_DEPEX",
}


class FvError(ValueError):
    pass


def _guid(b: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(b))).upper()


@dataclass
class FfsFile:
    guid: str
    type: str
    size: int
    offset: int
    ui_name: str | None = None
    sections: list[str] = field(default_factory=list)
    volumes: list[Volume] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        if self.ui_name:
            return self.ui_name
        # A file GUID is a module's FILE_GUID, so prefer the module name from
        # its .inf over a .dec alias (Shell, not gUefiShellFileGuid).
        info = edk2.lookup_guid(self.guid)
        if info.module:
            return f"{info.module['name']} (by GUID)"
        if info.names:
            return f"{info.names[0][0]} (by GUID)"
        return "-"


@dataclass
class Volume:
    offset: int
    length: int
    fs_guid: str
    name_guid: str | None
    files: list[FfsFile] = field(default_factory=list)
    depth: int = 0


def find_volumes(data: bytes, depth: int = 0, base: int = 0) -> list[Volume]:
    """Top-level FVs, walked by FvLength from each header (not by a blind
    signature scan, which also hits '_FVH' bytes inside compressed data)."""
    vols: list[Volume] = []
    off = 0
    while off + 56 <= len(data):
        if data[off + 40:off + 44] == FV_SIGNATURE:
            vol = parse_volume(data, off, depth, base)
            vols.append(vol)
            off += max(vol.length, 0x1000)
            continue
        off += 0x1000 if depth == 0 else 8
    return vols


def parse_volume(data: bytes, off: int, depth: int = 0, base: int = 0) -> Volume:
    fv_len, = struct.unpack_from("<Q", data, off + 32)
    hdr_len, _checksum, ext_off = struct.unpack_from("<HHH", data, off + 48)
    if fv_len < hdr_len or off + fv_len > len(data):
        raise FvError(f"FV at {base + off:#x} has an impossible length {fv_len:#x}")
    vol = Volume(base + off, fv_len, _guid(data[off + 16:off + 32]), None, depth=depth)
    start = off + hdr_len
    if ext_off:
        vol.name_guid = _guid(data[off + ext_off:off + ext_off + 16])
        ext_size, = struct.unpack_from("<I", data, off + ext_off + 16)
        start = off + ext_off + ext_size
    pos = (start + 7) & ~7
    end = off + fv_len
    while pos + 24 <= end:
        name = data[pos:pos + 16]
        if data[pos:pos + 24] == b"\xff" * 24:
            break  # erased flash: no more files (PAD files also have an all-FF *name*)
        ftype, attrs = data[pos + 18], data[pos + 19]
        size = int.from_bytes(data[pos + 20:pos + 23], "little")
        hlen = 24
        if attrs & 0x01:  # FFS_ATTRIB_LARGE_FILE
            size, = struct.unpack_from("<Q", data, pos + 24)
            hlen = 32
        if size < hlen or pos + size > end:
            raise FvError(f"FFS file at {base + pos:#x} has an impossible size {size:#x}")
        f = FfsFile(_guid(name), FILE_TYPES.get(ftype, f"type {ftype:#04x}"), size, base + pos)
        if ftype != 0xF0 and ftype != 0x01:  # PAD and RAW files have no sections
            _parse_sections(data, pos + hlen, pos + size, f, depth, base)
        vol.files.append(f)
        pos = (pos + size + 7) & ~7
    return vol


def _parse_sections(data: bytes, pos: int, end: int, f: FfsFile, depth: int, base: int) -> None:
    while pos + 4 <= end:
        size = int.from_bytes(data[pos:pos + 3], "little")
        stype = data[pos + 3]
        hlen = 4
        if size == 0xFFFFFF:
            size, = struct.unpack_from("<I", data, pos + 4)
            hlen = 8
        if size < hlen or pos + size > end:
            break
        body = data[pos + hlen:pos + size]
        sname = SECTION_TYPES.get(stype, f"type {stype:#04x}")
        if stype == 0x15:
            f.ui_name = body.decode("utf-16-le", "replace").rstrip("\0")
        elif stype == 0x02 and len(body) >= 20:
            sguid = _guid(body[:16])
            data_off, = struct.unpack_from("<H", body, 16)
            payload = data[pos + data_off:pos + size]
            if sguid == LZMA_GUID:
                sname = "GUID_DEFINED(LZMA)"
                try:
                    inner = lzma.decompress(payload, format=lzma.FORMAT_ALONE)
                except lzma.LZMAError as e:
                    f.notes.append(f"LZMA section failed to decompress: {e}")
                else:
                    sub = FfsFile(f.guid, f.type, len(inner), f.offset)
                    _parse_sections(inner, 0, len(inner), sub, depth, 0)
                    f.sections.extend(f"{sname}/{s}" for s in sub.sections)
                    f.volumes.extend(sub.volumes)
                    f.ui_name = f.ui_name or sub.ui_name
                    pos = (pos + size + 3) & ~3
                    continue
            else:
                known = edk2.name_for_guid(sguid) or sguid
                sname = f"GUID_DEFINED({known})"
                f.notes.append(f"section encoded with {known}: not decoded")
        elif stype == 0x01:
            f.notes.append("EFI/Tiano-compressed section: not decoded")
        elif stype == 0x17:
            for v in find_volumes(body, depth + 1, 0):
                f.volumes.append(v)
        f.sections.append(sname)
        pos = (pos + size + 3) & ~3


def load(path: str) -> list[Volume]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"no such file: {path}")
    with open(path, "rb") as fh:
        data = fh.read()
    vols = find_volumes(data)
    if not vols:
        raise FvError(f"no firmware volume ('_FVH' header) found in {os.path.basename(path)}. "
                      "For OVMF use the CODE image (e.g. OVMF_CODE.fd / edk2-x86_64-code.fd).")
    return vols


def walk(vols: list[Volume]) -> list[tuple[Volume, FfsFile]]:
    out: list[tuple[Volume, FfsFile]] = []
    for v in vols:
        for f in v.files:
            out.append((v, f))
            out.extend(walk(f.volumes))
    return out


def describe(vols: list[Volume], query: str | None = None, limit: int = 200) -> str:
    lines: list[str] = []
    q = query.lower() if query else None
    shown = 0
    total = 0

    def render(vs: list[Volume], indent: str) -> None:
        nonlocal shown, total
        for v in vs:
            fs = edk2.name_for_guid(v.fs_guid) or v.fs_guid
            where = (f"at {v.offset:#x}" if v.depth == 0 and not indent
                     else "nested (decompressed from the file above)")
            lines.append(f"{indent}FV {v.name_guid or '(no name)'} {where}, "
                         f"{v.length:#x} bytes, {len(v.files)} files, file system {fs}")
            for f in v.files:
                total += 1
                match = q is None or q in f.name.lower() or q in f.guid.lower() or q in f.type.lower()
                if match and shown < limit and f.type != "PAD":
                    shown += 1
                    extra = f"  [{', '.join(f.sections)}]" if f.sections else ""
                    lines.append(f"{indent}  {f.guid}  {f.type:<22} {f.size:>8}  {f.name}{extra}")
                    for n in f.notes:
                        lines.append(f"{indent}      note: {n}")
                render(f.volumes, indent + "    ")

    render(vols, "")
    if q is not None and shown == 0:
        lines.append(f"No file matched {query!r}.")
    if shown >= limit:
        lines.append(f"[stopped after {limit} files - pass a query or a larger limit]")
    return "\n".join(lines)
