"""EFI_STATUS decoding and GUID/module lookup over data generated from EDK2.

The tables come from tools/gen_data.py (EDK2 at a pinned tag, BSD-2-Clause-
Patent - see data/EDK2-LICENSE.txt). The one-line hints below are this
project's own words about what usually causes each status in practice.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

GUID_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")

HINTS: dict[str, str] = {
    "EFI_LOAD_ERROR": "the image couldn't be loaded: bad PE/COFF header, wrong machine type, "
                      "or a format the firmware doesn't accept",
    "EFI_INVALID_PARAMETER": "a NULL or out-of-range argument - check every pointer you pass "
                             "(often a missing &, or the wrong handle)",
    "EFI_UNSUPPORTED": "the operation or image isn't supported here. During driver dispatch "
                       "this is normal: a driver declining hardware it doesn't own",
    "EFI_BUFFER_TOO_SMALL": "call again with a bigger buffer - the needed size was written back "
                            "into the size argument (GetMemoryMap, GetVariable, ...)",
    "EFI_NOT_READY": "nothing available yet (e.g. ReadKeyStroke with no key pressed) - poll or "
                     "wait on the event",
    "EFI_DEVICE_ERROR": "the hardware reported an error",
    "EFI_OUT_OF_RESOURCES": "allocation failed: not enough memory or handles",
    "EFI_NOT_FOUND": "the requested item doesn't exist: no handle with that protocol, file not "
                     "on the volume, variable not set",
    "EFI_ACCESS_DENIED": "access refused - write-protected media, a variable's attributes, or "
                         "Secure Boot policy",
    "EFI_TIMEOUT": "the operation timed out",
    "EFI_ALREADY_STARTED": "the protocol/driver is already installed or running on this handle",
    "EFI_ABORTED": "the operation was aborted. During driver dispatch this is often a driver "
                   "choosing to stop (e.g. an emulation fallback that isn't needed)",
    "EFI_SECURITY_VIOLATION": "Secure Boot (or a platform security policy) rejected the image: "
                              "it isn't signed by a trusted key",
    "EFI_INVALID_LANGUAGE": "the language code isn't supported",
    "EFI_VOLUME_CORRUPTED": "the file system structures on the volume are inconsistent",
    "EFI_NO_MEDIA": "no media in the device",
    "EFI_WRITE_PROTECTED": "the device or file is read-only",
    "EFI_END_OF_FILE": "read past the end of a file",
}


@cache
def data() -> dict[str, Any]:
    with resources.files("uefi_mcp").joinpath("data/edk2.json").open(encoding="utf-8") as fh:
        loaded: dict[str, Any] = json.load(fh)
    return loaded


def source_note() -> str:
    src = data()["source"]
    return f"EDK2 {src['tag']} ({src['commit'][:12]})"


@dataclass(frozen=True)
class Status:
    value: int  # as a 64-bit EFI_STATUS
    name: str | None
    text: str | None  # what OVMF's %r prints
    error: bool
    oem: bool
    code: int

    def describe(self) -> str:
        width = "64-bit"
        lines = [f"{self.name or 'unknown status'} = {self.value:#018x} ({width}), "
                 f"{(self.value & 0xFFFFFFFF) | (0x80000000 if self.error else 0):#010x} (32-bit)"]
        kind = "error" if self.error else ("success" if self.code == 0 else "warning")
        if self.oem:
            kind = "OEM-defined " + kind
        lines.append(f"kind: {kind} (high bit {'set' if self.error else 'clear'}), code {self.code}")
        if self.text:
            lines.append(f"OVMF/EDK2 logs print it as: {self.text!r}")
        if self.name and self.name in HINTS:
            lines.append(f"usually: {HINTS[self.name]}")
        if self.error:
            lines.append("EFI_ERROR(status) is true for this value.")
        return "\n".join(lines)


def _tables() -> tuple[dict[tuple[bool, int], str], dict[str, tuple[bool, int]]]:
    by_code: dict[tuple[bool, int], str] = {(False, 0): "EFI_SUCCESS"}
    for s in data()["status"]:
        by_code.setdefault((bool(s["error"]), int(s["code"])), str(s["name"]))
    return by_code, {v: k for k, v in by_code.items()}


def decode_status(query: str) -> Status:
    """Accepts 0x8000000000000003, 0x80000003, 3 (with error=…?), EFI_UNSUPPORTED,
    UNSUPPORTED, or the text OVMF logs print ('Unsupported', 'Not Found')."""
    by_code, by_name = _tables()
    strings = data()["status_strings"]
    q = query.strip()
    err: bool
    code: int
    oem = False
    if re.fullmatch(r"(0x)?[0-9A-Fa-f]+", q) and (q.lower().startswith("0x") or len(q) >= 8):
        v = int(q, 16)
        if v >> 32:
            err, oem, code = bool(v >> 63), bool((v >> 62) & 1), v & ((1 << 62) - 1)
        else:
            err, oem, code = bool(v >> 31), bool((v >> 30) & 1), v & 0x3FFFFFFF
    elif q.isdigit():
        err, code = False, int(q)
        if code != 0:
            raise ValueError(
                f"{q!r} is ambiguous: code {q} is both a warning and (with the high bit) an "
                f"error. Pass {by_code.get((True, code), 'the error')} or "
                f"0x{(1 << 63) | code:016x} for the error, or the name for the warning")
    else:
        wanted = q.upper().replace(" ", "_")
        if not wanted.startswith("EFI_"):
            wanted = "EFI_" + wanted
        hit = by_name.get(wanted)
        if hit is None:
            # The human text OVMF prints via %r.
            for i, label in enumerate(strings["warning"]):
                if label.lower() == q.lower():
                    hit = (False, i)
            for i, label in enumerate(strings["error"]):
                if label.lower() == q.lower():
                    hit = (True, i + 1)
        if hit is None:
            close = sorted(n for n in by_name if q.upper().replace(" ", "_") in n)[:8]
            raise KeyError(f"unknown EFI_STATUS {query!r}"
                           + (f"; similar: {', '.join(close)}" if close else ""))
        err, code = hit
    name = None if oem else by_code.get((err, code))
    if err:
        text = strings["error"][code - 1] if 1 <= code <= len(strings["error"]) and not oem else None
    else:
        text = strings["warning"][code] if 0 <= code < len(strings["warning"]) and not oem else None
    value = ((1 << 63) if err else 0) | ((1 << 62) if oem else 0) | code
    return Status(value, name, text, err, oem, code)


def status_from_log_text(text: str) -> Status | None:
    """Map a %r-printed status from a log ('Unsupported', '00000001') to a Status."""
    t = text.strip()
    try:
        if re.fullmatch(r"[0-9A-Fa-f]{8}|[0-9A-Fa-f]{16}", t):
            return decode_status("0x" + t)
        return decode_status(t)
    except (KeyError, ValueError):
        return None


@dataclass(frozen=True)
class GuidInfo:
    guid: str
    names: list[tuple[str, str, str]]  # (name, kind, package)
    module: dict[str, str] | None


def _guid_index() -> dict[str, list[tuple[str, str, str]]]:
    idx: dict[str, list[tuple[str, str, str]]] = {}
    for name, g in data()["guids"].items():
        idx.setdefault(g["guid"], []).append((name, g["kind"], g["package"]))
    return idx


_INDEX: dict[str, list[tuple[str, str, str]]] | None = None


def lookup_guid(guid: str) -> GuidInfo:
    global _INDEX
    if _INDEX is None:
        _INDEX = _guid_index()
    g = guid.strip().strip("{}").upper()
    if not GUID_RE.fullmatch(g):
        raise ValueError(f"{guid!r} is not a GUID (expected XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)")
    return GuidInfo(g, _INDEX.get(g, []), data()["modules"].get(g))


def name_for_guid(guid: str) -> str | None:
    info = lookup_guid(guid)
    if info.names:
        return info.names[0][0]
    if info.module:
        return info.module["name"]
    return None


def search_names(query: str, limit: int = 20) -> list[tuple[str, dict[str, str]]]:
    q = query.lower()
    hits = [(n, g) for n, g in data()["guids"].items() if q in n.lower()]
    hits.sort(key=lambda h: (not h[0].lower().startswith("g" + q) and not h[0].lower() == q,
                             len(h[0])))
    return hits[:limit]


def search_modules(query: str, limit: int = 20) -> list[tuple[str, dict[str, str]]]:
    q = query.lower()
    hits = [(g, m) for g, m in data()["modules"].items() if q in m["name"].lower()]
    hits.sort(key=lambda h: (h[1]["name"].lower() != q, len(h[1]["name"])))
    return hits[:limit]
