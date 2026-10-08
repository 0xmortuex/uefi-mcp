"""Generate src/uefi_mcp/data/edk2.json from EDK2 source at a pinned commit.

Everything uefi-mcp knows about GUIDs, module names and EFI_STATUS values
comes from this script's output, not from hand-typed tables:

  *.dec  [Guids] / [Protocols] / [Ppis]   -> named GUIDs (gEfi...Guid)
  *.inf  [Defines] FILE_GUID, BASE_NAME   -> module GUID -> driver name
  MdePkg/Include/Base.h  RETURN_* defines -> EFI_STATUS values
  BasePrintLib's mWarningString/mErrorString -> the text %r prints in logs

EDK2 is BSD-2-Clause-Patent; its License.txt is copied next to the data.

Usage: python tools/gen_data.py
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import urllib.request

TAG = "edk2-stable202408"
COMMIT = "b158dad150bf02879668f72ce306445250838201"
URL = f"https://codeload.github.com/tianocore/edk2/tar.gz/{COMMIT}"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "..", "src", "uefi_mcp", "data")

GUID_RE = re.compile(
    r"^\s*(g\w+)\s*=\s*\{\s*0x([0-9a-fA-F]+)\s*,\s*0x([0-9a-fA-F]+)\s*,\s*0x([0-9a-fA-F]+)\s*,"
    r"\s*\{\s*((?:0x[0-9a-fA-F]+\s*,?\s*){8})\}\s*\}"
)
RETURN_RE = re.compile(r"#define\s+RETURN_(\w+)\s+ENCODE_(ERROR|WARNING)\s*\(\s*(\d+)\s*\)")


def guid_str(d1: str, d2: str, d3: str, rest: str) -> str:
    b = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", rest)]
    return (f"{int(d1, 16):08X}-{int(d2, 16):04X}-{int(d3, 16):04X}-"
            f"{b[0]:02X}{b[1]:02X}-" + "".join(f"{x:02X}" for x in b[2:]))


def parse_dec(text: str, package: str, guids: dict[str, dict[str, str]]) -> None:
    section = ""
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if s.startswith("["):
            section = s.strip("[]").split(".")[0].split(",")[0].strip().lower()
            continue
        if section not in ("guids", "protocols", "ppis"):
            continue
        m = GUID_RE.match(s)
        if m:
            kind = {"guids": "guid", "protocols": "protocol", "ppis": "ppi"}[section]
            guids.setdefault(m.group(1), {
                "guid": guid_str(*m.group(2, 3, 4, 5)), "kind": kind, "package": package,
            })


def parse_inf(text: str, path: str) -> dict[str, str] | None:
    defines: dict[str, str] = {}
    in_defines = False
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if s.startswith("["):
            in_defines = s.lower().startswith("[defines")
            continue
        if in_defines and "=" in s:
            k, v = (x.strip() for x in s.split("=", 1))
            defines[k.upper()] = v
    if "FILE_GUID" not in defines or "BASE_NAME" not in defines:
        return None
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", defines["FILE_GUID"]):
        return None  # macro-valued GUIDs can't be resolved statically
    return {"name": defines["BASE_NAME"], "type": defines.get("MODULE_TYPE", ""), "inf": path}


def parse_status_strings(text: str) -> dict[str, list[str]]:
    """The strings %r prints: mWarningString[] (index = warning code, 0 =
    Success) and mErrorString[] (index + 1 = error code)."""
    out: dict[str, list[str]] = {}
    for key, array in (("warning", "mWarningString"), ("error", "mErrorString")):
        body = text[text.index(array):]
        body = body[body.index("{") + 1:body.index("};")]
        out[key] = re.findall(r'^\s*"([^"]*)"', body, re.M)
    return out


def main() -> None:
    print(f"downloading EDK2 {TAG} ({COMMIT[:12]}) ...")
    data = urllib.request.urlopen(URL, timeout=300).read()
    guids: dict[str, dict[str, str]] = {}
    modules: dict[str, dict[str, str]] = {}
    status: list[dict[str, object]] = []
    status_strings: dict[str, list[str]] = {}
    license_text = ""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            rel = member.name.split("/", 1)[1]
            if not rel.endswith((".dec", ".inf")) and rel not in (
                "MdePkg/Include/Base.h", "MdePkg/Library/BasePrintLib/PrintLibInternal.c", "License.txt"
            ):
                continue
            fh = tar.extractfile(member)
            assert fh is not None
            text = fh.read().decode("utf-8", "replace")
            if rel.endswith(".dec"):
                parse_dec(text, rel.split("/")[0], guids)
            elif rel.endswith(".inf"):
                mod = parse_inf(text, rel)
                if mod is not None:
                    m = re.search(r"FILE_GUID\s*=\s*([0-9a-fA-F-]{36})", text)
                    assert m is not None
                    modules.setdefault(m.group(1).upper(), mod)
            elif rel == "MdePkg/Include/Base.h":
                for name, kind, num in RETURN_RE.findall(text):
                    status.append({"name": "EFI_" + name, "code": int(num),
                                   "error": kind == "ERROR"})
            elif rel.endswith("PrintLibInternal.c"):
                status_strings = parse_status_strings(text)
            else:
                license_text = text
    if not (guids and modules and status and status_strings and license_text):
        raise SystemExit("EDK2 layout changed: some inputs were not found")
    os.makedirs(OUT_DIR, exist_ok=True)
    out = {
        "source": {"project": "tianocore/edk2", "tag": TAG, "commit": COMMIT,
                   "license": "BSD-2-Clause-Patent (see EDK2-LICENSE.txt)"},
        "guids": dict(sorted(guids.items())),
        "modules": dict(sorted(modules.items())),
        "status": status,
        "status_strings": status_strings,
    }
    with open(os.path.join(OUT_DIR, "edk2.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=0, sort_keys=False)
        fh.write("\n")
    with open(os.path.join(OUT_DIR, "EDK2-LICENSE.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(license_text)
    print(f"{len(guids)} GUIDs, {len(modules)} modules, {len(status)} status codes, "
          f"{len(status_strings['warning'])}+{len(status_strings['error'])} status strings")


if __name__ == "__main__":
    main()
