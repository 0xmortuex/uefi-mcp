"""uefi-mcp: an MCP server for UEFI/EDK2/OVMF work."""

from __future__ import annotations

import functools
import os
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import boot as bootmod
from . import edk2
from . import fv as fvmod
from . import ovmf_log
from . import pe_image

mcp = MCPServer(
    "uefi",
    instructions=(
        "Tools for UEFI development and firmware debugging with EDK2/OVMF. "
        "uefi_boot runs an .efi under OVMF in QEMU and explains what happened (load failure, "
        "return status, CPU exception with the faulting instruction). uefi_log explains an "
        "existing OVMF debug log (+ serial console). uefi_image checks a PE/COFF EFI binary "
        "for problems that stop firmware loading it, and disassembles at an RVA. "
        "uefi_status decodes EFI_STATUS values (hex, names, or the text logs print). "
        "uefi_guid names protocol/table/module GUIDs. uefi_volume lists the drivers and "
        "files inside a firmware image (OVMF_CODE.fd)."
    ),
)

F = TypeVar("F", bound=Callable[..., Any])

# Failures an agent can act on. MCPServer only forwards a ToolError's message
# to the client - anything else arrives as a bare "Error executing tool X" -
# so these are re-raised as ToolError with their text intact.
_EXPECTED = (KeyError, ValueError, FileNotFoundError, bootmod.BootError, OSError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _EXPECTED as e:
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            raise ToolError(str(msg)) from e

    mcp.tool()(wrapper)
    return fn


@tool
def uefi_status(code: str) -> str:
    """Decode an EFI_STATUS.

    code may be a 64-bit value (0x8000000000000003), a 32-bit one
    (0x80000003), a name (EFI_UNSUPPORTED / UNSUPPORTED), or the text OVMF
    logs print via %r ("Unsupported", "Not Found"). Returns the name, both
    widths, whether EFI_ERROR() is true, and what usually causes it.
    """
    return edk2.decode_status(code).describe() + f"\n(source: {edk2.source_note()})"


@tool
def uefi_guid(query: str, limit: int = 20) -> str:
    """Name a GUID, or find GUIDs by name.

    A GUID (e.g. 5B1B31A1-9562-11D2-8E3F-00A0C969723B) returns its EDK2
    name(s) - protocol, table, variable, PPI - and, for module FILE_GUIDs
    seen in OVMF logs ("Loading driver <GUID>"), the driver it belongs to.
    Any other text searches GUID names and module names (substring).
    """
    if edk2.GUID_RE.fullmatch(query.strip().strip("{}")):
        info = edk2.lookup_guid(query)
        lines = [info.guid]
        for name, kind, pkg in info.names:
            lines.append(f"  {name}  ({kind}, {pkg})")
        if info.module:
            m = info.module
            lines.append(f"  module {m['name']}  ({m['type']}, {m['inf']})")
        if len(lines) == 1:
            lines.append("  not a GUID defined in EDK2's .dec/.inf files - it may be "
                         "vendor-specific or generated for this build")
        return "\n".join(lines) + f"\n(source: {edk2.source_note()})"
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    names = edk2.search_names(query, limit)
    modules = edk2.search_modules(query, limit)
    if not names and not modules:
        raise KeyError(f"nothing in EDK2 matches {query!r} - try a shorter fragment "
                       "(e.g. 'LoadedImage', 'GraphicsOutput', 'Acpi20Table')")
    out = []
    for name, g in names:
        out.append(f"{g['guid']}  {name}  ({g['kind']}, {g['package']})")
    for guid, m in modules:
        out.append(f"{guid}  module {m['name']}  ({m['type']}, {m['inf']})")
    return "\n".join(out)


@tool
def uefi_log(log_path: str, serial_path: str | None = None) -> str:
    """Explain an OVMF/EDK2 boot from its debug log, plus the serial console.

    log_path is OVMF's debug output: QEMU `-debugcon file:ovmf.log -global
    isa-debugcon.iobase=0x402` (debug builds of OVMF write there). Pass the
    serial console capture too (`-serial file:serial.log`): boot-load
    failures and CPU exception dumps only appear there. Reports the phases,
    drivers that didn't start (with which of those are normal), every boot
    attempt with the images it loaded and their base addresses, return
    statuses, load failures with likely causes, exceptions mapped to
    image + RVA, and ASSERTs.
    """
    if not os.path.isfile(log_path):
        raise FileNotFoundError(f"log not found: {log_path}")
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        debug = fh.read()
    serial = ""
    if serial_path is not None:
        if not os.path.isfile(serial_path):
            raise FileNotFoundError(f"serial log not found: {serial_path}")
        with open(serial_path, encoding="utf-8", errors="replace") as fh:
            serial = fh.read()
    return ovmf_log.explain(ovmf_log.parse(debug, serial))


@tool
def uefi_image(path: str, rva: str | None = None, count: int = 8) -> str:
    """Inspect a PE/COFF EFI binary (.efi) for problems that stop it loading.

    Reports machine, subsystem (must be EFI application/driver), entry point,
    sections, base relocations, and concrete problems: wrong subsystem,
    relocations stripped, section alignment below 4K, no entry point, plus
    the removable-media boot file name it needs (\\EFI\\BOOT\\BOOTX64.EFI).
    With rva (e.g. "0x1012" - a crash's IP minus its ImageBase, as uefi_log
    reports), disassembles `count` instructions there with the faulting one
    marked.
    """
    if rva is None:
        return pe_image.analyze(path)
    if not 1 <= count <= 100:
        raise ValueError("count must be between 1 and 100")
    return pe_image.disassemble(path, int(rva, 0), count=count, before=4)


@tool
def uefi_volume(path: str, query: str | None = None, limit: int = 200) -> str:
    """List firmware volumes and the files inside a firmware image.

    path is a flash image such as OVMF_CODE.fd / edk2-x86_64-code.fd. Walks
    every firmware volume, decompresses LZMA-packed volumes (OVMF's main DXE
    volume), and lists each FFS file: GUID, type (PEIM, DRIVER,
    APPLICATION...), size, name and sections. query filters by name, GUID
    or type (e.g. "Shell", "PEIM", "6D33944A").
    """
    if not 1 <= limit <= 2000:
        raise ValueError("limit must be between 1 and 2000")
    return fvmod.describe(fvmod.load(path), query, limit)


@tool
def uefi_boot(app: str, timeout_s: float = 30.0) -> str:
    """Boot an EFI application under OVMF in QEMU and explain what happened.

    The app is placed at \\EFI\\BOOT\\BOOTX64.EFI on a virtual disk so OVMF's
    default boot option runs it. The run stops when the app returns, fails
    to load, hits a CPU exception or an ASSERT, or after timeout_s. Returns
    what the app printed, the explanation from uefi_log, and - for a crash
    inside the app - the faulting instruction. Logs are kept (paths in the
    output). Needs qemu-system-x86_64 and OVMF (set UEFI_MCP_OVMF_CODE /
    UEFI_MCP_OVMF_VARS if they aren't found).
    """
    result = bootmod.boot(app, timeout_s)
    serial_path = os.path.join(result.workdir, "serial.log")
    with open(result.log_path, encoding="utf-8", errors="replace") as fh:
        debug = fh.read()
    with open(serial_path, encoding="utf-8", errors="replace") as fh:
        serial = fh.read()
    parsed = ovmf_log.parse(debug, serial)
    out = [f"Booted {os.path.basename(app)} under OVMF ({os.path.basename(result.firmware)}) "
           f"in {result.seconds}s - stopped by: {result.stopped_by}"]
    printed = _app_output(result.serial)
    out.append("")
    if printed is None:
        out.append("The app never started (see the boot attempts below).")
    elif printed:
        out.append("What the app printed:")
        out.extend(f"  {ln}" for ln in printed)
    else:
        out.append("The app started but printed nothing.")
    out.append("")
    out.append(ovmf_log.explain(parsed))
    first = parsed.attempts[0] if parsed.attempts else None
    if first is not None and first.failed_load is not None:
        # The status OVMF prints for a rejected image differs between EDK2
        # versions (a stripped-relocation image is "Invalid Parameter" in
        # QEMU's bundled OVMF and "Not Found" in Ubuntu's), so check the file
        # itself rather than trusting the status alone.
        report = pe_image.analyze(app)
        if "PROBLEMS:" in report:
            out.append("")
            out.append("What's wrong with the image (uefi_image):")
            out.append(report[report.index("PROBLEMS:"):])
    # Debug builds of OVMF name the image after the .efi; release builds use
    # the PDB path from the debug directory (crash.pdb), so compare stems.
    app_stem = os.path.splitext(os.path.basename(app).lower())[0]
    for exc in parsed.exceptions:
        ip = exc.registers.get("RIP", exc.registers.get("EIP"))
        loaded = os.path.splitext(os.path.basename((exc.image or "").lower()))[0]
        if ip is not None and exc.image_base is not None and loaded in (app_stem, "bootx64"):
            out.append("")
            out.append("Faulting instruction:")
            out.append(pe_image.disassemble(app, ip - exc.image_base, count=3, before=4))
    out.append("")
    out.append(f"Logs: {result.log_path} and {serial_path} (pass both to uefi_log)")
    return "\n".join(out)


def _app_output(serial: str) -> list[str] | None:
    """What the first boot option printed: console lines after BDS starts it,
    up to the next BDS message or exception dump. None if it never started
    (e.g. it failed to load and BDS moved on to the next option)."""
    lines = serial.splitlines()
    first = next((i for i, ln in enumerate(lines) if ln.startswith("BdsDxe: ")), None)
    if first is None:
        return None
    # The first option's own BDS lines: "loading", then "starting" or "failed to load".
    start = None
    for i in range(first, len(lines)):
        if lines[i].startswith("BdsDxe: failed to load"):
            return None
        if lines[i].startswith("BdsDxe: starting Boot"):
            start = i
            break
    if start is None:
        return None
    out = []
    for ln in lines[start + 1:]:
        if ln.startswith(("BdsDxe:", "!!!!")):
            break
        out.append(ln)
    return out


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
