"""Parse and explain OVMF/EDK2 boot output.

OVMF splits what happened across two streams, and both are needed:

  debug log (debugcon port 0x402, debug builds only)
      phases, every PEIM/driver load with base address, driver start
      failures, BDS boot options, `Image Return Status`, ASSERTs
  console (serial)
      `BdsDxe: failed to load BootXXXX ...: <status>` and CPU exception
      dumps (`!!!! X64 Exception Type - ...`), which never reach debugcon

A healthy OVMF boot logs several `Error: Image at ... start failed` lines:
platform drivers declining hardware that isn't there. They are classified
as normal here so an agent doesn't chase them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import edk2

# OVMF drivers that routinely decline to start, and the usual reason.
BENIGN_DECLINES: dict[str, str] = {
    "AmdSevDxe": "not an AMD SEV guest",
    "TdxDxe": "not an Intel TDX guest",
    "TdTcg2Dxe": "not an Intel TDX guest",
    "EmuVariableFvbRuntimeDxe": "real flash variable storage is present, so the emulated "
                                "variable store steps aside",
    "TcgDxe": "no TPM 1.2 device",
    "Tcg2Dxe": "no TPM 2.0 device",
    "RngDxe": "no usable hardware entropy source for this RNG driver",
    "QemuRamfbDxe": "no `-device ramfb` on the QEMU command line",
    "QemuKernelLoaderFsDxe": "no `-kernel` passed to QEMU",
    "VirtioRngDxe": "no virtio-rng device",
    "LegacyBiosDxe": "no CSM/legacy BIOS in this build",
}

LOAD_FAILURE_HINTS = {
    "Not Found": "the file was opened, but the firmware didn't accept it as a bootable image. "
                 "Most often the PE subsystem isn't EFI application (10) or the machine type "
                 "doesn't match the CPU - check with uefi_image",
    "Invalid Parameter": "LoadImage rejected the PE/COFF image. Common causes: base "
                         "relocations stripped (IMAGE_FILE_RELOCS_STRIPPED) so it can't be "
                         "placed at a firmware-chosen address, or malformed headers - check "
                         "with uefi_image",
    "Load Error": "the image is malformed or not a PE/COFF file the firmware understands",
    "Unsupported": "the image type or machine isn't supported by this firmware",
    "Security Violation": "Secure Boot rejected the image (unsigned or untrusted signer)",
    "Access Denied": "Secure Boot policy denied the image",
}

_LOAD_RE = re.compile(r"Loading (PEIM|driver|DXE CORE) at 0x([0-9A-Fa-f]+) EntryPoint=0x([0-9A-Fa-f]+)\s*(\S*)")
_LOAD_GUID_RE = re.compile(r"Loading (PEIM|driver) ([0-9A-Fa-f-]{36})\s*$")
_START_FAIL_RE = re.compile(r"Error: Image at ([0-9A-Fa-f]+) start failed: (.+?)\s*$")
_RETURN_RE = re.compile(r"Image Return Status = (.+?)\s*$")
_OPTION_RE = re.compile(r"^\s*(Boot[0-9A-Fa-f]{4}): (.+?)\s+0x([0-9A-Fa-f]+)\s*$")
_BOOTING_RE = re.compile(r"\[Bds\]\s*Booting (.+?)\s*$")
_EXPAND_RE = re.compile(r"\[Bds\] Expand .* -> (.+?)\s*$")
_STARTING_RE = re.compile(r'BdsDxe: starting (Boot[0-9A-Fa-f]{4}) "(.*?)" from (.+?)\s*$')
_FAILED_LOAD_RE = re.compile(r'BdsDxe: failed to load (Boot[0-9A-Fa-f]{4}) "(.*?)" from (.+?): (.+?)\s*$')
_EXC_RE = re.compile(r"!!!! (X64|IA32) Exception Type - ([0-9A-Fa-f]+)\((.+?)\)")
_EXC_REG_RE = re.compile(r"\b(RIP|EIP|CR2|RSP|ESP|RBP|EBP)\s*-\s*([0-9A-Fa-f]+)")
_FIND_IMAGE_RE = re.compile(r"Find image based on IP\(0x([0-9A-Fa-f]+)\) (.+?) \(ImageBase=([0-9A-Fa-f]+), EntryPoint=([0-9A-Fa-f]+)\)")
_ASSERT_RE = re.compile(r"ASSERT \[(\S+)\] (.+?)\((\d+)\): (.+?)\s*$")


@dataclass
class Image:
    kind: str  # PEIM | driver
    name: str
    base: int
    entry: int
    guid: str | None
    after_bds: bool
    start_failed: str | None = None


@dataclass
class Attempt:
    description: str
    path: str | None = None
    images: list[Image] = field(default_factory=list)
    returned: str | None = None
    failed_load: str | None = None  # status from "BdsDxe: failed to load ..."


@dataclass
class CpuException:
    arch: str
    vector: int
    description: str
    registers: dict[str, int]
    image: str | None = None
    image_base: int | None = None
    entry: int | None = None


@dataclass
class BootLog:
    phases: list[str] = field(default_factory=list)
    images: list[Image] = field(default_factory=list)
    options: list[tuple[str, str, int]] = field(default_factory=list)
    attempts: list[Attempt] = field(default_factory=list)
    failed_loads: list[tuple[str, str, str, str]] = field(default_factory=list)
    exceptions: list[CpuException] = field(default_factory=list)
    asserts: list[tuple[str, str, int, str]] = field(default_factory=list)
    lines: int = 0

    def image_at(self, address: int) -> Image | None:
        best = None
        for im in self.images:
            if im.base <= address and (best is None or im.base > best.base):
                best = im
        return best


def parse(debug_log: str, serial: str = "") -> BootLog:
    log = BootLog()
    pending_guid: str | None = None
    after_bds = False
    for line in debug_log.splitlines():
        log.lines += 1
        if "SecCoreStartupWithStack" in line and "SEC" not in log.phases:
            log.phases.append("SEC")
        elif line.startswith("Loading PEIM") and "PEI" not in log.phases:
            log.phases.append("PEI")
        elif ("DXE IPL Entry" in line or "Loading DXE CORE" in line) and "DXE" not in log.phases:
            log.phases.append("DXE")
        elif line.startswith("[Bds] Entry") and "BDS" not in log.phases:
            log.phases.append("BDS")
            after_bds = True
        m = _LOAD_GUID_RE.search(line)
        if m:
            pending_guid = m.group(2).upper()
            continue
        m = _LOAD_RE.search(line)
        if m:
            kind, base, entry, fname = m.groups()
            if kind == "DXE CORE":
                continue  # DxeCore.efi was just logged as a PEIM-style load
            name = fname or (edk2.name_for_guid(pending_guid) if pending_guid else None) or "?"
            image = Image(kind, name, int(base, 16), int(entry, 16), pending_guid,
                          after_bds and kind == "driver")
            log.images.append(image)
            if image.after_bds and log.attempts:
                log.attempts[-1].images.append(image)
            pending_guid = None
            continue
        m = _START_FAIL_RE.search(line)
        if m:
            im = log.image_at(int(m.group(1), 16))
            if im is not None and im.base == int(m.group(1), 16):
                im.start_failed = m.group(2)
            continue
        m = _OPTION_RE.match(line)
        if m and after_bds:
            log.options.append((m.group(1), m.group(2).strip(), int(m.group(3), 16)))
            continue
        m = _BOOTING_RE.search(line)
        if m:
            log.attempts.append(Attempt(m.group(1).rstrip(".")))
            continue
        m = _EXPAND_RE.search(line)
        if m and log.attempts:
            log.attempts[-1].path = m.group(1)
            continue
        m = _RETURN_RE.search(line)
        if m and log.attempts:
            log.attempts[-1].returned = m.group(1)
            continue
        m = _ASSERT_RE.search(line)
        if m:
            log.asserts.append((m.group(1), m.group(2), int(m.group(3)), m.group(4)))
    from_log = bool(log.attempts)
    _parse_console(serial, log, add_attempts=not from_log)
    _parse_console(debug_log, log, only_exceptions=True)
    for _opt, desc, _path, status in log.failed_loads:
        for attempt in log.attempts:
            if attempt.description.strip() == desc.strip() and attempt.failed_load is None:
                attempt.failed_load = status
                break
    for exc in log.exceptions:
        # OVMF names the PDB; prefer the image name the loader logged at that base.
        if exc.image_base is not None:
            im = log.image_at(exc.image_base)
            if im is not None and im.base == exc.image_base:
                exc.image = im.name
    return log


def _parse_console(text: str, log: BootLog, only_exceptions: bool = False,
                   add_attempts: bool = False) -> None:
    """Console lines. add_attempts: with no debug log (RELEASE OVMF), the
    console's `BdsDxe: starting/failed to load` lines are the only record
    of boot attempts."""
    text = re.sub(r"\x1b\[[0-9;=?]*[A-Za-z]", "", text).replace("\r", "\n")
    current: CpuException | None = None
    for line in text.splitlines():
        if not only_exceptions:
            m = _STARTING_RE.search(line)
            if m:
                if add_attempts:
                    log.attempts.append(Attempt(m.group(2).strip(), m.group(3)))
                continue
            m = _FAILED_LOAD_RE.search(line)
            if m:
                opt, desc, path, status = m.groups()
                log.failed_loads.append((opt, desc, path, status))
                if add_attempts:
                    log.attempts.append(Attempt(desc.strip(), path))
                continue
            m = _ASSERT_RE.search(line)
            if m:
                entry = (m.group(1), m.group(2), int(m.group(3)), m.group(4))
                if entry not in log.asserts:
                    log.asserts.append(entry)
        m = _EXC_RE.search(line)
        if m:
            current = CpuException(m.group(1), int(m.group(2), 16), m.group(3), {})
            log.exceptions.append(current)
            continue
        if current is not None:
            for reg, val in _EXC_REG_RE.findall(line):
                current.registers.setdefault(reg, int(val, 16))
            m = _FIND_IMAGE_RE.search(line)
            if m:
                current.image = m.group(2)
                current.image_base = int(m.group(3), 16)
                current.entry = int(m.group(4), 16)
                current = None


def _status_label(text: str) -> str:
    st = edk2.status_from_log_text(text)
    if st is None:
        return text
    if st.error or st.code == 0:
        return st.name or text
    return f"a warning value, {st.value:#x} - not an error code"


def explain(log: BootLog) -> str:
    out: list[str] = []
    peims = [i for i in log.images if i.kind == "PEIM"]
    drivers = [i for i in log.images if i.kind == "driver" and not i.after_bds]
    declined = [i for i in drivers if i.start_failed]
    phases = " -> ".join(log.phases) or "no phases recognised"
    out.append(f"Firmware phases: {phases}  ({len(peims)} PEIMs, {len(drivers)} DXE drivers "
               f"loaded; {log.lines} log lines)")
    if not log.lines:
        out.append("The debug log is empty: this OVMF is probably a RELEASE build (no debug "
                   "output) or the log wasn't captured on port 0x402. Console output is still "
                   "parsed.")
    if declined:
        out.append("")
        out.append(f"Drivers that did not start ({len(declined)}):")
        for im in declined:
            reason = BENIGN_DECLINES.get(im.name.removesuffix(".efi"))
            verdict = f"normal - {reason}" if reason else "check whether this driver matters for you"
            out.append(f"  {im.name}: {im.start_failed} ({_status_label(im.start_failed or '')})"
                       f" -> {verdict}")
    if log.options:
        out.append("")
        out.append("Boot options: " + "; ".join(f"{o} {d!r}" for o, d, _ in log.options))
    if log.attempts:
        out.append("")
        out.append("Boot attempts (in order):")
        for i, a in enumerate(log.attempts, 1):
            shown_path = a.path if a.path and a.path != "<null string>" else None
            out.append(f"  {i}. {a.description}" + (f"  [{shown_path}]" if shown_path else ""))
            for im in a.images:
                out.append(f"     loaded {im.name} at {im.base:#x} (entry {im.entry:#x}, "
                           f"entry RVA {im.entry - im.base:#x})")
            if a.returned is not None:
                out.append(f"     returned: {a.returned} ({_status_label(a.returned)})")
            if a.failed_load is not None:
                hint = LOAD_FAILURE_HINTS.get(a.failed_load, "")
                out.append(f"     FAILED TO LOAD: {a.failed_load}" + (f" - {hint}" if hint else ""))
            elif a.path == "<null string>":
                out.append("     the boot option's device path didn't resolve to a loadable file")
    for exc in log.exceptions:
        out.append("")
        out.append(f"CPU EXCEPTION: {exc.arch} vector {exc.vector:#04x} ({exc.description})")
        ip = exc.registers.get("RIP", exc.registers.get("EIP"))
        if ip is not None:
            out.append(f"  at IP {ip:#x}")
        if exc.image and exc.image_base is not None and ip is not None:
            rva = ip - exc.image_base
            entry_note = (f" (entry point + {ip - exc.entry:#x})"
                          if exc.entry is not None and ip >= exc.entry else "")
            out.append(f"  in {exc.image} loaded at {exc.image_base:#x}: RVA {rva:#x}{entry_note}")
            out.append(f"  -> uefi_image(path, rva='{rva:#x}') shows the faulting instruction")
        if "CR2" in exc.registers and exc.vector == 0x0E:
            out.append(f"  faulting address (CR2) = {exc.registers['CR2']:#x}")
    for module, file, line, expr in log.asserts:
        out.append("")
        out.append(f"ASSERT in {module}: {file}:{line}: {expr}")
    if not (log.attempts or log.exceptions or log.asserts):
        out.append("")
        out.append("No boot attempt found - the log may have been cut off before BDS.")
    return "\n".join(out)
