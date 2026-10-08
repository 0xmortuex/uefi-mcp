"""Boot an EFI application under OVMF in QEMU and capture what happened.

The app is copied to EFI/BOOT/BOOTX64.EFI on a QEMU "vvfat" directory disk,
so OVMF's default boot option finds it with no NVRAM setup. OVMF's debug
output goes to the ISA debugcon port 0x402 (where OVMF debug builds write
it), the console to serial. After the app returns, OVMF's boot manager
falls back to its setup UI and would sit there forever, so the run stops as
soon as the log shows the app returned, crashed, or failed to load.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

# Code/vars pairs. The vars file is copied per run (OVMF writes to it).
_CANDIDATES = [
    # QEMU's own bundled EDK2 (Windows installer; some Linux distros)
    ("{share}/edk2-x86_64-code.fd", "{share}/edk2-i386-vars.fd"),
    # Debian/Ubuntu `ovmf` package
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
    # Fedora / Arch
    ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
    ("/usr/share/edk2/x64/OVMF_CODE.fd", "/usr/share/edk2/x64/OVMF_VARS.fd"),
    ("/usr/share/qemu/edk2-x86_64-code.fd", "/usr/share/qemu/edk2-i386-vars.fd"),
]

# Outcomes of the first boot attempt. Some land in the debug log (debugcon),
# some only on the console (serial): load failures and CPU exception dumps.
STOP_MARKERS = (
    ("Image Return Status", "the app returned"),
    ("Exception Type - ", "a CPU exception"),
    ("failed to load Boot", "the boot option failed to load"),
    ("ASSERT ", "an ASSERT"),
)


class BootError(RuntimeError):
    pass


def find_qemu() -> str:
    found = shutil.which("qemu-system-x86_64")
    if found:
        return found
    for d in (os.environ.get("QEMU_DIR", ""), r"C:\Program Files\qemu"):
        exe = os.path.join(d, "qemu-system-x86_64.exe")
        if d and os.path.isfile(exe):
            return exe
    raise BootError("qemu-system-x86_64 not found. Install QEMU and put it on PATH "
                    "(or set QEMU_DIR on Windows).")


def find_ovmf(qemu: str) -> tuple[str, str]:
    code = os.environ.get("UEFI_MCP_OVMF_CODE")
    if code:
        vars_ = os.environ.get("UEFI_MCP_OVMF_VARS", "")
        if not (os.path.isfile(code) and os.path.isfile(vars_)):
            raise BootError("UEFI_MCP_OVMF_CODE/UEFI_MCP_OVMF_VARS must both point at "
                            f"existing files (got {code!r}, {vars_!r})")
        return code, vars_
    share = os.path.join(os.path.dirname(qemu), "share")
    tried = []
    for code_t, vars_t in _CANDIDATES:
        c, v = code_t.format(share=share), vars_t.format(share=share)
        tried.append(c)
        if os.path.isfile(c) and os.path.isfile(v):
            return c, v
    raise BootError("OVMF firmware not found. Install it (Debian/Ubuntu: apt install ovmf) or "
                    "set UEFI_MCP_OVMF_CODE and UEFI_MCP_OVMF_VARS. Looked for: "
                    + ", ".join(tried))


@dataclass
class BootResult:
    workdir: str
    log_path: str
    serial: str
    stopped_by: str
    seconds: float
    firmware: str


def _clean_serial(raw: bytes) -> str:
    """Drop the terminal escape sequences OVMF's console emits."""
    import re
    text = raw.decode("utf-8", "replace")
    text = re.sub(r"\x1b\[[0-9;=?]*[A-Za-z]", "", text)
    lines = [ln.rstrip() for ln in text.replace("\r", "\n").split("\n")]
    return "\n".join(ln for ln in lines if ln.strip())


def boot(app: str, timeout_s: float = 30.0, workdir: str | None = None,
         extra_args: list[str] | None = None) -> BootResult:
    if not os.path.isfile(app):
        raise FileNotFoundError(f"EFI application not found: {app}")
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    qemu = find_qemu()
    code, vars_template = find_ovmf(qemu)
    work = workdir or tempfile.mkdtemp(prefix="uefi-mcp-")
    esp = os.path.join(work, "esp", "EFI", "BOOT")
    os.makedirs(esp, exist_ok=True)
    shutil.copyfile(app, os.path.join(esp, "BOOTX64.EFI"))
    vars_copy = os.path.join(work, "vars.fd")
    shutil.copyfile(vars_template, vars_copy)
    log_path = os.path.join(work, "ovmf.log")
    serial_path = os.path.join(work, "serial.log")
    cmd = [
        qemu, "-M", "q35", "-m", "256", "-display", "none", "-no-reboot", "-net", "none",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={vars_copy}",
        "-drive", f"format=raw,file=fat:rw:{os.path.join(work, 'esp')}",
        "-debugcon", f"file:{log_path}", "-global", "isa-debugcon.iobase=0x402",
        "-serial", f"file:{serial_path}",
        *(extra_args or []),
    ]
    start = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    stopped_by = "timeout"
    try:
        while time.monotonic() - start < timeout_s:
            if proc.poll() is not None:
                stopped_by = f"QEMU exited (code {proc.returncode})"
                break
            hit = _outcome(_read(log_path), _read(serial_path))
            if hit:
                time.sleep(0.5)  # let the rest of the dump/console output flush
                stopped_by = hit
                break
            time.sleep(0.1)
    finally:
        if proc.poll() is None:
            proc.kill()
        _, err = proc.communicate()
    if stopped_by.startswith("QEMU exited") and proc.returncode not in (0, None):
        raise BootError(f"QEMU failed: {err.decode('utf-8', 'replace').strip()[-800:]}")
    return BootResult(work, log_path, _clean_serial(_read_bytes(serial_path)), stopped_by,
                      round(time.monotonic() - start, 2), code)


def _outcome(log: str, serial: str) -> str | None:
    """What ended the first boot attempt, if anything has yet.

    Only text after BDS started booting counts: firmware drivers
    legitimately fail to start during DXE dispatch. BDS moving on to a
    second boot option also ends the attempt (e.g. the EFI Shell fallback).
    Works from the serial console alone too, for RELEASE builds of OVMF
    that write no debug log.
    """
    log_start = log.find("[Bds]Booting ")
    serial_start = serial.find("BdsDxe: ")
    if log_start == -1 and serial_start == -1:
        return None
    after_log = log[log_start:] if log_start != -1 else ""
    after_serial = serial[serial_start:] if serial_start != -1 else ""
    for marker, label in STOP_MARKERS:
        if marker in after_log or marker in after_serial:
            return label
    if after_log.find("[Bds]Booting ", len("[Bds]Booting ")) != -1:
        return "boot manager moved on to the next boot option"
    starts = after_serial.count("BdsDxe: starting Boot")
    loads = after_serial.count("BdsDxe: loading Boot")
    if starts >= 2 or (starts == 1 and loads >= 2):
        return "boot manager moved on to the next boot option"
    return None


def _read_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return b""


def _read(path: str) -> str:
    return _read_bytes(path).decode("utf-8", "replace")


if __name__ == "__main__":  # pragma: no cover - manual fixture capture helper
    r = boot(sys.argv[1], workdir=sys.argv[2] if len(sys.argv) > 2 else None)
    print(r.stopped_by, r.seconds, r.log_path)
    print(r.serial)
