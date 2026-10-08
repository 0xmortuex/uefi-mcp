"""Boot the fixture apps under real OVMF in QEMU. Skipped without QEMU/OVMF.

Assertions use only what both OVMF flavours report: the serial console
(app output, load failures, exception dumps) - so they hold for a RELEASE
OVMF (e.g. Ubuntu's `ovmf` package) as well as QEMU's bundled debug build.
"""

import os

import pytest

from uefi_mcp import server as S
from uefi_mcp.boot import BootError, find_ovmf, find_qemu

APPS = os.path.join(os.path.dirname(__file__), "fixtures", "apps")

try:
    find_ovmf(find_qemu())
    HAVE_OVMF = True
except BootError:
    HAVE_OVMF = False

pytestmark = pytest.mark.skipif(not HAVE_OVMF, reason="QEMU and OVMF not installed")


def boot(name):
    return S.uefi_boot(os.path.join(APPS, name), timeout_s=60)


def test_hello_prints_and_returns():
    out = boot("hello.efi")
    assert "uefi-mcp hello: booted" in out
    assert "stopped by: the app returned" in out or "moved on to the next boot option" in out


def test_crash_is_disassembled():
    out = boot("crash.efi")
    assert "stopped by: a CPU exception" in out
    assert "#UD - Invalid Opcode" in out
    assert "=> 0x001012" in out and "ud2" in out


def test_wrong_subsystem_fails_to_load_with_a_cause():
    out = boot("wrongsub.efi")
    assert "FAILED TO LOAD: Not Found" in out
    assert "PE subsystem isn't EFI application" in out


def test_stripped_relocations_fail_to_load():
    out = boot("stripped.efi")
    assert "FAILED TO LOAD: Invalid Parameter" in out


def test_function_table_app_runs_because_it_has_relocations():
    out = boot("fptr.efi")
    assert "called through a function table" in out
