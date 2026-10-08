"""The log parser against real OVMF output (QEMU's bundled edk2-stable202408
debug build), one capture per failure mode - see tests/fixtures/apps."""

import os

import pytest

from uefi_mcp import ovmf_log

LOGS = os.path.join(os.path.dirname(__file__), "fixtures", "logs")


def load(name, serial=True):
    with open(os.path.join(LOGS, f"{name}.ovmf.log"), encoding="utf-8", errors="replace") as fh:
        debug = fh.read()
    con = ""
    if serial:
        with open(os.path.join(LOGS, f"{name}.serial.log"), encoding="utf-8", errors="replace") as fh:
            con = fh.read()
    return ovmf_log.parse(debug, con)


def test_phases_and_driver_counts():
    log = load("hello")
    assert log.phases == ["SEC", "PEI", "DXE", "BDS"]
    assert sum(i.kind == "PEIM" for i in log.images) >= 10
    assert any(i.name == "BdsDxe.efi" for i in log.images)


def test_benign_driver_declines_are_called_normal():
    text = ovmf_log.explain(load("hello"))
    assert "AmdSevDxe.efi: Unsupported (EFI_UNSUPPORTED) -> normal - not an AMD SEV guest" in text
    assert "QemuKernelLoaderFsDxe.efi: Not Found" in text
    assert "a warning value, 0x1 - not an error code" in text  # RngDxe's odd status


def test_success_is_attached_to_the_right_attempt():
    log = load("hello")
    first = log.attempts[0]
    assert first.description.startswith("UEFI QEMU HARDDISK")
    assert first.path and first.path.endswith("\\EFI\\BOOT\\BOOTX64.EFI")
    assert [i.name for i in first.images] == ["hello.efi"]
    assert first.returned == "Success"
    assert all(a.returned is None for a in log.attempts[1:])


def test_error_return():
    log = load("fail")
    assert log.attempts[0].returned == "Unsupported"
    assert "returned: Unsupported (EFI_UNSUPPORTED)" in ovmf_log.explain(log)


def test_crash_maps_ip_to_image_and_rva():
    log = load("crash")
    (exc,) = log.exceptions
    assert exc.vector == 6 and "Invalid Opcode" in exc.description
    assert exc.image == "crash.efi"  # loader's name, not the PDB OVMF prints
    assert exc.registers["RIP"] - exc.image_base == 0x1012
    assert "RVA 0x1012 (entry point + 0x12)" in ovmf_log.explain(log)


def test_wrong_subsystem_load_failure_comes_from_serial():
    log = load("wrongsub")
    assert log.attempts[0].failed_load == "Not Found"
    assert "PE subsystem isn't EFI application" in ovmf_log.explain(log)
    # Without the console the failure is invisible - the debug log alone
    # only shows the device path expanding to <null string>.
    assert load("wrongsub", serial=False).attempts[0].failed_load is None
    assert "didn't resolve to a loadable file" in ovmf_log.explain(load("wrongsub", serial=False))


def test_stripped_relocations_load_failure():
    log = load("stripped")
    assert log.attempts[0].failed_load == "Invalid Parameter"
    assert "relocations stripped" in ovmf_log.explain(log)


@pytest.mark.parametrize("name", ["hello", "fail", "crash", "fptr", "wrongsub", "stripped"])
def test_serial_only_mode_for_release_builds(name):
    with open(os.path.join(LOGS, f"{name}.serial.log"), encoding="utf-8", errors="replace") as fh:
        log = ovmf_log.parse("", fh.read())
    assert log.attempts, "console alone must still yield the boot attempts"
    assert "RELEASE build" in ovmf_log.explain(log)


def test_assert_lines_are_reported():
    log = ovmf_log.parse("[Bds] Entry...\nASSERT [BdsDxe] /edk2/MdeModulePkg/Bds.c(123): Status == 0\n")
    assert log.asserts == [("BdsDxe", "/edk2/MdeModulePkg/Bds.c", 123, "Status == 0")]
    assert "ASSERT in BdsDxe: /edk2/MdeModulePkg/Bds.c:123: Status == 0" in ovmf_log.explain(log)


def test_empty_input():
    assert "No boot attempt found" in ovmf_log.explain(ovmf_log.parse("", ""))


@pytest.mark.parametrize("name,expected", [
    ("hello", ["uefi-mcp hello: booted"]),
    ("crash", ["uefi-mcp hello: booted"]),
    ("fptr", ["uefi-mcp hello: called through a function table"]),
    ("wrongsub", None),   # never started; the EFI Shell's output must not leak in
    ("stripped", None),
])
def test_app_output_is_only_the_first_options(name, expected):
    from uefi_mcp.boot import _clean_serial
    from uefi_mcp.server import _app_output
    with open(os.path.join(LOGS, f"{name}.serial.log"), "rb") as fh:
        assert _app_output(_clean_serial(fh.read())) == expected
