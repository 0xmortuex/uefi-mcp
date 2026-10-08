# uefi-mcp

**Let your AI agent boot your UEFI app, and tell you why it didn't work.**

<!-- mcp-name: io.github.0xmortuex/uefi-mcp -->

uefi-mcp is an [MCP](https://modelcontextprotocol.io) server for UEFI development: the
bootloader of your hobby OS, an EFI application, or a firmware driver. It boots an `.efi`
under OVMF in QEMU and explains what happened. It reads OVMF's logs the way someone who
knows EDK2 would, and it checks PE/COFF binaries for the mistakes that stop firmware
loading them.

Companion to [qemu-mcp](https://github.com/0xmortuex/qemu-mcp) and
[gdbstub-mcp](https://github.com/0xmortuex/gdbstub-mcp), for the stage before your kernel
runs.

## What it looks like

All output below is real, from booting the test apps in
[`tests/fixtures/apps`](tests/fixtures/apps) under QEMU's bundled OVMF
(edk2-stable202408).

An app that crashes. One tool call boots it, finds the exception, maps the instruction
pointer back into the `.efi`, and disassembles the faulting instruction:

```
> uefi_boot crash.efi
Booted crash.efi under OVMF (edk2-x86_64-code.fd) in 5.42s - stopped by: a CPU exception

What the app printed:
  uefi-mcp hello: booted

Boot attempts (in order):
  1. UEFI QEMU HARDDISK QM00001  [PciRoot(0x0)/.../HD(1,MBR,...)/\EFI\BOOT\BOOTX64.EFI]
     loaded crash.efi at 0xde21000 (entry 0xde22000, entry RVA 0x1000)

CPU EXCEPTION: X64 vector 0x06 (#UD - Invalid Opcode)
  at IP 0xde22012
  in crash.efi loaded at 0xde21000: RVA 0x1012 (entry point + 0x12)

Faulting instruction:
crash.efi .text, RVA 0x1012:
   0x00100a entry+0xa    mov rcx, rdx
   0x00100d entry+0xd    call 0x1020
=> 0x001012 entry+0x12   ud2
   0x001014 entry+0x14   xor eax, eax
```

An app that never runs. OVMF says only `Not Found`, then silently falls through to the
EFI Shell. uefi-mcp says why:

```
> uefi_boot wrongsub.efi
... stopped by: the boot option failed to load

The app never started (see the boot attempts below).

Boot attempts (in order):
  1. UEFI QEMU HARDDISK QM00001
     FAILED TO LOAD: Not Found - the file was opened, but the firmware didn't accept it as a
     bootable image. Most often the PE subsystem isn't EFI application (10) or the machine
     type doesn't match the CPU - check with uefi_image
  2. EFI Internal Shell  [Fv(7CB8BDC9-...)/FvFile(7C04A583-...)]

> uefi_image wrongsub.efi
wrongsub.efi: PE32+, machine x64, subsystem 3 (NOT an EFI subsystem (3))
PROBLEMS:
  - subsystem 3 is not an EFI subsystem. Firmware refuses to boot it (OVMF's boot manager
    reports `failed to load ...: Not Found`). Link with /subsystem:efi_application
    (lld/MSVC) or --subsystem 10 (GNU ld/objcopy).
```

Every healthy OVMF boot logs eight `Error: Image at ... start failed` lines. An agent
would chase them. uefi-mcp knows they're normal:

```
Drivers that did not start (8):
  AmdSevDxe.efi: Unsupported (EFI_UNSUPPORTED) -> normal - not an AMD SEV guest
  Tcg2Dxe.efi: Unsupported (EFI_UNSUPPORTED) -> normal - no TPM 2.0 device
  QemuKernelLoaderFsDxe.efi: Not Found (EFI_NOT_FOUND) -> normal - no `-kernel` passed to QEMU
  ...
```

## Tools

| Tool | What it does |
|------|--------------|
| `uefi_boot` | Boot an `.efi` under OVMF in QEMU (placed at `\EFI\BOOT\BOOTX64.EFI` on a virtual disk) and explain the outcome: what the app printed, its return status, load failures with likely causes, CPU exceptions with the faulting instruction disassembled. Stops as soon as the outcome is known (about 5 s). |
| `uefi_log` | Explain an existing OVMF debug log plus serial console: phases, every PEIM/driver with its base address, which start failures are normal, each boot attempt with the images it loaded, return statuses, exceptions mapped to image + RVA, ASSERTs. Works from the console alone for RELEASE OVMF builds. |
| `uefi_image` | Check a PE/COFF `.efi` for what stops firmware loading it (subsystem, stripped relocations, section alignment, entry point, boot file name), and disassemble at an RVA. |
| `uefi_status` | Decode an EFI_STATUS from a 64- or 32-bit value, a name, or the text logs print (`"Not Found"`), with what usually causes it. |
| `uefi_guid` | Name a GUID (protocol, table, PPI, or a driver's FILE_GUID from `Loading driver <GUID>`), or search GUIDs and modules by name. |
| `uefi_volume` | List the firmware volumes and FFS files in a flash image (OVMF_CODE.fd), including OVMF's LZMA-compressed DXE volume. |

## Why the console matters

OVMF splits what happened across two outputs, and each half is useless alone:

- **Debug log** (`-debugcon file:ovmf.log -global isa-debugcon.iobase=0x402`): phases,
  driver loads and addresses, `Image Return Status`, ASSERTs. Only debug builds write it.
- **Serial console** (`-serial file:serial.log`): `BdsDxe: failed to load ...` and CPU
  exception dumps. These never reach the debug log. With the debug log alone, a load
  failure shows up only as `Expand ... -> <null string>`.

`uefi_boot` captures both. Give `uefi_log` both too.

## Install

```bash
pip install uefi-mcp
claude mcp add uefi -- uefi-mcp
```

`uefi_boot` needs `qemu-system-x86_64` and OVMF. QEMU's Windows installer bundles OVMF,
and on Debian/Ubuntu run `apt install qemu-system-x86 ovmf`. If OVMF isn't found
automatically, set `UEFI_MCP_OVMF_CODE` and `UEFI_MCP_OVMF_VARS`. The other tools need
nothing beyond Python 3.10+.

## Where the data comes from

EFI_STATUS values, the text OVMF prints for them, 964 GUID names, and 1240 module
FILE_GUID→name mappings are **generated** from EDK2 source at tag `edk2-stable202408`
(commit `b158dad1`) by [`tools/gen_data.py`](tools/gen_data.py), not typed by hand. EDK2 is
BSD-2-Clause-Patent, and its licence ships next to the data
(`src/uefi_mcp/data/EDK2-LICENSE.txt`). The one-line explanations of common statuses and
the list of normally-declining OVMF drivers are this project's own.

## Limits

- x64 only so far: boot, exception decoding and disassembly. AArch64 and IA32 are in
  [BACKLOG.md](BACKLOG.md).
- Crash locations are instruction-level (RVA + disassembly), with no source lines yet.
- EFI/Tiano-compressed FFS sections are listed but not decoded. LZMA ones are.
- Tested against QEMU's bundled OVMF (a debug build). Ubuntu's `ovmf` package runs in CI.

## Tests

```bash
pip install ".[test]" "ruff==0.16.0" "mypy==2.3.0"
ruff check src tests tools && mypy --strict src
pytest tests
```

The unit tests run on real captured OVMF logs, one per failure mode (success, error return,
`#UD` crash, wrong subsystem, stripped relocations, function-pointer table). They also run
on the fixture `.efi` files, and on a firmware volume built byte by byte, so they need no
QEMU. `tests/test_boot_integration.py` boots every fixture under real OVMF and skips if
QEMU or OVMF is missing. To rebuild the fixture apps, run `python tests/fixtures/apps/build.py`
(needs `pip install ziglang pefile`).

## License

MIT. EDK2-derived data is BSD-2-Clause-Patent; see above.
