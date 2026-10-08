# Changelog

## 0.1.0 - 2026-10-08

First release.

- `uefi_boot`: boot an .efi under OVMF in QEMU (as `\EFI\BOOT\BOOTX64.EFI` on a virtual
  disk) and explain the outcome - what the app printed, its return status, load failures
  with likely causes, CPU exceptions with the faulting instruction disassembled.
- `uefi_log`: explain an OVMF debug log plus the serial console - phases, every driver and
  its base address, which driver start failures are normal, boot attempts, return
  statuses, exceptions mapped to image + RVA, ASSERTs. Works from the console alone for
  RELEASE builds of OVMF.
- `uefi_image`: PE/COFF checks that predict load failures (subsystem, stripped
  relocations, section alignment, entry point) and disassembly at an RVA.
- `uefi_status`, `uefi_guid`: EFI_STATUS values and 964 GUID names + 1240 module FILE_GUIDs
  generated from EDK2 edk2-stable202408 (`tools/gen_data.py`).
- `uefi_volume`: firmware volumes and FFS files, including LZMA-compressed nested volumes.
