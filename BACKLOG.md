# Backlog

## Features
- [ ] AArch64: boot with `qemu-system-aarch64 -M virt` + edk2-aarch64-code.fd (BOOTAA64.EFI),
      and decode AArch64 exception dumps (ESR/FAR) in uefi_log.
- [ ] IA32 apps (BOOTIA32.EFI) with OVMF Ia32.
- [ ] Symbolize crash RVAs with the app's PDB or a DWARF-carrying ELF before objcopy (gnu-efi
      builds keep an ELF): function + source line, not just the instruction.
- [ ] `uefi_variables`: read/write NVRAM variables in an OVMF VARS.fd (authenticated
      variable store format), e.g. BootOrder / Boot#### decoding.
- [ ] EFI/Tiano-compressed sections (fv.py currently reports them as not decoded).
- [ ] Secure Boot runs: OVMF secure-boot images + enrolled keys, explain SECURITY_VIOLATION.
- [ ] uefi_boot `disk=` option to boot a full ESP directory or image, not only one app.

## Quality
- [ ] CI job that reruns tools/gen_data.py and fails if the committed data drifts from the
      pinned EDK2 commit (needs network).
- [ ] Capture fixture logs from a RELEASE OVMF (Ubuntu's) to test that path against real data,
      not only by stripping the debug log.
