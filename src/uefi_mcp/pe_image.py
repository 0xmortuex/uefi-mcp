"""Inspect a PE/COFF EFI image and flag what will stop firmware loading it."""

from __future__ import annotations

import os

import capstone
import pefile

SUBSYSTEMS = {
    10: "EFI application",
    11: "EFI boot service driver",
    12: "EFI runtime driver",
    13: "EFI ROM",
}
MACHINES = {
    0x8664: ("x64", "BOOTX64.EFI"),
    0x014C: ("IA32", "BOOTIA32.EFI"),
    0xAA64: ("AArch64", "BOOTAA64.EFI"),
    0x01C2: ("ARM Thumb", "BOOTARM.EFI"),
    0x01C4: ("ARM Thumb-2", "BOOTARM.EFI"),
    0x5064: ("RISC-V 64", "BOOTRISCV64.EFI"),
    0x6264: ("LoongArch64", "BOOTLOONGARCH64.EFI"),
    0x0EBC: ("EFI Byte Code", None),
}
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
DLLCHAR_NX_COMPAT = 0x0100


class ImageError(ValueError):
    pass


def _load(path: str) -> pefile.PE:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"no such file: {path}")
    try:
        return pefile.PE(path, fast_load=False)
    except pefile.PEFormatError as e:
        raise ImageError(f"{os.path.basename(path)} is not a PE/COFF image: {e}") from None


def analyze(path: str) -> str:
    pe = _load(path)
    try:
        oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
        machine, boot_name = MACHINES.get(fh.Machine, (f"unknown ({fh.Machine:#06x})", None))
        sub = SUBSYSTEMS.get(oh.Subsystem, f"NOT an EFI subsystem ({oh.Subsystem})")
        magic = "PE32+" if oh.Magic == 0x20B else "PE32"
        relocs = sum(len(b.entries) for b in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []))
        out = [
            f"{os.path.basename(path)}: {magic}, machine {machine}, subsystem {oh.Subsystem} ({sub})",
            f"ImageBase {oh.ImageBase:#x}, SizeOfImage {oh.SizeOfImage:#x}, entry point RVA "
            f"{oh.AddressOfEntryPoint:#x}, SectionAlignment {oh.SectionAlignment:#x}, "
            f"FileAlignment {oh.FileAlignment:#x}",
            "sections:",
        ]
        for s in pe.sections:
            name = s.Name.rstrip(b"\0").decode("ascii", "replace")
            flags = "".join(c for c, bit in (("R", 0x40000000), ("W", 0x80000000), ("X", 0x20000000))
                            if s.Characteristics & bit)
            out.append(f"  {name:<8} RVA {s.VirtualAddress:#08x} size {s.Misc_VirtualSize:#07x} {flags}")
        out.append(f"base relocations: {relocs} fixup(s)"
                   + (" (relocations stripped flag SET)" if fh.Characteristics & IMAGE_FILE_RELOCS_STRIPPED else ""))
        problems: list[str] = []
        if oh.Subsystem not in SUBSYSTEMS:
            problems.append(f"subsystem {oh.Subsystem} is not an EFI subsystem. Firmware refuses to "
                            "boot it (OVMF's boot manager reports `failed to load ...: Not Found`). "
                            "Link with /subsystem:efi_application (lld/MSVC) or "
                            "--subsystem 10 (GNU ld/objcopy).")
        if fh.Characteristics & IMAGE_FILE_RELOCS_STRIPPED:
            problems.append("IMAGE_FILE_RELOCS_STRIPPED is set: the image can only run at its "
                            f"ImageBase ({oh.ImageBase:#x}), but firmware picks the load address, "
                            "so LoadImage rejects it (OVMF says `Invalid Parameter` or `Not Found`, depending on "
                            "its EDK2 version). Keep relocations "
                            "(don't pass /fixed or --strip-relocs).")
        notes: list[str] = []
        if relocs == 0 and not fh.Characteristics & IMAGE_FILE_RELOCS_STRIPPED:
            notes.append("no base relocations. That's fine only if the code never uses an "
                            "absolute address (function-pointer tables, pointers in initialised "
                            "data). If it does and the firmware loads it away from ImageBase, it "
                            "jumps to garbage. lld emits .reloc automatically when it's needed.")
        if oh.SectionAlignment < 0x1000:
            problems.append(f"SectionAlignment {oh.SectionAlignment:#x} is below 4 KiB: firmware "
                            "with memory protection can't map sections with separate permissions "
                            "(OVMF logs `Image Section Alignment ... does not match Required "
                            "Alignment (0x1000)`).")
        if boot_name is None and fh.Machine != 0x0EBC:
            problems.append(f"unknown machine type {fh.Machine:#06x}")
        if oh.AddressOfEntryPoint == 0:
            problems.append("entry point RVA is 0 - the linker didn't find the entry symbol "
                            "(efi_main / EfiMain / _start, depending on the toolchain)")
        out.append("")
        if problems:
            out.append("PROBLEMS:")
            out.extend(f"  - {p}" for p in problems)
        else:
            out.append("No loading problems found.")
        if notes:
            out.append("Notes:")
            out.extend(f"  - {n}" for n in notes)
        if boot_name and oh.Subsystem == 10:
            out.append(f"As a removable-media boot loader it must be named \\EFI\\BOOT\\{boot_name}.")
        return "\n".join(out)
    finally:
        pe.close()


def disassemble(path: str, rva: int, count: int = 8, before: int = 0) -> str:
    """Disassemble around an RVA (e.g. from a crash: RIP - ImageBase)."""
    pe = _load(path)
    try:
        fh = pe.FILE_HEADER
        if fh.Machine == 0x8664:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif fh.Machine == 0x014C:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif fh.Machine == 0xAA64:
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            raise ImageError(f"disassembly not supported for machine {fh.Machine:#06x}")
        section = next((s for s in pe.sections
                        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)), None)
        if section is None:
            raise ImageError(f"RVA {rva:#x} is outside every section of {os.path.basename(path)}")
        name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        if not section.Characteristics & 0x20000000:
            raise ImageError(f"RVA {rva:#x} is in {name}, which isn't executable - the IP "
                             "points into data (a corrupted return address or function pointer?)")
        data = section.get_data()
        # Decode from the section start so instruction boundaries are right.
        insns = list(cs.disasm(data, section.VirtualAddress))
        idx = next((i for i, ins in enumerate(insns) if ins.address == rva), None)
        if idx is None:
            raise ImageError(f"RVA {rva:#x} is not on an instruction boundary in {name} "
                             "(linear decode from the section start)")
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        lines = []
        for ins in insns[max(0, idx - before):idx + count]:
            mark = "=>" if ins.address == rva else "  "
            off = f"entry+{ins.address - entry:#x}" if ins.address >= entry else ""
            lines.append(f"{mark} {ins.address:#08x} {off:<12} {ins.mnemonic} {ins.op_str}".rstrip())
        return f"{os.path.basename(path)} {name}, RVA {rva:#x}:\n" + "\n".join(lines)
    finally:
        pe.close()
