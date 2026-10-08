"""Rebuild the fixture EFI applications (committed, so tests need no compiler).

Requires: pip install ziglang pefile
  hello.efi     prints a line and returns EFI_SUCCESS
  fail.efi      prints, then returns EFI_UNSUPPORTED
  crash.efi     prints, then executes ud2 (#UD) - OVMF dumps the exception
  fptr.efi      calls through a table of absolute function pointers
  wrongsub.efi  hello.efi with its PE subsystem patched to Windows CUI (3)
"""
import os
import subprocess
import sys

import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
FLAGS = ["-target", "x86_64-uefi", "-ffreestanding", "-fno-stack-protector",
         "-fno-sanitize=undefined", "-fshort-wchar", "-mno-red-zone", "-nostdlib", "-O1"]
VARIANTS = {
    "hello": [],
    "fail": ["-DEXIT_STATUS=0x8000000000000003ULL"],
    "crash": ["-DCRASH"],
    "fptr": ["-DFPTR_TABLE"],
}

for name, extra in VARIANTS.items():
    out = os.path.join(HERE, name + ".efi")
    subprocess.run([sys.executable, "-m", "ziglang", "cc", *FLAGS, *extra, "-o", out,
                    os.path.join(HERE, "hello.c")], check=True)
    pdb = os.path.join(HERE, name + ".pdb")
    if os.path.exists(pdb):
        os.remove(pdb)

pe = pefile.PE(os.path.join(HERE, "hello.efi"))
pe.OPTIONAL_HEADER.Subsystem = 3  # IMAGE_SUBSYSTEM_WINDOWS_CUI
pe.write(os.path.join(HERE, "wrongsub.efi"))
pe.close()
print("built", ", ".join(n + ".efi" for n in [*VARIANTS, "wrongsub"]))
