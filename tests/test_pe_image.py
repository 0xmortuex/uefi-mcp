import os

import pytest

from uefi_mcp import pe_image

APPS = os.path.join(os.path.dirname(__file__), "fixtures", "apps")


def app(name):
    return os.path.join(APPS, name)


def test_good_app_has_no_problems_but_notes_missing_relocs():
    text = pe_image.analyze(app("hello.efi"))
    assert "machine x64, subsystem 10 (EFI application)" in text
    assert "No loading problems found." in text
    assert "no base relocations. That's fine only if" in text
    assert "\\EFI\\BOOT\\BOOTX64.EFI" in text


def test_wrong_subsystem_is_a_problem():
    text = pe_image.analyze(app("wrongsub.efi"))
    assert "NOT an EFI subsystem (3)" in text and "PROBLEMS:" in text
    assert "/subsystem:efi_application" in text


def test_relocs_stripped_is_a_problem():
    text = pe_image.analyze(app("stripped.efi"))
    assert "IMAGE_FILE_RELOCS_STRIPPED is set" in text and "Invalid Parameter" in text


def test_image_with_relocations_is_clean():
    text = pe_image.analyze(app("fptr.efi"))
    assert "base relocations: 2 fixup(s)" in text and "No loading problems found." in text
    assert "Notes:" not in text


def test_disassemble_marks_the_faulting_instruction():
    text = pe_image.disassemble(app("crash.efi"), 0x1012, count=2, before=1)
    assert "=> 0x001012 entry+0x12   ud2" in text


def test_disassemble_errors_are_specific(tmp_path):
    with pytest.raises(pe_image.ImageError, match="outside every section"):
        pe_image.disassemble(app("crash.efi"), 0x90000)
    with pytest.raises(pe_image.ImageError, match="isn't executable"):
        pe_image.disassemble(app("crash.efi"), 0x2000)
    with pytest.raises(pe_image.ImageError, match="not on an instruction boundary"):
        pe_image.disassemble(app("crash.efi"), 0x1013)
    junk = tmp_path / "junk.efi"
    junk.write_bytes(b"not a pe file at all")
    with pytest.raises(pe_image.ImageError, match="not a PE/COFF image"):
        pe_image.analyze(str(junk))
    with pytest.raises(FileNotFoundError):
        pe_image.analyze(str(tmp_path / "missing.efi"))
