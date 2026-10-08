import pytest

from uefi_mcp import edk2


@pytest.mark.parametrize("query", [
    "0x8000000000000003", "0x80000003", "EFI_UNSUPPORTED", "unsupported", "Unsupported",
])
def test_status_forms_agree(query):
    st = edk2.decode_status(query)
    assert st.name == "EFI_UNSUPPORTED" and st.error and st.code == 3
    assert st.value == 0x8000000000000003
    assert st.text == "Unsupported"


def test_status_text_as_logged_by_ovmf():
    assert edk2.decode_status("Not Found").name == "EFI_NOT_FOUND"
    assert edk2.decode_status("Out of Resources").name == "EFI_OUT_OF_RESOURCES"
    assert edk2.decode_status("Success").name == "EFI_SUCCESS"


def test_status_describe_has_hint_and_widths():
    text = edk2.decode_status("EFI_BUFFER_TOO_SMALL").describe()
    assert "0x8000000000000005" in text and "0x80000005" in text
    assert "bigger buffer" in text and "EFI_ERROR(status) is true" in text


def test_warning_and_ambiguous_codes():
    w = edk2.decode_status("0x1")
    assert w.name == "EFI_WARN_UNKNOWN_GLYPH" and not w.error
    with pytest.raises(ValueError, match="ambiguous"):
        edk2.decode_status("6")
    with pytest.raises(KeyError, match="unknown EFI_STATUS"):
        edk2.decode_status("EFI_NOPE")


def test_oem_status_is_flagged_not_named():
    st = edk2.decode_status("0xC000000000000001")
    assert st.oem and st.error and st.name is None
    assert "OEM-defined" in st.describe()


def test_status_from_log_text_handles_hex_and_unknown():
    assert edk2.status_from_log_text("00000001").code == 1
    assert edk2.status_from_log_text("not a status") is None


def test_guid_lookup_names_protocols_and_modules():
    info = edk2.lookup_guid("5b1b31a1-9562-11d2-8e3f-00a0c969723b")
    assert ("gEfiLoadedImageProtocolGuid", "protocol", "MdePkg") in info.names
    mod = edk2.lookup_guid("{2EC9DA37-EE35-4DE9-86C5-6D9A81DC38A7}").module
    assert mod is not None and mod["name"] == "AmdSevDxe"
    with pytest.raises(ValueError, match="not a GUID"):
        edk2.lookup_guid("nope")


def test_search_finds_gop():
    names = [n for n, _ in edk2.search_names("GraphicsOutputProtocol")]
    assert "gEfiGraphicsOutputProtocolGuid" in names


def test_data_provenance_and_license_shipped():
    from importlib import resources
    src = edk2.data()["source"]
    assert src["tag"].startswith("edk2-stable") and len(src["commit"]) == 40
    lic = resources.files("uefi_mcp").joinpath("data/EDK2-LICENSE.txt").read_text(encoding="utf-8")
    assert "BSD-2-Clause-Patent" in lic
