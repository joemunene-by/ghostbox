from ghostbox.analyzers.filetype import detect
from tests import fixtures


def test_detect_pe(pe_bytes):
    assert detect(pe_bytes)["type"] == "pe"


def test_detect_elf(elf_bytes):
    assert detect(elf_bytes)["type"] == "elf"


def test_detect_pdf(pdf_bytes):
    assert detect(pdf_bytes)["type"] == "pdf"


def test_detect_ooxml(ooxml_bytes):
    result = detect(ooxml_bytes)
    assert result["type"] == "office"
    assert result["subtype"] == "ooxml"


def test_detect_ole(ole_bytes):
    result = detect(ole_bytes)
    assert result["type"] == "office"
    assert result["subtype"] == "ole"


def test_detect_script(script_bytes):
    assert detect(script_bytes)["type"] == "script"


def test_detect_macho():
    data = b"\xcf\xfa\xed\xfe" + b"\x00" * 64
    assert detect(data)["type"] == "macho"


def test_detect_empty():
    assert detect(b"")["type"] == "empty"


def test_detect_zip_archive():
    # Bare zip without OOXML markers should be an archive.
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hello")
    assert detect(buf.getvalue())["type"] == "archive"


def test_detect_high_entropy_unknown():
    data = fixtures.make_high_entropy(2048)
    # No magic match; near-uniform binary -> unknown (not text).
    assert detect(data)["type"] in {"unknown", "macho"}
