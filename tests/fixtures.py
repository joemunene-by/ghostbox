"""Programmatic, SAFE, benign sample fixtures.

These helpers craft tiny but structurally valid files entirely in memory. They
contain no executable behavior and no real malware. They exist so the analyzers
can be exercised deterministically and offline.
"""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO


def make_pe(*, with_import_name: bytes = b"") -> bytes:
    """Craft a tiny but valid 32-bit PE with one section.

    The headers parse cleanly with the built-in parser. ``with_import_name`` lets
    a test embed a function name string (for capability/string assertions) inside
    the section body without building a real import table.
    """
    # DOS header: 'MZ' + padding, e_lfanew at 0x3C points to the PE header.
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    # COFF file header.
    machine = 0x014C  # IMAGE_FILE_MACHINE_I386
    num_sections = 1
    timestamp = 0x5F000000
    size_opt_header = 0xE0  # standard 32-bit optional header size
    # PE signature followed by the 20-byte COFF file header.
    coff = b"PE\x00\x00" + struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        timestamp,
        0,
        0,
        size_opt_header,
        0,  # Characteristics
    )

    # Optional header (32-bit). Only the fields the parser reads must be sane.
    opt = bytearray(size_opt_header)
    struct.pack_into("<H", opt, 0, 0x010B)  # Magic = PE32
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint

    # Section table: one section named .text.
    section_name = b".text\x00\x00\x00"
    virtual_size = 0x200
    virtual_address = 0x1000
    section_body = b"benign sample body " + with_import_name + b"\x00" * 16
    raw_size = max(0x200, len(section_body))

    headers_len = e_lfanew + len(coff) + size_opt_header
    section_header_off = headers_len
    raw_ptr = section_header_off + 40
    # Align raw_ptr a little so it lands cleanly after the section header.
    raw_ptr = raw_ptr + (16 - (raw_ptr % 16)) % 16

    section_header = struct.pack(
        "<8sIIII",
        section_name,
        virtual_size,
        virtual_address,
        raw_size,
        raw_ptr,
    ) + struct.pack("<IIHHI", 0, 0, 0, 0, 0x60000020)  # relocs/lines/chars

    out = bytearray()
    out += dos
    out += coff
    out += opt
    out += section_header
    # Pad to raw_ptr, then write the section body.
    if len(out) < raw_ptr:
        out += b"\x00" * (raw_ptr - len(out))
    body = section_body + b"\x00" * (raw_size - len(section_body))
    out += body
    return bytes(out)


def make_elf() -> bytes:
    """Craft a tiny but valid 64-bit little-endian ELF with a section table."""
    # ELF header is 64 bytes for ELF64.
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # 64-bit, LE, SysV
    e_type = 2  # EXEC
    e_machine = 0x3E  # x86-64
    e_version = 1
    e_entry = 0x400000
    e_phoff = 0
    e_shoff = 64  # section headers right after the ELF header
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 0
    e_phnum = 0
    e_shentsize = 64
    e_shnum = 3  # null, .text, .shstrtab
    e_shstrndx = 2

    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    )

    # Section header string table content.
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    name_text = shstrtab.index(b".text")
    name_shstr = shstrtab.index(b".shstrtab")

    # Layout: [ehdr 64][shdrs 3*64=192][.text body][shstrtab]
    sh_table_off = e_shoff
    sh_table_size = e_shnum * e_shentsize
    text_off = sh_table_off + sh_table_size
    text_body = b"\x90" * 32  # NOPs as benign filler content
    shstr_off = text_off + len(text_body)

    def shdr(name, sh_type, addr, offset, size) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            name,  # sh_name
            sh_type,  # sh_type
            0,  # sh_flags
            addr,  # sh_addr
            offset,  # sh_offset
            size,  # sh_size
            0,  # sh_link
            0,  # sh_info
            1,  # sh_addralign
            0,  # sh_entsize
        )

    sh_null = shdr(0, 0, 0, 0, 0)
    sh_text = shdr(name_text, 1, e_entry, text_off, len(text_body))  # PROGBITS
    sh_shstr = shdr(name_shstr, 3, 0, shstr_off, len(shstrtab))  # STRTAB

    out = header + sh_null + sh_text + sh_shstr + text_body + shstrtab
    return out


def make_pdf() -> bytes:
    """A minimal, benign PDF document."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<< /Type /Catalog >>endobj\n"
        b"trailer<< /Root 1 0 R >>\n"
        b"%%EOF\n"
    )


def make_ooxml() -> bytes:
    """A minimal benign OOXML (docx-like) zip container."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<document>benign</document>")
    return buf.getvalue()


def make_ole() -> bytes:
    """A minimal OLE2 compound document header (legacy Office signature)."""
    return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512


def make_script_with_iocs() -> bytes:
    """A benign shell script containing extractable IOCs and capability hints."""
    return (
        b"#!/bin/sh\n"
        b"# benign test sample, do not run\n"
        b"URL=http://malicious.example.com/payload.bin\n"
        b"C2=203.0.113.45\n"
        b"DOMAIN=evil-domain.top\n"
        b"REPORT=admin@evil-domain.top\n"
        b"REG=HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        b"echo powershell -enc ABCD\n"
        b"echo schtasks /create\n"
        b"echo your files have been encrypted\n"
    )


def make_high_entropy(size: int = 4096) -> bytes:
    """Deterministic high-entropy bytes (not random, but near-uniform)."""
    # Repeating 0..255 yields entropy of exactly 8.0 bits/byte.
    return bytes(i % 256 for i in range(size))
