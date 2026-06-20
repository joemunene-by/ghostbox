"""Shared pytest fixtures built on the programmatic sample crafters."""

from __future__ import annotations

import pytest

from tests import fixtures


@pytest.fixture
def pe_bytes() -> bytes:
    return fixtures.make_pe(with_import_name=b"VirtualAlloc")


@pytest.fixture
def elf_bytes() -> bytes:
    return fixtures.make_elf()


@pytest.fixture
def pdf_bytes() -> bytes:
    return fixtures.make_pdf()


@pytest.fixture
def ooxml_bytes() -> bytes:
    return fixtures.make_ooxml()


@pytest.fixture
def ole_bytes() -> bytes:
    return fixtures.make_ole()


@pytest.fixture
def script_bytes() -> bytes:
    return fixtures.make_script_with_iocs()
