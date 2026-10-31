import struct

import pytest

from safeshell import runtime


def test_elf_parser_rejects_untrusted_forms():
    for data in (b"", b"not an ELF", b"\x7fELF\x01\x01" + b"\0" * 100):
        with pytest.raises(ValueError):
            runtime.elf_dependencies(data)


def test_elf_parser_rejects_out_of_bounds_headers():
    data = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01" + b"\0" * 10,
        2,
        62,
        1,
        0,
        99999,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    with pytest.raises(ValueError, match="headers"):
        runtime.elf_dependencies(data)


def test_static_elf_needs_no_host_command():
    data = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01" + b"\0" * 10,
        2,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        0,
        0,
        0,
        0,
    )
    assert runtime.elf_dependencies(data) == ([], None)
