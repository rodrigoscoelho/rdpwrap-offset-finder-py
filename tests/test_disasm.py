from __future__ import annotations

import pytest

pytest.importorskip("capstone")

from rdpwrap_offset_finder.disasm import Disassembler


def test_capstone_disassembler_normalizes_zydis_jump_aliases() -> None:
    disasm = Disassembler("x64")

    # 75 02 is encoded as JNZ/JNE. Capstone prints "jne", upstream Zydis
    # logic expects JNZ, so the normalization layer must make it look like Zydis.
    instruction = disasm.disasm_one(b"\x75\x02", 0x1000)

    assert instruction is not None
    assert instruction.mnemonic == "jnz"
    assert instruction.relative_target() == 0x1004


def test_capstone_disassembler_normalizes_rip_memory_targets() -> None:
    disasm = Disassembler("x64")

    # lea rcx, [rip + 0x1234]
    instruction = disasm.disasm_one(b"\x48\x8d\x0d\x34\x12\x00\x00", 0x2000)

    assert instruction is not None
    assert instruction.mnemonic == "lea"
    assert instruction.mem_target(1) == 0x2007 + 0x1234
