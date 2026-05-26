from __future__ import annotations

from rdpwrap_offset_finder.disasm import Instruction, Operand, SequenceDecoder
from rdpwrap_offset_finder.patches import def_policy_patch


def test_def_policy_x64_path2_refreshes_mov_base_for_26100_8376() -> None:
    decoder = SequenceDecoder(
        [
            Instruction(
                address=0x1000,
                size=4,
                mnemonic="mov",
                operands=(
                    Operand.reg_op("r8d"),
                    Operand.mem_op(base="rax", disp=0x63C),
                ),
            ),
            Instruction(
                address=0x1004,
                size=4,
                mnemonic="mov",
                operands=(
                    Operand.reg_op("r9d"),
                    Operand.mem_op(base="rdi", disp=0x63C),
                ),
            ),
            Instruction(
                address=0x1008,
                size=4,
                mnemonic="mov",
                operands=(
                    Operand.reg_op("ecx"),
                    Operand.mem_op(base="rdi", disp=0x638),
                ),
            ),
            Instruction(
                address=0x100C,
                size=2,
                mnemonic="cmp",
                operands=(
                    Operand.reg_op("r9d"),
                    Operand.reg_op("ecx"),
                ),
            ),
            Instruction(address=0x100E, size=2, mnemonic="jnz"),
        ],
        arch="x64",
    )

    lines = def_policy_patch(decoder, 0x1000)

    assert lines == [
        "DefPolicyPatch.x64=1",
        "DefPolicyOffset.x64=1008",
        "DefPolicyCode.x64=CDefPolicy_Query_ecx_rdi_jmp",
    ]


def test_def_policy_x64_path2_does_not_regress_ip_on_jnz() -> None:
    decoder = SequenceDecoder(
        [
            Instruction(
                address=0x2000,
                size=5,
                mnemonic="mov",
                operands=(
                    Operand.reg_op("eax"),
                    Operand.mem_op(base="rdi", disp=0x63C),
                ),
            ),
            Instruction(
                address=0x2005,
                size=3,
                mnemonic="mov",
                operands=(
                    Operand.reg_op("r9d"),
                    Operand.mem_op(base="rdi", disp=0x638),
                ),
            ),
            Instruction(
                address=0x2008,
                size=2,
                mnemonic="cmp",
                operands=(
                    Operand.reg_op("eax"),
                    Operand.reg_op("r9d"),
                ),
            ),
            Instruction(address=0x200A, size=2, mnemonic="jnz"),
        ],
        arch="x64",
    )

    lines = def_policy_patch(decoder, 0x2000)

    assert "DefPolicyOffset.x64=2005" in lines
    assert "DefPolicyOffset.x64=2000" not in lines
