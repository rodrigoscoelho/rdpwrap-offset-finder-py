"""Capstone-backed x86/x64 disassembly normalized for the ported matchers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator, Protocol

from .errors import DependencyUnavailable
from .models import Architecture

RELATIVE_BRANCHES = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "je",
    "jg",
    "jge",
    "jl",
    "jle",
    "jna",
    "jnae",
    "jnb",
    "jnbe",
    "jnc",
    "jne",
    "jng",
    "jnge",
    "jnl",
    "jnle",
    "jno",
    "jnp",
    "jns",
    "jnz",
    "jo",
    "jp",
    "jpe",
    "jpo",
    "js",
    "jz",
}


@dataclass(frozen=True)
class Operand:
    """Normalized instruction operand."""

    type: str
    reg: str | None = None
    imm: int | None = None
    mem_base: str | None = None
    mem_index: str | None = None
    mem_segment: str | None = None
    mem_disp: int = 0
    mem_disp_size: int = 0
    size: int = 0
    is_relative: bool = False
    relative_target: int | None = None

    @classmethod
    def reg_op(cls, reg: str, size: int = 0) -> "Operand":
        return cls(type="reg", reg=reg.lower(), size=size)

    @classmethod
    def imm_op(
        cls,
        imm: int,
        *,
        size: int = 0,
        is_relative: bool = False,
        relative_target: int | None = None,
    ) -> "Operand":
        return cls(
            type="imm",
            imm=imm,
            size=size,
            is_relative=is_relative,
            relative_target=relative_target,
        )

    @classmethod
    def mem_op(
        cls,
        *,
        base: str | None = None,
        index: str | None = None,
        segment: str | None = None,
        disp: int = 0,
        disp_size: int | None = None,
        size: int = 0,
    ) -> "Operand":
        return cls(
            type="mem",
            mem_base=base.lower() if base else None,
            mem_index=index.lower() if index else None,
            mem_segment=segment.lower() if segment else None,
            mem_disp=disp,
            mem_disp_size=(1 if disp else 0) if disp_size is None else disp_size,
            size=size,
        )


@dataclass(frozen=True)
class Instruction:
    """Normalized x86/x64 instruction."""

    address: int
    size: int
    mnemonic: str
    operands: tuple[Operand, ...] = ()
    op_str: str = ""
    raw: bytes = b""
    groups: frozenset[str] = field(default_factory=frozenset)
    relative_offset_offset: int | None = None

    @property
    def end(self) -> int:
        return self.address + self.size

    def is_mnemonic(self, *names: str) -> bool:
        return self.mnemonic in {name.lower() for name in names}

    def operand(self, index: int) -> Operand | None:
        try:
            return self.operands[index]
        except IndexError:
            return None

    def relative_target(self, index: int = 0) -> int | None:
        operand = self.operand(index)
        if not operand or operand.type != "imm" or not operand.is_relative:
            return None
        if operand.relative_target is not None:
            return operand.relative_target
        return operand.imm

    def mem_target(self, index: int = 0) -> int | None:
        operand = self.operand(index)
        if not operand or operand.type != "mem":
            return None
        if operand.mem_base in {"rip", "eip"}:
            return self.end + operand.mem_disp
        return operand.mem_disp


class Decoder(Protocol):
    """Protocol consumed by the patch searchers."""

    arch: Architecture
    image_base: int

    def disassemble(self, rva: int, max_length: int) -> Iterator[Instruction]:
        ...

    def decode_one(self, rva: int, max_length: int) -> Instruction | None:
        ...


class Disassembler:
    """Small wrapper around Capstone with lazy import."""

    def __init__(self, arch: Architecture):
        self.arch = arch
        try:
            import capstone
            from capstone import x86
        except Exception as exc:  # pragma: no cover - exercised without dependency in import tests.
            raise DependencyUnavailable(
                "capstone is required for disassembly; install the package dependencies"
            ) from exc

        self._capstone = capstone
        self._x86 = x86
        mode = capstone.CS_MODE_64 if arch == "x64" else capstone.CS_MODE_32
        self._md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self._md.detail = True

    def disasm(self, code: bytes, address: int) -> Iterator[Instruction]:
        for insn in self._md.disasm(code, address):
            yield self._normalize(insn)

    def disasm_one(self, code: bytes, address: int) -> Instruction | None:
        for insn in self.disasm(code, address):
            return insn
        return None

    def _normalize(self, insn: object) -> Instruction:
        capstone = self._capstone
        x86 = self._x86
        mnemonic = _zydis_mnemonic(str(insn.mnemonic).lower())
        groups: set[str] = set()
        if insn.group(capstone.CS_GRP_JUMP):
            groups.add("jump")
        if insn.group(capstone.CS_GRP_CALL):
            groups.add("call")
        if insn.group(capstone.CS_GRP_RET):
            groups.add("ret")

        raw = bytes(insn.bytes)
        relative_offset_offset = _relative_offset(raw)
        operands: list[Operand] = []
        for operand in getattr(insn, "operands", ()):
            if operand.type == x86.X86_OP_REG:
                operands.append(Operand.reg_op(insn.reg_name(operand.reg), size=operand.size))
            elif operand.type == x86.X86_OP_IMM:
                is_relative = mnemonic == "call" or mnemonic in RELATIVE_BRANCHES or mnemonic == "jmp"
                operands.append(
                    Operand.imm_op(
                        int(operand.imm),
                        size=operand.size,
                        is_relative=is_relative,
                        relative_target=int(operand.imm) if is_relative else None,
                    )
                )
            elif operand.type == x86.X86_OP_MEM:
                mem = operand.mem
                base = insn.reg_name(mem.base) if mem.base else None
                index = insn.reg_name(mem.index) if mem.index else None
                segment = insn.reg_name(mem.segment) if mem.segment else None
                disp_size = getattr(insn, "disp_size", None)
                operands.append(
                    Operand.mem_op(
                        base=base,
                        index=index,
                        segment=segment,
                        disp=int(mem.disp),
                        disp_size=disp_size,
                        size=operand.size,
                    )
                )
            else:
                operands.append(Operand(type="other", size=getattr(operand, "size", 0)))

        return Instruction(
            address=int(insn.address),
            size=int(insn.size),
            mnemonic=mnemonic,
            operands=tuple(operands),
            op_str=str(insn.op_str),
            raw=raw,
            groups=frozenset(groups),
            relative_offset_offset=relative_offset_offset,
        )


class SequenceDecoder:
    """Decoder backed by a sorted synthetic instruction list, used in tests."""

    def __init__(
        self,
        instructions: Iterable[Instruction],
        *,
        arch: Architecture = "x64",
        image_base: int = 0,
    ):
        self.arch = arch
        self.image_base = image_base
        self._instructions = {instruction.address: instruction for instruction in instructions}

    def disassemble(self, rva: int, max_length: int) -> Iterator[Instruction]:
        end = rva + max_length
        current = rva
        while current < end:
            instruction = self._instructions.get(current)
            if instruction is None:
                return
            yield instruction
            current = instruction.end

    def decode_one(self, rva: int, max_length: int) -> Instruction | None:
        instruction = self._instructions.get(rva)
        if instruction and instruction.end <= rva + max_length:
            return instruction
        return None


def _zydis_mnemonic(mnemonic: str) -> str:
    """Normalize Capstone aliases to the mnemonics used by Zydis/upstream."""

    if mnemonic == "je":
        return "jz"
    if mnemonic == "jne":
        return "jnz"
    return mnemonic


def _relative_offset(raw: bytes) -> int | None:
    if not raw:
        return None
    first = raw[0]
    if first in {0xE8, 0xE9, 0xEB} or 0x70 <= first <= 0x7F:
        return 1
    if len(raw) >= 2 and first == 0x0F and 0x80 <= raw[1] <= 0x8F:
        return 2
    return None


def is_conditional_jump(instruction: Instruction) -> bool:
    return instruction.mnemonic in RELATIVE_BRANCHES
