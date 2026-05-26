"""Ports of Patch.cpp matchers that emit rdpwrap.ini snippet lines."""

from __future__ import annotations

from .disasm import Decoder, Instruction, Operand


def _fmt(value: int) -> str:
    return f"{value:X}"


def _arch_suffix(decoder: Decoder) -> str:
    return decoder.arch


def _is_reg(operand: Operand | None, *names: str) -> bool:
    return bool(operand and operand.type == "reg" and (not names or operand.reg in names))


def _is_mem(operand: Operand | None) -> bool:
    return bool(operand and operand.type == "mem")


def _is_imm(operand: Operand | None) -> bool:
    return bool(operand and operand.type == "imm")


def _mem_disp(operand: Operand | None) -> int | None:
    return operand.mem_disp if operand and operand.type == "mem" else None


def _mem_base(operand: Operand | None) -> str | None:
    return operand.mem_base if operand and operand.type == "mem" else None


def _reg_name(operand: Operand | None) -> str | None:
    return operand.reg if operand and operand.type == "reg" else None


def _relative_target(instruction: Instruction) -> int | None:
    return instruction.relative_target(0)


def _mem_target(instruction: Instruction, operand_index: int = 0) -> int | None:
    return instruction.mem_target(operand_index)


def _is_relative_call(instruction: Instruction) -> bool:
    operand = instruction.operand(0)
    return instruction.mnemonic == "call" and bool(operand and operand.type == "imm" and operand.is_relative)


def _is_relative_jmp(instruction: Instruction) -> bool:
    operand = instruction.operand(0)
    return instruction.mnemonic == "jmp" and bool(operand and operand.type == "imm" and operand.is_relative)


def _branch_target(instruction: Instruction) -> int | None:
    operand = instruction.operand(0)
    if operand and operand.type == "imm" and operand.is_relative:
        return instruction.relative_target(0)
    return None


def _is_ip_register_operand(instruction: Instruction) -> bool:
    """Compatibility with Zydis relative branch/call operand checks."""

    if len(instruction.operands) < 2:
        return True
    return _is_reg(instruction.operand(1), "rip", "eip")


def local_only_patch(decoder: Decoder, rva: int, target: int) -> list[str]:
    """Port of LocalOnlyPatch."""

    ip = rva
    remaining = 256
    for instruction in decoder.disassemble(ip, remaining):
        ip = instruction.end
        remaining = rva + 256 - ip
        if (
            _is_relative_call(instruction)
            and _is_ip_register_operand(instruction)
            and _relative_target(instruction) == target
        ):
            while True:
                next_instruction = decoder.decode_one(ip, remaining)
                if not next_instruction or next_instruction.mnemonic != "mov":
                    break
                ip = next_instruction.end
                remaining = rva + 256 - ip

            instruction = decoder.decode_one(ip, remaining)
            if not instruction or instruction.mnemonic != "test":
                break
            ip = instruction.end
            remaining = rva + 256 - ip

            instruction = decoder.decode_one(ip, remaining)
            if not instruction or instruction.mnemonic not in {"jns", "js"}:
                break
            branch_target = _branch_target(instruction)
            if branch_target is None:
                break
            if instruction.mnemonic == "jns":
                target_after_branch = instruction.end
                ip = branch_target
                target_cmp_jump = target_after_branch
            else:
                ip = instruction.end
                target_cmp_jump = branch_target
            remaining = rva + 256 - ip

            instruction = decoder.decode_one(ip, remaining)
            if not instruction or instruction.mnemonic != "cmp":
                break
            ip = instruction.end
            remaining = rva + 256 - ip

            instruction = decoder.decode_one(ip, remaining)
            if (
                not instruction
                or instruction.mnemonic != "jz"
                or _branch_target(instruction) != target_cmp_jump
            ):
                break

            code = "nopjmp" if instruction.relative_offset_offset == 2 else "jmpshort"
            suffix = _arch_suffix(decoder)
            return [
                f"LocalOnlyPatch.{suffix}=1",
                f"LocalOnlyOffset.{suffix}={_fmt(instruction.address)}",
                f"LocalOnlyCode.{suffix}={code}",
            ]

    return ["ERROR: LocalOnlyPatch pattern not found"]


def def_policy_patch(decoder: Decoder, rva: int) -> list[str]:
    """Port of DefPolicyPatch, including the 26100.8376 x64 path2 fixes."""

    ip = rva
    remaining = 128
    last_length = 0
    mov_base: str | None = None
    mov_target: str | None = None
    end = rva + 128

    while remaining > 0:
        instruction = decoder.decode_one(ip, remaining)
        if instruction is None:
            break
        inst_length = instruction.size
        op0 = instruction.operand(0)
        op1 = instruction.operand(1)

        if instruction.mnemonic == "cmp":
            reg1: str | None = None
            reg2: str | None = None
            if _is_mem(op0) and _mem_disp(op0) == 0x63C and _is_reg(op1):
                reg1 = _reg_name(op1)
                reg2 = _mem_base(op0)
            elif _is_mem(op1) and _mem_disp(op1) == 0x320 and _is_reg(op0):
                reg1 = _reg_name(op0)
                reg2 = _mem_base(op1)
            else:
                ip += inst_length
                remaining = end - ip
                last_length = inst_length
                continue
            if not reg1 or not reg2:
                break

            next_instruction = decoder.decode_one(ip + inst_length, remaining - inst_length)
            if next_instruction is None:
                break
            jmp = ""
            output_ip = ip
            if next_instruction.mnemonic == "jnz":
                output_ip = ip - last_length
                jmp = "_jmp"
            elif next_instruction.mnemonic not in {"jz", "pop"}:
                break
            suffix = _arch_suffix(decoder)
            return [
                f"DefPolicyPatch.{suffix}=1",
                f"DefPolicyOffset.{suffix}={_fmt(output_ip)}",
                f"DefPolicyCode.{suffix}=CDefPolicy_Query_{reg1}_{reg2}{jmp}",
            ]

        if (
            decoder.arch == "x64"
            and instruction.mnemonic == "mov"
            and _is_reg(op0)
            and _is_mem(op1)
            and _mem_disp(op1) == 0x63C
        ):
            # Current master intentionally refreshes mov_base every time this pattern appears.
            mov_base = _mem_base(op1)
            mov_target = _reg_name(op0)
        elif (
            decoder.arch == "x64"
            and instruction.mnemonic == "mov"
            and _is_reg(op0)
            and _is_mem(op1)
            and mov_base is not None
            and mov_target is not None
            and _mem_base(op1) == mov_base
            and _mem_disp(op1) == 0x638
        ):
            mov_target2 = _reg_name(op0)
            reg1 = mov_target2
            reg2 = _mem_base(op1)
            if not mov_target2 or not reg1 or not reg2:
                break

            offset = inst_length
            while ip + offset < end:
                scan_instruction = decoder.decode_one(ip + offset, end - (ip + offset))
                if scan_instruction is None:
                    break
                offset += scan_instruction.size
                scan0 = scan_instruction.operand(0)
                scan1 = scan_instruction.operand(1)
                if (
                    scan_instruction.mnemonic == "cmp"
                    and _is_reg(scan0)
                    and _is_reg(scan1)
                    and {
                        _reg_name(scan0),
                        _reg_name(scan1),
                    }
                    == {mov_target, mov_target2}
                ):
                    break

            next_instruction = decoder.decode_one(ip + offset, end - (ip + offset))
            if next_instruction is None:
                break
            jmp = ""
            if next_instruction.mnemonic == "jnz":
                jmp = "_jmp"
            elif next_instruction.mnemonic not in {"jz", "pop"}:
                break
            return [
                "DefPolicyPatch.x64=1",
                f"DefPolicyOffset.x64={_fmt(ip)}",
                f"DefPolicyCode.x64=CDefPolicy_Query_{reg1}_{reg2}{jmp}",
            ]

        ip += inst_length
        remaining = end - ip
        last_length = inst_length

    return ["ERROR: DefPolicyPatch pattern not found"]


def single_user_patch(decoder: Decoder, rva: int, target: int, target2: int | None) -> list[str]:
    """Port of SingleUserPatch. Returns an empty list when not found."""

    ip = rva
    end = rva + 256
    while ip < end:
        instruction = decoder.decode_one(ip, end - ip)
        if instruction is None:
            break
        ip = instruction.end
        if not (_is_relative_call(instruction) and _is_ip_register_operand(instruction)):
            continue
        jmp_addr = _relative_target(instruction)
        if jmp_addr is None:
            continue
        jmp_instruction = decoder.decode_one(jmp_addr, end - ip)
        if (
            not jmp_instruction
            or jmp_instruction.mnemonic != "jmp"
            or not _is_mem(jmp_instruction.operand(0))
        ):
            continue
        if not _jmp_mem_matches_target(decoder, jmp_instruction, target):
            continue

        while ip < end:
            instruction = decoder.decode_one(ip, end - ip)
            if instruction is None:
                break
            op0 = instruction.operand(0)
            op1 = instruction.operand(1)
            if decoder.arch == "x64":
                if (
                    target2 is not None
                    and instruction.mnemonic == "call"
                    and 5 <= instruction.size <= 7
                    and _is_mem(op0)
                    and _mem_base(op0) == "rip"
                    and _mem_target(instruction) == target2
                ):
                    return [
                        "SingleUserPatch.x64=1",
                        f"SingleUserOffset.x64={_fmt(instruction.address)}",
                        f"SingleUserCode.x64=mov_eax_1_nop_{instruction.size - 5}",
                    ]
                if (
                    instruction.mnemonic == "cmp"
                    and instruction.size <= 8
                    and _is_mem(op0)
                    and _mem_base(op0) in {"rbp", "rsp"}
                    and (
                        (_is_imm(op1) and op1.imm == 1)
                        or _is_reg(op1)
                    )
                ):
                    return [
                        "SingleUserPatch.x64=1",
                        f"SingleUserOffset.x64={_fmt(instruction.address)}",
                        f"SingleUserCode.x64=nop_{instruction.size}",
                    ]
            else:
                if (
                    target2 is not None
                    and instruction.mnemonic == "call"
                    and 5 <= instruction.size <= 7
                    and _is_mem(op0)
                    and _x86_abs_mem_matches(decoder, op0, target2)
                ):
                    return [
                        "SingleUserPatch.x86=1",
                        f"SingleUserOffset.x86={_fmt(instruction.address)}",
                        f"SingleUserCode.x86=pop_eax_add_esp_12_nop_{instruction.size - 4}",
                    ]
                if (
                    instruction.mnemonic == "cmp"
                    and instruction.size <= 8
                    and _is_mem(op0)
                    and _mem_base(op0) == "ebp"
                    and _is_imm(op1)
                    and op1.imm == 1
                ):
                    return [
                        "SingleUserPatch.x86=1",
                        f"SingleUserOffset.x86={_fmt(instruction.address)}",
                        f"SingleUserCode.x86=nop_{instruction.size}",
                    ]
            ip = instruction.end
        break
    return []


def sl_policy_cp(decoder: Decoder, rva: int) -> bool:
    """Port of the x86-only SLPolicyCP helper from the symbol backend."""

    if decoder.arch != "x86":
        return False
    ip = rva
    end = rva + 128
    while ip < end:
        instruction = decoder.decode_one(ip, end - ip)
        if instruction is None:
            break
        ip = instruction.end
        op0 = instruction.operand(0)
        op1 = instruction.operand(1)
        if (
            instruction.mnemonic == "mov"
            and _is_mem(op1)
            and _mem_base(op1) == "ebp"
            and op1.mem_disp > 0
            and _is_reg(op0)
        ):
            return True
        if instruction.mnemonic == "test":
            break
    return False


def _jmp_mem_matches_target(decoder: Decoder, instruction: Instruction, target: int) -> bool:
    op0 = instruction.operand(0)
    if decoder.arch == "x64":
        return _is_mem(op0) and _mem_base(op0) == "rip" and _mem_target(instruction) == target
    return _is_mem(op0) and _x86_abs_mem_matches(decoder, op0, target)


def _x86_abs_mem_matches(decoder: Decoder, operand: Operand | None, target: int) -> bool:
    if not _is_mem(operand):
        return False
    disp = operand.mem_disp
    image_base = getattr(decoder, "image_base", 0)
    candidates = {target}
    if image_base:
        candidates.add(target + image_base)
        candidates.add(target - image_base)
    return disp in candidates
