"""Pure-Python no-symbol backend ported from RDPWrapOffsetFinder_nosym.cpp."""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .disasm import Decoder, Instruction, is_conditional_jump
from .errors import FinderError, PEFormatError
from .models import FinderResult, ImportFunction, RuntimeFunction
from .patches import def_policy_patch, local_only_patch, single_user_patch
from .pe_image import PEImage, RangeSet

QUERY = "CDefPolicy::Query"
LOCAL_ONLY = "CSLQuery::IsTerminalTypeLocalOnly"
SINGLE_SESSION_ENABLED = "CSessionArbitrationHelper::IsSingleSessionPerUserEnabled"
INSTANCE_OF_LICENSE = "CEnforcementCore::GetInstanceOfTSLicense "

ALLOW_REMOTE = "TerminalServices-RemoteConnectionManager-AllowRemoteConnections"
ALLOW_MULTIPLE_SESSIONS = "TerminalServices-RemoteConnectionManager-AllowMultipleSessions"
ALLOW_APP_SERVER = "TerminalServices-RemoteConnectionManager-AllowAppServerMode"
ALLOW_MULTIMON = "TerminalServices-RemoteConnectionManager-AllowMultimon"
MAX_USER_SESSIONS = "TerminalServices-RemoteConnectionManager-MaxUserSessions"
MAX_DEBUG_SESSIONS = (
    "TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions"
)

RUNTIME_FUNCTION_INDIRECT = 0x1
UNW_FLAG_CHAININFO = 0x4


@dataclass
class MinHeap:
    """Small min-heap wrapper mirroring the C helper API."""

    _data: list[int] = field(default_factory=list)

    def push(self, value: int) -> None:
        heapq.heappush(self._data, value)

    def pop(self) -> int:
        return heapq.heappop(self._data)

    def clear(self) -> None:
        self._data.clear()

    @property
    def size(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return bool(self._data)


@dataclass
class DiscoveredSymbols:
    cdefpolicy_query: int = 0
    get_instance_of_license: int = 0
    single_session_enabled: int = 0
    single_session_per_user: int = 0
    license_type_local_only: int = 0
    cslquery_initialize: int = 0
    cslquery_initialize_len: int = 0x11000
    b_remote_conn_allowed_xref: int = 0
    win8_sl_func: str = "New_Win8SL"


def find_offsets(path: str | Path) -> FinderResult:
    """Run the no-symbol backend and return generated rdpwrap.ini snippet lines."""

    image = PEImage(path)
    finder = NoSymbolFinder(image)
    lines = finder.run()
    return FinderResult(
        backend="nosymbol",
        termsrv_path=image.path,
        architecture=image.architecture,
        version=image.version,
        lines=tuple(lines),
    )


class NoSymbolFinder:
    def __init__(self, image: PEImage):
        self.image = image
        self.decoder = image.decoder()
        self.arch = image.architecture

    def run(self) -> list[str]:
        symbols = self._discover_symbols()
        lines: list[str] = [f"[{self.image.version}]"]

        memset = self._find_memset()
        verify_version = self._find_verify_version_info()
        if memset is not None:
            single_user_rva = symbols.single_session_enabled or symbols.single_session_per_user
            if single_user_rva:
                target = memset.iat_rva if self.arch == "x64" else memset.iat_va
                target2 = None
                if verify_version is not None:
                    target2 = verify_version.iat_rva if self.arch == "x64" else verify_version.iat_va
                single_user = single_user_patch(self.decoder, single_user_rva, target, target2)
                if single_user:
                    lines.extend(single_user)
                elif symbols.single_session_per_user:
                    lines.append("ERROR: SingleUserPatch not found")

        if symbols.cdefpolicy_query:
            lines.extend(def_policy_patch(self.decoder, symbols.cdefpolicy_query))
        else:
            lines.append("ERROR: CDefPolicy_Query not found")

        if self.image.version.ms <= 0x00060001:
            return lines

        if not symbols.cslquery_initialize:
            lines.append("ERROR: CSLQuery_Initialize not found")
            return lines

        if self.image.version.ms == 0x00060002:
            lines.extend(self._emit_win8_sl_policy(symbols))
            return lines

        if symbols.get_instance_of_license:
            if symbols.license_type_local_only:
                lines.extend(
                    local_only_patch(
                        self.decoder,
                        symbols.get_instance_of_license,
                        symbols.license_type_local_only,
                    )
                )
            else:
                lines.append("ERROR: IsLicenseTypeLocalOnly not found")
        else:
            lines.append("ERROR: GetInstanceOfTSLicense not found")

        suffix = self.arch
        lines.extend(
            [
                f"SLInitHook.{suffix}=1",
                f"SLInitOffset.{suffix}={symbols.cslquery_initialize:X}",
                f"SLInitFunc.{suffix}=New_CSLQuery_Initialize",
                "",
                f"[{self.image.version}-SLInit]",
            ]
        )
        variables = self._discover_slinit_variables(symbols)
        for name in (
            "bServerSku",
            "bRemoteConnAllowed",
            "bFUSEnabled",
            "bAppServerAllowed",
            "bMultimonAllowed",
            "lMaxUserSessions",
            "ulMaxDebugSessions",
            "bInitialized",
        ):
            value = variables.get(name, 0)
            if value:
                lines.append(f"{name}.{suffix}={value:X}")
            else:
                lines.append(f"ERROR: {name} not found")
        return lines

    def _discover_symbols(self) -> DiscoveredSymbols:
        rdata = self.image.rdata_section
        cdefpolicy_query = _expect(self.image.find_ascii(QUERY, rdata), QUERY)
        get_instance = _expect(self.image.find_ascii(INSTANCE_OF_LICENSE, rdata), INSTANCE_OF_LICENSE)
        single_enabled = _expect(
            self.image.find_ascii(SINGLE_SESSION_ENABLED, rdata),
            SINGLE_SESSION_ENABLED,
        )
        single_per_user = self.image.find_ascii("IsSingleSessionPerUser", rdata, include_nul=True)
        if single_per_user is None:
            raise FinderError("IsSingleSessionPerUser marker not found")
        if self.image.read_rva(single_per_user - 8, 8) == b"CUtils::":
            single_per_user -= 8
        local_only = _expect(self.image.find_ascii(LOCAL_ONLY, rdata), LOCAL_ONLY)
        b_remote = _expect(self.image.find_utf16(ALLOW_REMOTE, rdata), ALLOW_REMOTE)

        symbols = DiscoveredSymbols()
        if self.arch == "x64":
            self._discover_x64_symbols(
                symbols,
                cdefpolicy_query,
                get_instance,
                single_enabled,
                single_per_user,
                local_only,
                b_remote,
            )
        else:
            self._discover_x86_symbols(
                symbols,
                cdefpolicy_query,
                get_instance,
                single_enabled,
                single_per_user,
                local_only,
                b_remote,
            )
        return symbols

    def _discover_x64_symbols(
        self,
        symbols: DiscoveredSymbols,
        cdefpolicy_query: int | None,
        get_instance: int | None,
        single_enabled: int | None,
        single_per_user: int,
        local_only: int | None,
        b_remote: int | None,
    ) -> None:
        runtime_functions = self.image.runtime_functions()
        if not runtime_functions:
            raise PEFormatError("x64 exception/runtime function table not found")

        for runtime_function in runtime_functions:
            if not symbols.cdefpolicy_query and cdefpolicy_query is not None:
                if search_xref(self.decoder, runtime_function, cdefpolicy_query):
                    symbols.cdefpolicy_query = self._backtrace(runtime_function).begin
            elif not symbols.get_instance_of_license and get_instance is not None:
                if search_xref(self.decoder, runtime_function, get_instance):
                    symbols.get_instance_of_license = self._backtrace(runtime_function).begin
            elif not symbols.single_session_enabled and single_enabled is not None:
                if search_xref(self.decoder, runtime_function, single_enabled):
                    symbols.single_session_enabled = self._backtrace(runtime_function).begin
            elif not symbols.single_session_per_user:
                if search_xref(self.decoder, runtime_function, single_per_user):
                    symbols.single_session_per_user = self._backtrace(runtime_function).begin
            elif not symbols.license_type_local_only and local_only is not None:
                if search_xref(self.decoder, runtime_function, local_only):
                    symbols.license_type_local_only = self._backtrace(runtime_function).begin
            elif not symbols.cslquery_initialize and b_remote is not None:
                xref = search_xref(self.decoder, runtime_function, b_remote)
                if xref:
                    init_function = self._backtrace(runtime_function)
                    symbols.cslquery_initialize = init_function.begin
                    symbols.cslquery_initialize_len = init_function.end - init_function.begin
                    symbols.b_remote_conn_allowed_xref = xref

            if (
                symbols.cdefpolicy_query
                and symbols.get_instance_of_license
                and symbols.single_session_enabled
                and symbols.single_session_per_user
                and symbols.license_type_local_only
                and symbols.cslquery_initialize
            ):
                break

    def _discover_x86_symbols(
        self,
        symbols: DiscoveredSymbols,
        cdefpolicy_query: int | None,
        get_instance: int | None,
        single_enabled: int | None,
        single_per_user: int,
        local_only: int | None,
        b_remote: int | None,
    ) -> None:
        text = self.image.text_section
        visited = RangeSet()
        heap = MinHeap()
        ip = text.virtual_address
        end = text.virtual_address + text.raw_size

        while ip + 5 <= end:
            if self.image.read_rva(ip, 5) == b"\x8B\xFF\x55\x8B\xEC":
                function_start = ip
                heap.push(ip)

                while heap:
                    addr = heap.pop()
                    if visited.contains(addr):
                        continue
                    block = addr
                    current = block
                    block_end = text.virtual_address + text.raw_size
                    while current < block_end:
                        instruction = self.decoder.decode_one(current, block_end - current)
                        if instruction is None:
                            break
                        current = instruction.end

                        target = self._x86_immediate_string_target(instruction)
                        if target is not None:
                            if not symbols.cdefpolicy_query and target == cdefpolicy_query:
                                symbols.cdefpolicy_query = function_start
                            elif not symbols.get_instance_of_license and target == get_instance:
                                symbols.get_instance_of_license = function_start
                            elif not symbols.single_session_enabled and target == single_enabled:
                                symbols.single_session_enabled = function_start
                            elif not symbols.single_session_per_user and target == single_per_user:
                                symbols.single_session_per_user = function_start
                            elif not symbols.license_type_local_only and target == local_only:
                                symbols.license_type_local_only = function_start
                            elif not symbols.cslquery_initialize and target == b_remote:
                                if instruction.mnemonic == "push":
                                    symbols.win8_sl_func = "New_Win8SL_CP"
                                symbols.b_remote_conn_allowed_xref = current
                                symbols.cslquery_initialize = function_start
                            else:
                                target = None

                            if target is not None:
                                if not visited.ranges:
                                    visited.add(addr, current)
                                heap.clear()
                                if (
                                    symbols.cdefpolicy_query
                                    and symbols.get_instance_of_license
                                    and symbols.single_session_enabled
                                    and symbols.single_session_per_user
                                    and symbols.license_type_local_only
                                    and symbols.cslquery_initialize
                                ):
                                    return
                                break

                        if is_conditional_jump(instruction) and instruction.operand(0):
                            jump_target = instruction.relative_target(0)
                            if (
                                jump_target is not None
                                and (jump_target < addr or jump_target > current)
                                and not visited.contains(jump_target)
                            ):
                                heap.push(jump_target)
                        if instruction.mnemonic in {"ret", "jmp"}:
                            visited.add(addr, current)
                            break

                next_ip = visited.next_value(function_start)
                visited.clear()
                ip = next_ip if next_ip > function_start else function_start + 1
            else:
                ip += 1

    def _emit_win8_sl_policy(self, symbols: DiscoveredSymbols) -> list[str]:
        ip = symbols.b_remote_conn_allowed_xref
        end = ip + symbols.cslquery_initialize_len
        while ip < end:
            instruction = self.decoder.decode_one(ip, end - ip)
            if instruction is None:
                break
            ip = instruction.end
            if instruction.mnemonic == "call" and instruction.operand(0) and instruction.operand(0).is_relative:
                target = instruction.relative_target(0)
                if target is None:
                    break
                suffix = self.arch
                return [
                    f"SLPolicyInternal.{suffix}=1",
                    f"SLPolicyOffset.{suffix}={target:X}",
                    f"SLPolicyFunc.{suffix}={symbols.win8_sl_func}",
                ]
        return ["ERROR: SLGetWindowsInformationDWORDWrapper not found"]

    def _discover_slinit_variables(self, symbols: DiscoveredSymbols) -> dict[str, int]:
        strings = self._slinit_policy_string_rvas()
        variables = {
            "bServerSku": 0,
            "bRemoteConnAllowed": 0,
            "bFUSEnabled": 0,
            "bAppServerAllowed": 0,
            "bMultimonAllowed": 0,
            "lMaxUserSessions": 0,
            "ulMaxDebugSessions": 0,
            "bInitialized": 0,
        }
        current = "bServerSku"
        ip = symbols.cslquery_initialize
        length = symbols.cslquery_initialize_len

        if self.arch == "x86":
            end = ip + length
            while ip < end:
                instruction = self.decoder.decode_one(ip, end - ip)
                if instruction is None:
                    break
                ip = instruction.end
                op0 = instruction.operand(0)
                op1 = instruction.operand(1)
                if (
                    not variables[current]
                    and instruction.mnemonic == "mov"
                    and op0
                    and op0.type == "mem"
                    and op0.mem_base is None
                    and op0.mem_disp_size != 0
                    and op1
                    and op1.type == "reg"
                    and op1.reg in {"eax", "edi", "esi"}
                ):
                    variables[current] = op0.mem_disp - self.image.image_base
                elif (
                    instruction.mnemonic == "mov"
                    and op0
                    and op0.type == "mem"
                    and op0.mem_base is None
                    and op0.mem_disp_size != 0
                    and op1
                    and op1.type == "imm"
                    and op1.imm == 1
                ):
                    variables["bInitialized"] = op0.mem_disp - self.image.image_base
                    break
                elif instruction.size == 5:
                    target = self._x86_immediate_string_target(instruction)
                    if target is not None:
                        current = _string_target_to_variable(strings, target) or current
            return variables

        if length > 0x100:
            self._discover_slinit_variables_x64_long(symbols, variables, strings)
        else:
            self._discover_slinit_variables_x64_short(symbols, variables, strings)
        return variables

    def _discover_slinit_variables_x64_long(
        self,
        symbols: DiscoveredSymbols,
        variables: dict[str, int],
        strings: dict[str, int | None],
    ) -> None:
        current = "bServerSku"
        ip = symbols.cslquery_initialize
        end = ip + symbols.cslquery_initialize_len
        while ip < end:
            instruction = self.decoder.decode_one(ip, end - ip)
            if instruction is None:
                break
            ip = instruction.end
            op0 = instruction.operand(0)
            op1 = instruction.operand(1)
            if (
                not variables[current]
                and instruction.mnemonic == "mov"
                and op0
                and op0.type == "mem"
                and op0.mem_base == "rip"
                and op0.mem_disp_size != 0
                and op1
                and op1.type == "reg"
                and op1.reg == "eax"
            ):
                variables[current] = instruction.mem_target(0) or 0
            elif (
                instruction.mnemonic == "lea"
                and op0
                and op0.type == "reg"
                and op0.reg == "rcx"
                and op1
                and op1.type == "mem"
                and op1.mem_base == "rip"
                and op1.mem_disp_size != 0
            ):
                target = instruction.mem_target(1)
                if target is not None:
                    current = _string_target_to_variable(strings, target) or current
            elif (
                instruction.mnemonic == "mov"
                and op0
                and op0.type == "mem"
                and op0.mem_base == "rip"
                and op0.mem_disp_size != 0
                and op1
                and op1.type == "imm"
                and op1.imm == 1
            ):
                variables["bInitialized"] = instruction.mem_target(0) or 0
                break

    def _discover_slinit_variables_x64_short(
        self,
        symbols: DiscoveredSymbols,
        variables: dict[str, int],
        strings: dict[str, int | None],
    ) -> None:
        current = "bServerSku"
        ip = symbols.cslquery_initialize
        end = ip + 0x11000
        while ip < end:
            instruction = self.decoder.decode_one(ip, end - ip)
            if instruction is None:
                break
            next_ip = instruction.end
            op0 = instruction.operand(0)
            op1 = instruction.operand(1)
            if instruction.mnemonic == "jmp" and op0 and op0.type == "imm" and op0.is_relative:
                target = instruction.relative_target(0)
                if target is not None:
                    next_ip = target
            elif (
                not variables[current]
                and instruction.mnemonic == "mov"
                and op0
                and op0.type == "mem"
                and op0.mem_base == "rip"
                and op0.mem_disp_size != 0
                and op1
                and op1.type == "reg"
            ):
                variables[current] = instruction.mem_target(0) or 0
            elif (
                instruction.mnemonic == "lea"
                and op0
                and op0.type == "reg"
                and op0.reg == "rdx"
                and op1
                and op1.type == "mem"
                and op1.mem_base == "rip"
                and op1.mem_disp_size != 0
            ):
                target = instruction.mem_target(1)
                if target is not None:
                    current = _string_target_to_variable(strings, target) or current
            elif (
                instruction.mnemonic == "mov"
                and op0
                and op0.type == "mem"
                and op0.mem_base == "rip"
                and op0.mem_disp_size != 0
                and op1
                and op1.type == "reg"
                and op1.reg in {"eax", "ecx"}
            ):
                variables["bInitialized"] = instruction.mem_target(0) or 0
            elif instruction.mnemonic == "ret":
                break
            ip = next_ip

    def _slinit_policy_string_rvas(self) -> dict[str, int | None]:
        rdata = self.image.rdata_section
        return {
            "bRemoteConnAllowed": self.image.find_utf16(ALLOW_REMOTE, rdata),
            "bFUSEnabled": self.image.find_utf16(ALLOW_MULTIPLE_SESSIONS, rdata),
            "bAppServerAllowed": self.image.find_utf16(ALLOW_APP_SERVER, rdata),
            "bMultimonAllowed": self.image.find_utf16(ALLOW_MULTIMON, rdata),
            "lMaxUserSessions": self.image.find_utf16(MAX_USER_SESSIONS, rdata),
            "ulMaxDebugSessions": self.image.find_utf16(MAX_DEBUG_SESSIONS, rdata),
        }

    def _x86_immediate_string_target(self, instruction: Instruction) -> int | None:
        op0 = instruction.operand(0)
        op1 = instruction.operand(1)
        imm: int | None = None
        if instruction.size == 5 and instruction.mnemonic == "push" and op0 and op0.type == "imm":
            imm = op0.imm
        elif (
            instruction.mnemonic == "mov"
            and op1
            and op1.type == "imm"
            and (
                (op0 and op0.type == "reg" and instruction.size == 5)
                or (
                    op0
                    and op0.type == "mem"
                    and instruction.size >= 7
                    and op0.mem_base in {"ebp", "esp"}
                )
            )
        ):
            imm = op1.imm
        if imm is None:
            return None
        return imm - self.image.image_base

    def _find_memset(self) -> ImportFunction | None:
        return self.image.find_import_function(
            ("api-ms-win-crt-string-l1-1-0.dll", "msvcrt.dll"),
            "memset",
        )

    def _find_verify_version_info(self) -> ImportFunction | None:
        return self.image.find_import_function(
            ("api-ms-win-core-kernel32-legacy-l1-1-1.dll", "KERNEL32.dll"),
            "VerifyVersionInfoW",
        )

    def _backtrace(self, runtime_function: RuntimeFunction) -> RuntimeFunction:
        current = runtime_function
        if current.unwind_data & RUNTIME_FUNCTION_INDIRECT:
            current = self._runtime_function_from_rva(current.unwind_data & ~3)

        unwind = self.image.unwind_info(current.unwind_data)
        while unwind.flags & UNW_FLAG_CHAININFO:
            current = self.image.chained_runtime_function(unwind)
            unwind = self.image.unwind_info(current.unwind_data)
        return current

    def _runtime_function_from_rva(self, rva: int) -> RuntimeFunction:
        data = self.image.read_rva(rva, 12)
        if len(data) != 12:
            raise PEFormatError(f"cannot read runtime function at RVA 0x{rva:X}")
        import struct

        return RuntimeFunction(*struct.unpack("<III", data))


def search_xref(decoder: Decoder, runtime_function: RuntimeFunction, target: int) -> int:
    """Search a function for `lea reg, [rip+target]` and return IP after the LEA."""

    ip = runtime_function.begin
    end = runtime_function.end
    while ip < end:
        instruction = decoder.decode_one(ip, end - ip)
        if instruction is None:
            break
        ip = instruction.end
        op0 = instruction.operand(0)
        op1 = instruction.operand(1)
        if (
            instruction.mnemonic == "lea"
            and op0
            and op0.type == "reg"
            and op1
            and op1.type == "mem"
            and op1.mem_base == "rip"
            and instruction.mem_target(1) == target
        ):
            return ip
    return 0


def _expect(value: int | None, _name: str) -> int | None:
    # Upstream keeps going for most missing string markers and later emits per-feature errors.
    return value


def _string_target_to_variable(strings: dict[str, int | None], target: int) -> str | None:
    for variable, rva in strings.items():
        if rva == target:
            return variable
    return None
