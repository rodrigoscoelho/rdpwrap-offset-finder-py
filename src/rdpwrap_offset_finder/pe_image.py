"""PE image helpers used by both finder backends."""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .disasm import Disassembler, Instruction
from .errors import DependencyUnavailable, PEFormatError
from .models import Architecture, ImportFunction, RuntimeFunction, Section, VersionInfo

IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B


def import_pefile():
    try:
        import pefile
    except Exception as exc:  # pragma: no cover - depends on local environment.
        raise DependencyUnavailable(
            "pefile is required for PE parsing; install the package dependencies"
        ) from exc
    return pefile


def strip_section_name(raw: bytes | str) -> str:
    if isinstance(raw, str):
        return raw.split("\x00", 1)[0]
    return raw.rstrip(b"\x00").decode("ascii", errors="replace")


def rva_to_file_offset_from_sections(rva: int, sections: Iterable[Section]) -> int | None:
    """Map an RVA to a raw file offset using PE section headers."""

    for section in sections:
        if section.contains_rva(rva):
            return section.raw_address + (rva - section.virtual_address)
    return None


def normalize_dll_name(name: str | bytes) -> str:
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="replace")
    return name.lower()


@dataclass(frozen=True)
class UnwindInfo:
    flags: int
    count_of_codes: int
    chain_entry_offset: int


class PEImage:
    """Mapped-image abstraction for termsrv.dll."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        pefile = import_pefile()
        try:
            self.pe = pefile.PE(str(self.path), fast_load=False)
        except Exception as exc:
            raise PEFormatError(f"failed to parse PE image {self.path}: {exc}") from exc

        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.size_of_image = int(self.pe.OPTIONAL_HEADER.SizeOfImage)
        self.sections = tuple(
            Section(
                name=strip_section_name(section.Name),
                virtual_address=int(section.VirtualAddress),
                virtual_size=int(section.Misc_VirtualSize),
                raw_address=int(section.PointerToRawData),
                raw_size=int(section.SizeOfRawData),
            )
            for section in self.pe.sections
        )
        self._file_data = self.path.read_bytes()
        self._mapped = self._build_mapped_image()
        self._version: VersionInfo | None = None

    @property
    def architecture(self) -> Architecture:
        magic = int(self.pe.OPTIONAL_HEADER.Magic)
        if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return "x64"
        if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return "x86"
        raise PEFormatError(f"unsupported PE optional header magic: 0x{magic:X}")

    @property
    def text_section(self) -> Section:
        return self.get_section(".text") or self.sections[0]

    @property
    def rdata_section(self) -> Section:
        return self.get_section(".rdata") or self.text_section

    @property
    def version(self) -> VersionInfo:
        if self._version is None:
            self._version = self._read_version()
        return self._version

    def get_section(self, name: str) -> Section | None:
        wanted = name.lower()
        for section in self.sections:
            if section.name.lower() == wanted:
                return section
        return None

    def rva_to_offset(self, rva: int) -> int:
        offset = rva_to_file_offset_from_sections(rva, self.sections)
        if offset is None:
            size_of_headers = int(self.pe.OPTIONAL_HEADER.SizeOfHeaders)
            if 0 <= rva < size_of_headers:
                return rva
            raise PEFormatError(f"RVA 0x{rva:X} is not mapped by any section")
        return offset

    def read_rva(self, rva: int, size: int) -> bytes:
        if size <= 0:
            return b""
        end = min(rva + size, len(self._mapped))
        if rva < 0 or rva >= len(self._mapped):
            return b""
        return bytes(self._mapped[rva:end])

    def read_u32(self, rva: int) -> int:
        data = self.read_rva(rva, 4)
        if len(data) != 4:
            raise PEFormatError(f"cannot read u32 at RVA 0x{rva:X}")
        return struct.unpack_from("<I", data)[0]

    def find_bytes(self, pattern: bytes, section: Section | None = None, *, step: int = 1) -> int | None:
        """Find bytes in a mapped section and return the matching RVA."""

        if not pattern:
            return None
        section = section or self.rdata_section
        data = self.read_rva(section.virtual_address, section.raw_size)
        limit = max(0, len(data) - len(pattern) + 1)
        for offset in range(0, limit, step):
            if data[offset : offset + len(pattern)] == pattern:
                return section.virtual_address + offset
        return None

    def find_ascii(self, text: str, section: Section | None = None, *, include_nul: bool = False) -> int | None:
        pattern = text.encode("ascii") + (b"\x00" if include_nul else b"")
        return self.find_bytes(pattern, section, step=4)

    def find_utf16(self, text: str, section: Section | None = None, *, include_nul: bool = True) -> int | None:
        pattern = text.encode("utf-16le") + (b"\x00\x00" if include_nul else b"")
        return self.find_bytes(pattern, section, step=4)

    def imports(self) -> dict[str, dict[str, ImportFunction]]:
        parse_failed = False
        try:
            self.pe.parse_data_directories(directories=[IMAGE_DIRECTORY_ENTRY_IMPORT])
        except Exception:
            parse_failed = True
        _ = parse_failed
        imports: dict[str, dict[str, ImportFunction]] = {}
        for descriptor in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = normalize_dll_name(descriptor.dll)
            entries: dict[str, ImportFunction] = {}
            for imported in descriptor.imports:
                if not imported.name:
                    continue
                name = imported.name.decode("ascii", errors="replace")
                iat_va = int(imported.address)
                entries[name] = ImportFunction(dll=dll, name=name, iat_rva=iat_va - self.image_base, iat_va=iat_va)
            imports[dll] = entries
        return imports

    def find_import_image(self, *dll_names: str) -> dict[str, ImportFunction] | None:
        imports = self.imports()
        for name in dll_names:
            found = imports.get(normalize_dll_name(name))
            if found is not None:
                return found
        return None

    def find_import_function(self, dll_names: tuple[str, ...], function_name: str) -> ImportFunction | None:
        image = self.find_import_image(*dll_names)
        if not image:
            return None
        return image.get(function_name)

    def runtime_functions(self) -> tuple[RuntimeFunction, ...]:
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
        rva = int(directory.VirtualAddress)
        size = int(directory.Size)
        if not rva or not size:
            return ()
        data = self.read_rva(rva, size)
        functions: list[RuntimeFunction] = []
        for offset in range(0, len(data) - 11, 12):
            begin, end, unwind_data = struct.unpack_from("<III", data, offset)
            if begin or end or unwind_data:
                functions.append(RuntimeFunction(begin, end, unwind_data))
        return tuple(functions)

    def unwind_info(self, unwind_rva: int) -> UnwindInfo:
        first = self.read_rva(unwind_rva, 4)
        if len(first) != 4:
            raise PEFormatError(f"cannot read unwind info at RVA 0x{unwind_rva:X}")
        flags = first[0] >> 3
        count_of_codes = first[2]
        chain_entry_offset = unwind_rva + 4 + (((count_of_codes + 1) & ~1) * 2)
        return UnwindInfo(flags=flags, count_of_codes=count_of_codes, chain_entry_offset=chain_entry_offset)

    def chained_runtime_function(self, unwind_info: UnwindInfo) -> RuntimeFunction:
        data = self.read_rva(unwind_info.chain_entry_offset, 12)
        if len(data) != 12:
            raise PEFormatError(f"cannot read chained runtime function at RVA 0x{unwind_info.chain_entry_offset:X}")
        return RuntimeFunction(*struct.unpack("<III", data))

    def decoder(self) -> "ImageDecoder":
        return ImageDecoder(self)

    def _build_mapped_image(self) -> bytearray:
        mapped = bytearray(self.size_of_image)
        headers = min(int(self.pe.OPTIONAL_HEADER.SizeOfHeaders), len(self._file_data), len(mapped))
        mapped[:headers] = self._file_data[:headers]
        for section in self.sections:
            if section.raw_address <= 0 or section.raw_size <= 0:
                continue
            raw_end = min(section.raw_address + section.raw_size, len(self._file_data))
            data = self._file_data[section.raw_address:raw_end]
            start = section.virtual_address
            end = min(start + len(data), len(mapped))
            if start < len(mapped):
                mapped[start:end] = data[: end - start]
        return mapped

    def _read_version(self) -> VersionInfo:
        for fixed in getattr(self.pe, "VS_FIXEDFILEINFO", []) or []:
            return VersionInfo.from_fixed_file_info(int(fixed.FileVersionMS), int(fixed.FileVersionLS))

        # Fallback for unusual pefile parsing failures: scan for VS_FIXEDFILEINFO.
        signature = b"\xbd\x04\xef\xfe"
        offset = self._file_data.find(signature)
        if offset >= 0 and offset + 16 <= len(self._file_data):
            file_version_ms, file_version_ls = struct.unpack_from("<II", self._file_data, offset + 8)
            return VersionInfo.from_fixed_file_info(file_version_ms, file_version_ls)
        raise PEFormatError(f"version resource not found in {self.path}")


class ImageDecoder:
    """Disassembles bytes from a mapped PE image using RVA addresses."""

    def __init__(self, image: PEImage):
        self.image = image
        self.arch = image.architecture
        self.image_base = image.image_base
        self._disassembler = Disassembler(self.arch)

    def disassemble(self, rva: int, max_length: int):
        return self._disassembler.disasm(self.image.read_rva(rva, max_length), rva)

    def decode_one(self, rva: int, max_length: int) -> Instruction | None:
        return self._disassembler.disasm_one(self.image.read_rva(rva, max_length), rva)


class RangeSet:
    """Sorted half-open range set matching the upstream helper behavior."""

    def __init__(self):
        self.ranges: list[tuple[int, int]] = []

    def clear(self) -> None:
        self.ranges.clear()

    def contains(self, value: int) -> bool:
        index = bisect.bisect_right(self.ranges, (value, 2**63 - 1)) - 1
        if index < 0:
            return False
        start, end = self.ranges[index]
        return start <= value < end

    def next_value(self, value: int) -> int:
        for start, end in self.ranges:
            if value < start:
                break
            if value < end:
                return end
        return value

    def add(self, start: int, end: int) -> None:
        if end <= start:
            return
        new_start = start
        new_end = end
        merged: list[tuple[int, int]] = []
        inserted = False
        for cur_start, cur_end in self.ranges:
            if new_end < cur_start:
                if not inserted:
                    merged.append((new_start, new_end))
                    inserted = True
                merged.append((cur_start, cur_end))
            elif new_start > cur_end:
                merged.append((cur_start, cur_end))
            else:
                new_start = min(new_start, cur_start)
                new_end = max(new_end, cur_end)
        if not inserted:
            merged.append((new_start, new_end))
        self.ranges = merged
