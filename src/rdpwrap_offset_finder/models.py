"""Small typed models shared by finder modules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Architecture = Literal["x86", "x64"]


@dataclass(frozen=True)
class VersionInfo:
    """Windows file version split into four 16-bit components."""

    major: int
    minor: int
    build: int
    revision: int

    @property
    def ms(self) -> int:
        return (self.major << 16) | self.minor

    @property
    def ls(self) -> int:
        return (self.build << 16) | self.revision

    @classmethod
    def from_fixed_file_info(cls, file_version_ms: int, file_version_ls: int) -> "VersionInfo":
        return cls(
            (file_version_ms >> 16) & 0xFFFF,
            file_version_ms & 0xFFFF,
            (file_version_ls >> 16) & 0xFFFF,
            file_version_ls & 0xFFFF,
        )

    @classmethod
    def parse(cls, value: str) -> "VersionInfo":
        parts = value.strip().split(".")
        if len(parts) != 4:
            raise ValueError(f"expected four-part version, got {value!r}")
        return cls(*(int(part, 10) for part in parts))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.build}.{self.revision}"


@dataclass(frozen=True)
class FinderResult:
    """Generated rdpwrap.ini snippet plus metadata."""

    backend: str
    termsrv_path: Path
    architecture: Architecture
    version: VersionInfo
    lines: tuple[str, ...]

    @property
    def text(self) -> str:
        return "\n".join(self.lines) + ("\n" if self.lines else "")

    @property
    def has_errors(self) -> bool:
        return any("ERROR" in line for line in self.lines)


@dataclass(frozen=True)
class RuntimeFunction:
    """x64 IMAGE_AMD64_RUNTIME_FUNCTION_ENTRY."""

    begin: int
    end: int
    unwind_data: int


@dataclass(frozen=True)
class Section:
    """PE section mapping metadata."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + self.mapped_size


@dataclass(frozen=True)
class ImportFunction:
    """Imported function address in the image address table."""

    dll: str
    name: str
    iat_rva: int
    iat_va: int
