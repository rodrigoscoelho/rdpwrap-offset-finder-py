"""Windows DbgHelp/SymSrv symbol backend."""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from ctypes import wintypes

from .errors import BackendUnavailable, SymbolError
from .models import FinderResult
from .patches import def_policy_patch, local_only_patch, single_user_patch, sl_policy_cp
from .pe_image import PEImage

MAX_PATH = 260
MAX_SYM_NAME = 2000

ERROR_FILE_NOT_FOUND = 2
SSRVOPT_GUIDPTR = 0x0008

SYMOPT_DEBUG = 0x80000000
SYMOPT_PUBLICS_ONLY = 0x00004000
SYMOPT_UNDNAME = 0x00000002

MS_SYMBOL_PATH = "cache*;srv*https://msdl.microsoft.com/download/symbols"

_DBGHELP_LOCK = threading.Lock()


def default_termsrv_path() -> Path:
    """Return the default system termsrv.dll path on Windows."""

    if os.name != "nt":
        raise BackendUnavailable("the default termsrv.dll path is only available on Windows")

    windir = os.environ.get("WINDIR") or os.environ.get("SystemRoot") or r"C:\Windows"
    system_dir = "Sysnative" if os.environ.get("PROCESSOR_ARCHITEW6432") else "System32"
    return Path(windir) / system_dir / "termsrv.dll"


def find_offsets(path: str | Path | None = None) -> FinderResult:
    """Run the symbol backend and return generated rdpwrap.ini snippet lines."""

    if os.name != "nt":
        raise BackendUnavailable("the DbgHelp/SymSrv symbol backend requires Windows")

    termsrv_path = Path(path) if path is not None else default_termsrv_path()
    image = PEImage(termsrv_path)

    with _DBGHELP_LOCK:
        with DbgHelpSession() as session:
            session.load_module_symbols(image)
            lines = SymbolFinder(image, session).run()

    return FinderResult(
        backend="symbols",
        termsrv_path=image.path,
        architecture=image.architecture,
        version=image.version,
        lines=tuple(lines),
    )


@dataclass(frozen=True)
class SymbolAddress:
    """Resolved symbol address returned by DbgHelp."""

    address: int
    module_base: int

    @property
    def rva(self) -> int:
        return self.address - self.module_base


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SYMSRV_INDEX_INFOW(ctypes.Structure):
    _fields_ = [
        ("sizeofstruct", wintypes.DWORD),
        ("file", wintypes.WCHAR * (MAX_PATH + 1)),
        ("stripped", wintypes.BOOL),
        ("timestamp", wintypes.DWORD),
        ("size", wintypes.DWORD),
        ("dbgfile", wintypes.WCHAR * (MAX_PATH + 1)),
        ("pdbfile", wintypes.WCHAR * (MAX_PATH + 1)),
        ("guid", GUID),
        ("sig", wintypes.DWORD),
        ("age", wintypes.DWORD),
    ]


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_ulonglong * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_ulonglong),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", wintypes.WCHAR * 1),
    ]


class DbgHelpSession:
    """Thin ctypes wrapper around the DbgHelp APIs used by upstream."""

    def __init__(self):
        self.hprocess: int | None = None
        self._initialized = False

        try:
            self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self.dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
        except AttributeError as exc:  # pragma: no cover - protected by find_offsets on non-Windows.
            raise BackendUnavailable("ctypes WinDLL is only available on Windows") from exc
        except OSError as exc:  # pragma: no cover - Windows environment dependent.
            raise BackendUnavailable(f"DbgHelp.dll could not be loaded: {exc}") from exc

        self._configure_functions()

    def __enter__(self) -> "DbgHelpSession":
        self.hprocess = int(self.kernel32.GetCurrentProcess())
        self.dbghelp.SymSetOptions(SYMOPT_DEBUG | SYMOPT_PUBLICS_ONLY)

        search_path = None if "_NT_SYMBOL_PATH" in os.environ else MS_SYMBOL_PATH
        if not self.dbghelp.SymInitializeW(self.hprocess, search_path, False):
            raise SymbolError(_last_error("SymInitializeW"))
        self._initialized = True
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        if self._initialized and self.hprocess is not None:
            self.dbghelp.SymCleanup(self.hprocess)
            self._initialized = False

    def load_module_symbols(self, image: PEImage) -> None:
        """Locate the matching PDB through SymSrv and load it into DbgHelp."""

        if self.hprocess is None:
            raise SymbolError("DbgHelp session is not initialized")

        info = SYMSRV_INDEX_INFOW()
        info.sizeofstruct = ctypes.sizeof(SYMSRV_INDEX_INFOW)
        if not self.dbghelp.SymSrvGetFileIndexInfoW(str(image.path), ctypes.byref(info), 0):
            raise SymbolError(_last_error("SymSrvGetFileIndexInfoW"))
        if not info.pdbfile:
            raise SymbolError(f"no PDB name found in debug information for {image.path}")

        found = ctypes.create_unicode_buffer(MAX_PATH + 1)
        if not self.dbghelp.SymFindFileInPathW(
            self.hprocess,
            None,
            info.pdbfile,
            ctypes.byref(info.guid),
            int(info.age),
            0,
            SSRVOPT_GUIDPTR,
            found,
            None,
            None,
        ):
            error = ctypes.get_last_error()
            if error == ERROR_FILE_NOT_FOUND:
                raise SymbolError(f"symbol not found for {image.path}: {info.pdbfile}")
            raise SymbolError(_last_error("SymFindFileInPathW"))

        loaded_base = self.dbghelp.SymLoadModuleExW(
            self.hprocess,
            None,
            found.value,
            None,
            int(image.image_base),
            int(image.size_of_image),
            None,
            0,
        )
        if not loaded_base:
            raise SymbolError(_last_error("SymLoadModuleExW"))

    def set_options(self, options: int) -> None:
        self.dbghelp.SymSetOptions(options)

    def symbol(self, name: str) -> SymbolAddress | None:
        if self.hprocess is None:
            raise SymbolError("DbgHelp session is not initialized")

        symbol = _new_symbol_info()
        if not self.dbghelp.SymFromNameW(self.hprocess, name, symbol):
            return None
        return SymbolAddress(int(symbol.contents.Address), int(symbol.contents.ModBase))

    def first_symbol(self, *names: str) -> SymbolAddress | None:
        for name in names:
            symbol = self.symbol(name)
            if symbol is not None:
                return symbol
        return None

    def _configure_functions(self) -> None:
        try:
            self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE

            self.dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
            self.dbghelp.SymSetOptions.restype = wintypes.DWORD

            self.dbghelp.SymInitializeW.argtypes = [
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.BOOL,
            ]
            self.dbghelp.SymInitializeW.restype = wintypes.BOOL

            self.dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
            self.dbghelp.SymCleanup.restype = wintypes.BOOL

            self.dbghelp.SymSrvGetFileIndexInfoW.argtypes = [
                wintypes.LPCWSTR,
                ctypes.POINTER(SYMSRV_INDEX_INFOW),
                wintypes.DWORD,
            ]
            self.dbghelp.SymSrvGetFileIndexInfoW.restype = wintypes.BOOL

            self.dbghelp.SymFindFileInPathW.argtypes = [
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPWSTR,
                wintypes.LPVOID,
                wintypes.LPVOID,
            ]
            self.dbghelp.SymFindFileInPathW.restype = wintypes.BOOL

            self.dbghelp.SymLoadModuleExW.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                ctypes.c_ulonglong,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
            ]
            self.dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong

            self.dbghelp.SymFromNameW.argtypes = [
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                ctypes.POINTER(SYMBOL_INFOW),
            ]
            self.dbghelp.SymFromNameW.restype = wintypes.BOOL
        except AttributeError as exc:  # pragma: no cover - Windows DbgHelp version dependent.
            raise BackendUnavailable(f"DbgHelp.dll does not export the required API: {exc}") from exc


class SymbolFinder:
    """Generate rdpwrap.ini lines from DbgHelp-resolved symbol RVAs."""

    def __init__(self, image: PEImage, session: DbgHelpSession):
        self.image = image
        self.session = session
        self.decoder = image.decoder()
        self.arch = image.architecture

    def run(self) -> list[str]:
        lines: list[str] = [f"[{self.image.version}]"]

        verify_version = self.session.first_symbol(
            "__imp_VerifyVersionInfoW",
            "__imp__VerifyVersionInfoW@16",
        )
        verify_version_addr: int | None = None
        if verify_version is not None:
            verify_version_addr = verify_version.rva
            if self.arch == "x86":
                verify_version_addr += self.image.image_base

        self.session.set_options(SYMOPT_DEBUG | SYMOPT_UNDNAME)

        memset = self.session.first_symbol("memset", "_memset")
        if memset is not None:
            single_session = self.session.symbol("CSessionArbitrationHelper::IsSingleSessionPerUserEnabled")
            if single_session is not None:
                lines.extend(
                    single_user_patch(
                        self.decoder,
                        single_session.rva,
                        memset.rva,
                        verify_version_addr,
                    )
                )
            else:
                single_session = self.session.symbol("CUtils::IsSingleSessionPerUser")
                if single_session is not None:
                    single_user = single_user_patch(
                        self.decoder,
                        single_session.rva,
                        memset.rva,
                        verify_version_addr,
                    )
                    if single_user:
                        lines.extend(single_user)
                    else:
                        lines.append("ERROR: SingleUserPatch not found")

        cdefpolicy_query = self.session.symbol("CDefPolicy::Query")
        if cdefpolicy_query is not None:
            lines.extend(def_policy_patch(self.decoder, cdefpolicy_query.rva))
        else:
            lines.append("ERROR: CDefPolicy_Query not found")

        if self.image.version.ms <= 0x00060001:
            return lines

        if self.image.version.ms == 0x00060002:
            sl_wrapper = self.session.symbol("SLGetWindowsInformationDWORDWrapper")
            if sl_wrapper is not None:
                suffix = self.arch
                func = "New_Win8SL_CP" if sl_policy_cp(self.decoder, sl_wrapper.rva) else "New_Win8SL"
                lines.extend(
                    [
                        f"SLPolicyInternal.{suffix}=1",
                        f"SLPolicyOffset.{suffix}={sl_wrapper.rva:X}",
                        f"SLPolicyFunc.{suffix}={func}",
                    ]
                )
            else:
                lines.append("ERROR: SLGetWindowsInformationDWORDWrapper not found")
            return lines

        get_instance = self.session.symbol("CEnforcementCore::GetInstanceOfTSLicense")
        if get_instance is not None:
            local_only = self.session.symbol("CSLQuery::IsLicenseTypeLocalOnly")
            if local_only is not None:
                lines.extend(local_only_patch(self.decoder, get_instance.rva, local_only.rva))
            else:
                lines.append("ERROR: IsLicenseTypeLocalOnly not found")
        else:
            lines.append("ERROR: GetInstanceOfTSLicense not found")

        cslquery_initialize = self.session.symbol("CSLQuery::Initialize")
        if cslquery_initialize is None:
            lines.append("ERROR: CSLQuery_Initialize not found")
            return lines

        suffix = self.arch
        lines.extend(
            [
                f"SLInitHook.{suffix}=1",
                f"SLInitOffset.{suffix}={cslquery_initialize.rva:X}",
                f"SLInitFunc.{suffix}=New_CSLQuery_Initialize",
                "",
                f"[{self.image.version}-SLInit]",
            ]
        )

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
            symbol = self.session.symbol(f"CSLQuery::{name}")
            if symbol is not None:
                lines.append(f"{name}.{suffix}={symbol.rva:X}")
            else:
                lines.append(f"ERROR: {name} not found")

        return lines


def _new_symbol_info() -> ctypes.POINTER(SYMBOL_INFOW):
    size = ctypes.sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * ctypes.sizeof(wintypes.WCHAR))
    buffer = ctypes.create_string_buffer(size)
    symbol = ctypes.cast(buffer, ctypes.POINTER(SYMBOL_INFOW))
    symbol.contents.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
    symbol.contents.MaxNameLen = MAX_SYM_NAME
    return symbol


def _last_error(function_name: str) -> str:
    error = ctypes.get_last_error()
    if sys.platform == "win32":
        detail = ctypes.WinError(error).strerror
        return f"{function_name} failed with Windows error {error}: {detail}"
    return f"{function_name} failed with Windows error {error}"
