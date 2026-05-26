"""Exception types used by the offset finder backends."""

from __future__ import annotations


class RDPWrapOffsetFinderError(RuntimeError):
    """Base exception for expected finder failures."""


class BackendUnavailable(RDPWrapOffsetFinderError):
    """Raised when a selected backend cannot run in this environment."""


class DependencyUnavailable(BackendUnavailable):
    """Raised when an optional runtime dependency is missing."""


class PEFormatError(RDPWrapOffsetFinderError):
    """Raised when a PE image is missing data required by the finder."""


class SymbolError(RDPWrapOffsetFinderError):
    """Raised for Windows DbgHelp/SymSrv symbol backend failures."""


class FinderError(RDPWrapOffsetFinderError):
    """Raised when the no-symbol backend cannot complete a required search."""
