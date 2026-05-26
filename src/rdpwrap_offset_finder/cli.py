"""Command-line entry point for generating rdpwrap.ini offsets."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .errors import RDPWrapOffsetFinderError
from .models import FinderResult


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        path = _resolve_termsrv_path(args.termsrv)
        result = run_backend(path, args.backend)
    except RDPWrapOffsetFinderError as exc:
        print(f"rdpwrap-offset-finder: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"rdpwrap-offset-finder: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(result.text)
    return 1 if result.has_errors and not args.allow_errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rdpwrap-offset-finder",
        description="Generate rdpwrap.ini offsets for termsrv.dll.",
    )
    parser.add_argument(
        "termsrv",
        nargs="?",
        help="Path to termsrv.dll. Defaults to %%WINDIR%%\\System32\\termsrv.dll on Windows.",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "symbols", "nosymbol"),
        default="auto",
        help="Finder backend to use. auto uses symbols on Windows and nosymbol elsewhere.",
    )
    parser.add_argument(
        "--allow-errors",
        action="store_true",
        help="Return exit code 0 even when generated snippet lines contain ERROR.",
    )
    return parser


def run_backend(path: Path, backend: str = "auto") -> FinderResult:
    if backend == "auto":
        backend = "symbols" if os.name == "nt" else "nosymbol"

    if backend == "symbols":
        from . import symbols

        return symbols.find_offsets(path)

    if backend == "nosymbol":
        from . import nosymbol

        return nosymbol.find_offsets(path)

    raise ValueError(f"unknown backend: {backend}")


def _resolve_termsrv_path(value: str | None) -> Path:
    if value:
        return Path(value)

    if os.name == "nt":
        from .symbols import default_termsrv_path

        return default_termsrv_path()

    raise FileNotFoundError("termsrv.dll path is required on non-Windows systems")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
