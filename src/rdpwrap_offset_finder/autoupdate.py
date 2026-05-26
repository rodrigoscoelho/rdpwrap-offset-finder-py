"""Dry-run-first Python equivalent of upstream autoupdate.bat."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

from .cli import run_backend
from .errors import BackendUnavailable, RDPWrapOffsetFinderError
from .models import VersionInfo
from .pe_image import PEImage

TEMPLATE_RESOURCE = "resources/rdpwrap_template.ini"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        termsrv_path = _resolve_termsrv_path(args.termsrv)
        rdpwrap_ini = Path(args.rdpwrap_ini) if args.rdpwrap_ini else default_rdpwrap_ini_path()
        output_path = Path(args.output) if args.output else Path.cwd() / "rdpwrap_new.ini"

        version = PEImage(termsrv_path).version
        print(f'[+] Installed "termsrv.dll" version: {version}.')

        if rdpwrap_ini.exists():
            print(f"[*] Start searching [{version}] version entry in file {rdpwrap_ini}...")
            if contains_version_entry(rdpwrap_ini, version):
                print(f"[+] Found version entry [{version}] in file {rdpwrap_ini}.")
                print("[*] RDP Wrapper seems to be up-to-date and working...")
                return 0
            print(f"[-] NOT found version entry [{version}] in file {rdpwrap_ini}!")
        else:
            print(f"[-] File NOT found: {rdpwrap_ini}.")

        print()
        print("[*] Autogenerating latest version of rdpwrap.ini...")
        result = run_backend(termsrv_path, args.backend)
        new_ini = render_updated_ini(result.text)

        if "ERROR" in new_ini:
            print("[-] FAILED to generate latest version of rdpwrap.ini!")
            if args.print:
                print(new_ini, end="")
            return 1

        if args.print:
            print(new_ini, end="")

        if not args.apply:
            print(f"[dry-run] Would write generated rdpwrap.ini to {output_path}.")
            print(f"[dry-run] Would replace {rdpwrap_ini} and restart TermService.")
            return 0

        if os.name != "nt":
            raise BackendUnavailable("--apply is only supported on Windows")

        apply_update(new_ini, output_path, rdpwrap_ini)
        print(f"[+] Successfully generated latest version to {rdpwrap_ini}.")
        return 0
    except RDPWrapOffsetFinderError as exc:
        print(f"rdpwrap-offset-update: {exc}", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"rdpwrap-offset-update: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rdpwrap-offset-update",
        description="Generate and optionally install an updated rdpwrap.ini.",
    )
    parser.add_argument(
        "--termsrv",
        help="Path to termsrv.dll. Defaults to %%WINDIR%%\\System32\\termsrv.dll on Windows.",
    )
    parser.add_argument(
        "--rdpwrap-ini",
        help='Path to installed rdpwrap.ini. Defaults to "%%PROGRAMFILES%%\\RDP Wrapper\\rdpwrap.ini".',
    )
    parser.add_argument(
        "--output",
        help="Temporary generated ini path used with --apply. Defaults to ./rdpwrap_new.ini.",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "symbols", "nosymbol"),
        default="auto",
        help="Finder backend to use.",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="Print the generated rdpwrap.ini content.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write rdpwrap.ini and run the service-control side effects from autoupdate.bat.",
    )
    return parser


def load_template() -> str:
    return files("rdpwrap_offset_finder").joinpath(TEMPLATE_RESOURCE).read_text(encoding="utf-8")


def render_updated_ini(offset_text: str, template_text: str | None = None) -> str:
    template = load_template() if template_text is None else template_text
    return template.rstrip("\r\n") + "\n" + offset_text


def contains_version_entry(path: Path, version: VersionInfo) -> bool:
    needle = f"[{version}]"
    try:
        return any(line.strip() == needle for line in path.read_text(encoding="utf-8", errors="ignore").splitlines())
    except FileNotFoundError:
        return False


def default_rdpwrap_ini_path() -> Path:
    if os.name != "nt":
        raise BackendUnavailable("the default rdpwrap.ini path is only available on Windows")
    program_files = os.environ.get("PROGRAMFILES") or r"C:\Program Files"
    return Path(program_files) / "RDP Wrapper" / "rdpwrap.ini"


def apply_update(new_ini: str, output_path: Path, rdpwrap_ini: Path) -> None:
    rdpwrap_ini.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(new_ini, encoding="utf-8", newline="\r\n")

    for command in (
        ("net", "stop", "UmRdpService"),
        ("sc", "stop", "termservice"),
        ("sc", "config", "termservice", "start=disabled"),
        ("taskkill", "/F", "/FI", "MODULES eq termsrv.dll"),
    ):
        subprocess.run(command, check=False)

    shutil.move(str(output_path), str(rdpwrap_ini))

    for command in (
        ("icacls", str(rdpwrap_ini), "/inheritance:e"),
        ("sc", "config", "termservice", "start=demand"),
        ("sc", "start", "termservice"),
    ):
        subprocess.run(command, check=True)


def _resolve_termsrv_path(value: str | None) -> Path:
    if value:
        return Path(value)

    if os.name == "nt":
        from .symbols import default_termsrv_path

        return default_termsrv_path()

    raise BackendUnavailable("termsrv.dll path is required on non-Windows systems")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
