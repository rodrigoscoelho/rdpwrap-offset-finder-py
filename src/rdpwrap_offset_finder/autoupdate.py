"""Dry-run-first Python equivalent of upstream autoupdate.bat."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path

from .cli import run_backend
from .errors import BackendUnavailable, RDPWrapOffsetFinderError
from .models import VersionInfo
from .pe_image import PEImage

TEMPLATE_RESOURCE = "resources/rdpwrap_template.ini"
PATCH_CODE_REFERENCE_KEYS = frozenset({"LocalOnlyCode", "SingleUserCode", "DefPolicyCode"})


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
                print("[*] Checking generated offsets and patch-code references against installed rdpwrap.ini...")
                result = run_backend(termsrv_path, args.backend)
                if "ERROR" in result.text:
                    print("[-] FAILED to generate latest version of rdpwrap.ini!")
                    if args.print:
                        print(result.text, end="")
                    return 1

                installed_ini = rdpwrap_ini.read_text(encoding="utf-8", errors="ignore")
                new_ini = ensure_generated_offset_sections(installed_ini, result.text)
                new_ini = ensure_referenced_patch_codes(new_ini, result.text)
                if new_ini == installed_ini:
                    print("[*] RDP Wrapper seems to be up-to-date and working...")
                    return 0

                print("[*] Missing generated offset or [PatchCodes] entries were added to the candidate ini.")
                if args.print:
                    print(new_ini, end="")

                if not args.apply:
                    print(f"[dry-run] Would write patched rdpwrap.ini to {output_path}.")
                    print(f"[dry-run] Would replace {rdpwrap_ini} and restart TermService.")
                    return 0

                if os.name != "nt":
                    raise BackendUnavailable("--apply is only supported on Windows")

                apply_update(new_ini, output_path, rdpwrap_ini)
                print(f"[+] Successfully patched {rdpwrap_ini}.")
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
    new_ini = template.rstrip("\r\n") + "\n" + offset_text
    return ensure_referenced_patch_codes(new_ini, offset_text, template)


def extract_referenced_patch_code_names(offset_text: str) -> set[str]:
    names: set[str] = set()
    for raw_line in offset_text.splitlines():
        line = _strip_ini_comment(raw_line).strip()
        if not line or "=" not in line:
            continue
        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip()
        value = raw_value.strip()
        if not value:
            continue
        key_base = key.split(".", 1)[0]
        if key_base in PATCH_CODE_REFERENCE_KEYS:
            names.add(value)
    return names


def ensure_referenced_patch_codes(
    ini_text: str,
    offset_text: str,
    template_text: str | None = None,
) -> str:
    referenced_names = extract_referenced_patch_code_names(offset_text)
    if not referenced_names:
        return ini_text

    template = load_template() if template_text is None else template_text
    template_codes = _parse_patch_code_lines(template)
    missing_from_template = sorted(referenced_names - set(template_codes))
    if missing_from_template:
        missing = ", ".join(missing_from_template)
        raise RDPWrapOffsetFinderError(f"template [PatchCodes] is missing generated patch code(s): {missing}")

    target_codes = _parse_patch_code_lines(ini_text)
    missing_names = [name for name in template_codes if name in referenced_names and name not in target_codes]
    if not missing_names:
        return ini_text

    return _insert_key_lines_into_section(
        ini_text,
        "PatchCodes",
        [template_codes[name] for name in missing_names],
        create_after_section="Main",
    )


def ensure_generated_offset_sections(ini_text: str, offset_text: str) -> str:
    updated = ini_text
    for section_name, generated_lines in _parse_generated_section_key_lines(offset_text):
        existing_keys = _parse_key_lines_in_section(updated, section_name)
        missing_lines = [line for key, line in generated_lines if key not in existing_keys]
        if missing_lines:
            updated = _insert_key_lines_into_section(updated, section_name, missing_lines)
    return updated


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


def _parse_patch_code_lines(ini_text: str) -> dict[str, str]:
    return _parse_key_lines_in_section(ini_text, "PatchCodes")


def _parse_key_lines_in_section(ini_text: str, section_name: str) -> dict[str, str]:
    lines = ini_text.splitlines(keepends=True)
    bounds = _find_section_bounds(lines, section_name)
    if bounds is None:
        return {}

    start, end = bounds
    key_lines: dict[str, str] = {}
    for line in lines[start + 1 : end]:
        parsed = _parse_ini_key_value(line)
        if parsed is None:
            continue
        key, _value = parsed
        key_lines.setdefault(key, _strip_line_ending(line).strip())
    return key_lines


def _parse_generated_section_key_lines(offset_text: str) -> list[tuple[str, list[tuple[str, str]]]]:
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    current_name: str | None = None
    current_lines: list[tuple[str, str]] = []

    def finish_section() -> None:
        if current_name is not None:
            sections.append((current_name, current_lines.copy()))

    for raw_line in offset_text.splitlines(keepends=True):
        section_name = _section_name(raw_line)
        if section_name is not None:
            finish_section()
            current_name = section_name
            current_lines = []
            continue

        if current_name is None:
            continue
        parsed = _parse_ini_key_value(raw_line)
        if parsed is None:
            continue
        key, _value = parsed
        current_lines.append((key, _strip_line_ending(raw_line).strip()))

    finish_section()
    return sections


def _insert_key_lines_into_section(
    ini_text: str,
    section_name: str,
    key_lines: Iterable[str],
    *,
    create_after_section: str | None = None,
) -> str:
    new_entries = list(key_lines)
    if not new_entries:
        return ini_text

    newline = "\r\n" if "\r\n" in ini_text else "\n"
    lines = ini_text.splitlines(keepends=True)
    insert_lines = [f"{line}{newline}" for line in new_entries]
    bounds = _find_section_bounds(lines, section_name)

    if bounds is None:
        section_lines = [f"[{section_name}]{newline}", *insert_lines, newline]
        if create_after_section is not None:
            after_bounds = _find_section_bounds(lines, create_after_section)
            if after_bounds is not None:
                _ensure_previous_line_ends(lines, after_bounds[1], newline)
                lines[after_bounds[1] : after_bounds[1]] = [newline, *section_lines]
                return "".join(lines)
        _ensure_previous_line_ends(lines, len(lines), newline)
        if lines and lines[-1].strip():
            lines.append(newline)
        return "".join(lines + section_lines)

    start, end = bounds
    insert_at = end
    while insert_at > start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1

    _ensure_previous_line_ends(lines, insert_at, newline)
    lines[insert_at:insert_at] = insert_lines
    return "".join(lines)


def _find_section_bounds(lines: list[str], name: str) -> tuple[int, int] | None:
    start = None
    for index, line in enumerate(lines):
        section_name = _section_name(line)
        if section_name is None:
            continue
        if start is None:
            if section_name == name:
                start = index
            continue
        return start, index

    if start is None:
        return None
    return start, len(lines)


def _section_name(line: str) -> str | None:
    stripped = line.strip()
    if not stripped.startswith("[") or not stripped.endswith("]"):
        return None
    return stripped[1:-1]


def _parse_ini_key_value(line: str) -> tuple[str, str] | None:
    stripped = line.lstrip()
    if not stripped or stripped.startswith(("#", ";")):
        return None
    line = _strip_ini_comment(line).strip()
    if "=" not in line:
        return None
    raw_key, raw_value = line.split("=", 1)
    key = raw_key.strip()
    if not key:
        return None
    return key, raw_value.strip()


def _strip_ini_comment(line: str) -> str:
    for marker in (";", "#"):
        before, marker_found, _after = line.partition(marker)
        if marker_found:
            return before
    return line


def _strip_line_ending(line: str) -> str:
    return line.rstrip("\r\n")


def _ensure_previous_line_ends(lines: list[str], index: int, newline: str) -> None:
    if index == 0 or not lines:
        return
    if not lines[index - 1].endswith(("\n", "\r")):
        lines[index - 1] = lines[index - 1] + newline


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
