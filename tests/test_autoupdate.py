from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from rdpwrap_offset_finder import autoupdate
from rdpwrap_offset_finder.autoupdate import (
    contains_version_entry,
    ensure_generated_offset_sections,
    ensure_referenced_patch_codes,
    extract_referenced_patch_code_names,
    load_template,
    render_updated_ini,
)
from rdpwrap_offset_finder.models import VersionInfo


def test_template_resource_is_bundled_with_post_v09_patch_code() -> None:
    template = load_template()

    assert "[PatchCodes]" in template
    assert "CDefPolicy_Query_r9d_rdi_jmp=C7873806000000010000EB" in template
    assert "CDefPolicy_Query_ecx_rdi_jmp=C7873806000000010000EB" in template


def test_render_updated_ini_appends_offsets_after_template() -> None:
    text = render_updated_ini("[10.0.1.2]\nDefPolicyPatch.x64=1\n", "[Main]\n")

    assert text == "[Main]\n[10.0.1.2]\nDefPolicyPatch.x64=1\n"


def test_contains_version_entry(tmp_path: Path) -> None:
    ini = tmp_path / "rdpwrap.ini"
    ini.write_text("[Main]\n\n[10.0.26100.8376]\n", encoding="utf-8")

    assert contains_version_entry(ini, VersionInfo(10, 0, 26100, 8376))
    assert not contains_version_entry(ini, VersionInfo(10, 0, 26100, 1))


def test_extract_referenced_patch_code_names_from_offset_text() -> None:
    offset_text = "\n".join(
        [
            "[10.0.26100.8521]",
            "LocalOnlyPatch.x64=1",
            "LocalOnlyCode.x64=jmpshort",
            "SingleUserCode.x64=mov_eax_1_nop_2",
            "DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp",
            "MaxUserSessions.x64=0",
            "",
        ]
    )

    assert extract_referenced_patch_code_names(offset_text) == {
        "jmpshort",
        "mov_eax_1_nop_2",
        "CDefPolicy_Query_r9d_rdi_jmp",
    }


def test_ensure_referenced_patch_codes_adds_missing_entries_from_template() -> None:
    ini_text = (
        "[Main]\n"
        "\n"
        "[PatchCodes]\n"
        "jmpshort=EB\n"
        "\n"
        "[10.0.26100.8521]\n"
        "LocalOnlyCode.x64=jmpshort\n"
        "SingleUserCode.x64=mov_eax_1_nop_2\n"
    )
    template_text = (
        "[PatchCodes]\n"
        "jmpshort=EB\n"
        "mov_eax_1_nop_2=B8010000009090\n"
        "\n"
        "[SLInit]\n"
    )

    updated = ensure_referenced_patch_codes(ini_text, ini_text, template_text)

    assert "jmpshort=EB\nmov_eax_1_nop_2=B8010000009090\n" in updated
    assert updated.count("mov_eax_1_nop_2=") == 1


def test_ensure_referenced_patch_codes_leaves_existing_entries_unchanged() -> None:
    ini_text = (
        "[Main]\n"
        "\n"
        "[PatchCodes]\n"
        "jmpshort=EB\n"
        "mov_eax_1_nop_2=LOCAL_VALUE\n"
        "\n"
        "[10.0.26100.8521]\n"
        "LocalOnlyCode.x64=jmpshort\n"
        "SingleUserCode.x64=mov_eax_1_nop_2\n"
    )
    template_text = (
        "[PatchCodes]\n"
        "jmpshort=EB\n"
        "mov_eax_1_nop_2=B8010000009090\n"
    )

    updated = ensure_referenced_patch_codes(ini_text, ini_text, template_text)

    assert updated == ini_text
    assert updated.count("mov_eax_1_nop_2=") == 1
    assert "mov_eax_1_nop_2=LOCAL_VALUE" in updated


def test_ensure_referenced_patch_codes_adds_26100_8521_missing_codes_from_template() -> None:
    ini_text = (
        "[Main]\n"
        "\n"
        "[PatchCodes]\n"
        "jmpshort=EB\n"
        "\n"
        "[10.0.26100.8521]\n"
        "SingleUserCode.x64=mov_eax_1_nop_2\n"
        "DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp\n"
    )
    offset_text = (
        "[10.0.26100.8521]\n"
        "SingleUserCode.x64=mov_eax_1_nop_2\n"
        "DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp\n"
    )

    updated = ensure_referenced_patch_codes(ini_text, offset_text, load_template())

    assert "mov_eax_1_nop_2=B8010000009090" in updated
    assert "CDefPolicy_Query_r9d_rdi_jmp=C7873806000000010000EB" in updated


def test_ensure_generated_offset_sections_adds_missing_keys_and_sections_without_overwriting() -> None:
    installed_ini = (
        "[Main]\n"
        "\n"
        "[PatchCodes]\n"
        "jmpshort=EB\n"
        "\n"
        "[10.0.26100.8521]\n"
        "LocalOnlyPatch.x64=1\n"
        "LocalOnlyCode.x64=LOCAL_OVERRIDE\n"
    )
    offset_text = (
        "[10.0.26100.8521]\n"
        "LocalOnlyPatch.x64=1\n"
        "LocalOnlyCode.x64=jmpshort\n"
        "SingleUserCode.x64=mov_eax_1_nop_2\n"
        "\n"
        "[10.0.26100.8521-SLInit]\n"
        "bInitialized.x64=126FC8\n"
    )

    updated = ensure_generated_offset_sections(installed_ini, offset_text)

    assert "LocalOnlyCode.x64=LOCAL_OVERRIDE" in updated
    assert "LocalOnlyCode.x64=jmpshort" not in updated
    assert "SingleUserCode.x64=mov_eax_1_nop_2" in updated
    assert "[10.0.26100.8521-SLInit]\n" in updated
    assert "bInitialized.x64=126FC8" in updated
    assert updated.count("SingleUserCode.x64=") == 1


def test_main_dry_run_updates_patch_codes_when_version_entry_already_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    termsrv = tmp_path / "termsrv.dll"
    termsrv.write_bytes(b"not a real pe")
    installed_ini = tmp_path / "rdpwrap.ini"
    installed_ini.write_text(
        "[Main]\n"
        "\n"
        "[PatchCodes]\n"
        "jmpshort=EB\n"
        "\n"
        "[10.0.26100.8521]\n"
        "SingleUserCode.x64=mov_eax_1_nop_2\n"
        "DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp\n",
        encoding="utf-8",
    )

    class FakePEImage:
        def __init__(self, path: Path) -> None:
            assert path == termsrv
            self.version = VersionInfo(10, 0, 26100, 8521)

    def fake_run_backend(path: Path, backend: str) -> SimpleNamespace:
        assert path == termsrv
        assert backend == "auto"
        return SimpleNamespace(
            text=(
                "[10.0.26100.8521]\n"
                "SingleUserCode.x64=mov_eax_1_nop_2\n"
                "DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp\n"
            ),
            has_errors=False,
        )

    def fail_apply_update(new_ini: str, output_path: Path, rdpwrap_ini: Path) -> None:
        raise AssertionError("dry run must not execute apply_update")

    monkeypatch.setattr(autoupdate, "PEImage", FakePEImage)
    monkeypatch.setattr(autoupdate, "run_backend", fake_run_backend)
    monkeypatch.setattr(autoupdate, "apply_update", fail_apply_update)

    assert (
        autoupdate.main(
            [
                "--termsrv",
                str(termsrv),
                "--rdpwrap-ini",
                str(installed_ini),
                "--print",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "mov_eax_1_nop_2=B8010000009090" in output
    assert "CDefPolicy_Query_r9d_rdi_jmp=C7873806000000010000EB" in output
    assert "[dry-run]" in output
    assert "mov_eax_1_nop_2=B8010000009090" not in installed_ini.read_text(encoding="utf-8")
