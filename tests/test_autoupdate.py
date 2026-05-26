from __future__ import annotations

from pathlib import Path

from rdpwrap_offset_finder.autoupdate import contains_version_entry, load_template, render_updated_ini
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
