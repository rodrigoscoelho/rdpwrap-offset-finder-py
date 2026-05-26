from __future__ import annotations

import os

import pytest

from rdpwrap_offset_finder.errors import BackendUnavailable


def test_public_modules_import_without_optional_runtime_dependencies() -> None:
    import rdpwrap_offset_finder.autoupdate  # noqa: F401
    import rdpwrap_offset_finder.cli  # noqa: F401
    import rdpwrap_offset_finder.disasm  # noqa: F401
    import rdpwrap_offset_finder.nosymbol  # noqa: F401
    import rdpwrap_offset_finder.patches  # noqa: F401
    import rdpwrap_offset_finder.pe_image  # noqa: F401
    import rdpwrap_offset_finder.symbols  # noqa: F401


@pytest.mark.skipif(os.name == "nt", reason="non-Windows BackendUnavailable behavior")
def test_symbol_backend_is_clear_unavailable_on_non_windows() -> None:
    from rdpwrap_offset_finder import symbols

    with pytest.raises(BackendUnavailable, match="requires Windows"):
        symbols.find_offsets("termsrv.dll")


@pytest.mark.skipif(os.name == "nt", reason="non-Windows path behavior")
def test_cli_requires_path_on_non_windows(capsys: pytest.CaptureFixture[str]) -> None:
    from rdpwrap_offset_finder import cli

    assert cli.main([]) == 2
    captured = capsys.readouterr()
    assert "termsrv.dll path is required" in captured.err


def test_cli_help_exits_successfully() -> None:
    from rdpwrap_offset_finder import cli

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0
