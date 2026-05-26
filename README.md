# rdpwrap-offset-finder

Python port of `llccd/RDPWrapOffsetFinder` for generating `rdpwrap.ini` offsets from
`termsrv.dll`.

The port keeps the current upstream matching behavior, including the post-v0.9
`DefPolicyPatch` fixes for `10.0.26100.8376` and the x64 path2 IP regression fix.
See [`PORTING_NOTES.md`](PORTING_NOTES.md) for the exact upstream commits.
It provides both backends:

- `symbols`: Windows-only DbgHelp/SymSrv backend that downloads or locates the
  matching PDB and uses public symbols when available.
- `nosymbol`: PE/string/xref search backend that does not require PDB symbols.

## Install

```bash
python -m pip install .
```

The no-symbol backend needs `pefile` and `capstone`, which are package
dependencies. The symbol backend also needs Windows `DbgHelp.dll`/`SymSrv`
support and network or local access to Microsoft symbols unless `_NT_SYMBOL_PATH`
points at a populated cache or proxy.

## Usage

Generate offsets for the system `termsrv.dll` on Windows:

```bash
rdpwrap-offset-finder
```

Generate offsets for a specific file:

```bash
rdpwrap-offset-finder C:\Windows\System32\termsrv.dll
```

Choose a backend explicitly:

```bash
rdpwrap-offset-finder --backend symbols C:\Windows\System32\termsrv.dll
rdpwrap-offset-finder --backend nosymbol ./termsrv.dll
```

`--backend auto` is the default. It uses `symbols` on Windows and `nosymbol`
elsewhere. The process exits nonzero if generated lines contain `ERROR`, unless
`--allow-errors` is supplied.

## Autoupdate

`rdpwrap-offset-update` is a dry-run-first equivalent of upstream
`autoupdate.bat`. By default it checks the installed `termsrv.dll` version,
checks the installed `rdpwrap.ini`, generates the candidate content in memory,
and prints the operations it would perform. If the installed ini already has
the current version section, the updater still verifies that generated offset
entries are present and that `[PatchCodes]` defines every patch-code name
referenced by those offsets; it can dry-run or apply a small ini repair when
entries are missing.

```bash
rdpwrap-offset-update --print
```

Use `--apply` to perform side effects: write the generated `rdpwrap.ini`, stop
the relevant services, replace the file, restore inheritance with `icacls`, and
start TermService again. Run from an elevated shell when applying.

```bash
rdpwrap-offset-update --apply
```

## Development

```bash
python -m pip install -e .[test]
python -m pytest -q
```

Tests are written so Linux import and unit checks pass without Windows DbgHelp
available. Tests that would require real Windows DLL parsing or live symbol
servers are not run on Linux.
