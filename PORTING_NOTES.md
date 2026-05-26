# Porting notes

This repository is a Python port of [`llccd/RDPWrapOffsetFinder`](https://github.com/llccd/RDPWrapOffsetFinder).

## Upstream baseline

- Port baseline inspected: `llccd/RDPWrapOffsetFinder` at `3f5ae264212bbc71ac648682ace63327b07a7a9e` (`v0.9-5-g3f5ae26`).
- Both upstream programs are represented:
  - `RDPWrapOffsetFinder`: DbgHelp/SymSrv/PDB-backed symbol mode.
  - `RDPWrapOffsetFinder_nosym`: no-symbol PE/string/xref scanning mode.
- `autoupdate/autoupdate.bat` is represented by `rdpwrap-offset-update`.

## Commits after v0.9

`git describe` on the inspected upstream was `v0.9-5-g3f5ae26`. The five commits after `v0.9` were:

1. `36ff9c1676123670c49454b99167dbcc6d3ea6da` — `Fix DefPolicyPatch on 26100.8376`
   - Removes the old `!mov_base` guard in the x64 `DefPolicyPatch` path so the matcher refreshes the last `[base+0x63c]` load before finding the `[same-base+0x638]` load.
   - This is the material fix for Windows build `10.0.26100.8376`.
2. `4f0818839c4493d61d2db1a594ed9b1a0a878e6c` — `fix: remove incorrect IP regression in DefPolicyPatch x64 path2`
   - Stops moving the emitted patch offset back by the previous instruction when path2 sees `JNZ`.
3. `2796dbe2704ddfb0ad0270996ea398c0c867941b` — `Remove STL dependencies and link against msvcrt.dll`
   - Packaging/runtime compatibility change for the C build.
4. `c39b9b102d4170cd8d250c06d23c31ff6cdc3661` — `Update zydis library`
   - Disassembler dependency update in upstream C.
5. `3f5ae264212bbc71ac648682ace63327b07a7a9e` — `Support running in old OS`
   - Runtime compatibility change for old Windows versions.

## Port-specific fidelity notes

- Capstone emits some aliases differently from Zydis (`je`/`jne` versus `jz`/`jnz`). The Python disassembler normalizes these to the Zydis names because the upstream matchers are written around Zydis mnemonics.
- The template keeps upstream patch codes and includes an alias for `CDefPolicy_Query_ecx_rdi_jmp`, which maps to the same bytes as the upstream `CDefPolicy_Query_r9d_rdi_jmp` path2 patch. This prevents the generator from emitting an unresolved patch-code name if a future DLL uses `ecx` for the temporary load.
- Linux tests cover pure matching logic and import behavior. Live end-to-end validation with Microsoft PDBs and real `termsrv.dll` files must be run on Windows.
