# Opt-in compatibility: one tested Dark Messiah 1.02 non-Steam build

This **source-only** patcher supports the exact non-Steam single-player build
identified by the hashes below. It does **not** claim support for all retail,
non-Steam, localized, or Steam builds. Unmatched versions are refused before
game files are written. The normal Steam launcher installation stays unchanged
unless a user explicitly invokes this tool on a directory matching the complete
non-Steam profile, including their own original executable.

Related report: [support for non-Steam version, issue #2](https://github.com/KingDavidW/DarkMessiah-ModLauncher-Files/issues/2).

## Requirements and installation

- Windows, Python **3.9 or newer**, standard library only (`py -3` on Windows).
- An existing full, working copy of the supported non-Steam 1.02 game.
- This launcher and [Advanced SDK R2-03.23](https://github.com/KingDavidW/DarkMessiah-AdvancedSDK-Mod-Files/tree/c5a6fb8f84bf9e6bc4f463b45655d812d1d59e15)
  installed, with the SDK in `_mods/advanced_sdk`. The SDK remains first in the
  launcher mod order. This tool does not install mods or change their settings.
- **Your saved original non-Steam EXE**, before the mod launcher replaced it.
  No original game EXE or DLL is included, fetched, or reconstructed from a
  download by this contribution.

Close the game and launcher. Use an independent game copy first. Choose the
game directory explicitly; there is no installation autodetection.

```powershell
py -3 patcher.py check --game-dir "D:\Games\DM-Test" --original-exe "D:\Backups\mm-original.exe"
py -3 patcher.py apply --game-dir "D:\Games\DM-Test" --original-exe "D:\Backups\mm-original.exe"
```

If the game folder still contains the supported original `mm.exe`, the
`--original-exe` argument is optional. The saved external EXE is read only.
After installation, run the game folder's `mm.exe` and choose the desired
launcher mode. Enable Advanced SDK before Restoration/other dependent mods.

Windows wrappers (no hard-coded game path):

```powershell
.\Install_OneClick.cmd "D:\Games\DM-Test" "D:\Backups\mm-original.exe"
.\Rollback_OneClick.cmd "D:\Games\DM-Test"
```

With the original EXE still in place, a game folder can be dragged onto
`Install_OneClick.cmd`. A folder can always be dragged onto the rollback wrapper.

## What changes

Only three existing game files are replaced, after complete preflight:

1. `mm.exe`: use the user's verified original bootstrap, replacing the **single
   fixed-size DLL-path string** `bin\launcher.dll` with `bin\wos_dmmm.dll` at
   RVA `0xE1A4`. The compatible four-argument `LauncherMain` entry is retained.
2. `bin/wos_dmmm.dll`: two fixed-size RVA operands.
3. `_mods/advanced_sdk/bin/server_sdk.dll`: two fixed-size RVA operands.

| Module operand RVA | Original little-endian bytes | Replacement | Engine hook target |
|---|---|---|---|
| WOS `0x1404E` | `B0 8F 18 00` | `A0 8F 18 00` | `0x188FB0` → `0x188FA0` |
| WOS `0x14093` | `70 8C 18 00` | `60 8C 18 00` | `0x188C70` → `0x188C60` |
| SDK server `0x19BDC9` | `20 6D 17 00` | `10 6D 17 00` | `0x176D20` → `0x176D10` |
| SDK server `0x19BE81` | `50 49 17 00` | `40 49 17 00` | `0x174950` → `0x174940` |

Each operand correction changes one byte. No engine/server/client relocation
tables are modified. No debugger, DLL injection, registry/service change,
machine-wide Steam change, or elevation is used by the patcher.

## Exact supported hashes

SHA-256, uppercase hexadecimal:

| File/version | SHA-256 |
|---|---|
| User's original non-Steam EXE | `8495465C430691CD6FE1BE821BBE9BB415D3A28CCE2999622A94C3B0B99B13C9` |
| Upstream launcher EXE allowed as current `mm.exe` | `74BB913EF6FC259D8EAA18EAE317D9CF1B36C6BE905A8F82A065B049E709EC69` |
| Patched original bootstrap | `D1F3288B1C90B3F7818F53C0890FE04787B66189E02F01A52596F15D9D85CA09` |
| WOS input | `4B3C5BC92E89591F85F51461A093AAE37544AB8D9E0F6759AC93E2E584D8C83A` |
| WOS output | `D1E213AE73A5D17380BB946BDE1AB81DFA2441D4D3BE4F89C7AFA6F50BFB85E7` |
| SDK server input | `CEC5327A05F7A461BA34784D267877797301AB844C91F5A927A73AAD68290B9D` |
| SDK server output | `344F54B392458F97DF5FFE4F372027F17D9C36CC41877578B849287BE5FF7621` |

The **six unmodified profile guard DLLs** must also match. Their complete hashes
are listed in `PROFILE.guards` in [patcher.py](patcher.py): engine, launcher,
gameui, game server/client, and SDK client. A version label such as "1.02" alone
is never sufficient. Translated or third-party-modified WOS/SDK binaries are not
silently overwritten; remove that extra binary layer before applying this
specific compatibility profile.

The verified upstream input revisions were launcher
`66aca607caa9af05f4e8ca21a2bbc967579d8cdd` and SDK
`c5a6fb8f84bf9e6bc4f463b45655d812d1d59e15`.

## Transaction, idempotency and rollback

Preflight validates **all** guard/input SHA-256 values, PE32 section mappings,
original operand bytes, the unique bootstrap path, and all three expected
output hashes before creating backups or modifying game files.

The game directory's `.dm-nonsteam-102-compat/` contains verified original
copies, a journal and an OS-owned lock. Each file replacement is atomic. If
a write or final verification fails, all recognized changes are automatically
rolled back. The journal is persisted before the first game write. A terminated
process releases its OS lock; recover an interrupted `prepared` transaction with:

```powershell
py -3 patcher.py rollback --game-dir "D:\Games\DM-Test"
```

Rollback checks **every** backup and current file before restoring anything,
refuses unknown EXE/DLL changes, and restores the actual three pre-install
hashes, including the previous launcher EXE when it was present. Backups remain.
Reapplying a fully patched profile changes nothing and does not replace backups.
Repeated rollback also verifies the restored state.

An already-compatible installation produced by another tool can be checked
without modification, but this patcher cannot invent its previous files: an
installation without this patcher's journal has no patcher-owned rollback.
Do not delete the state directory while you need its backups.

## Evidence and validation

[EVIDENCE.md](EVIDENCE.md) documents the observed fault and instruction-level
causal controls, distinguishing RVAs from loaded addresses. No raw dumps,
save files, game binaries, personal paths or large archives are submitted.

Historical acceptance on this exact build included three fresh modded processes
reaching playable `l00`, movement, F6 save/F9 load, Restoration `l00hub`, plus
the actual **Launch without Mods**, **Launch with Mods (all unchecked)** and
**Launch Original EXE (Vanilla)** branches. "Cold" means a new game process
after closing the previous one and restoring configuration, not a Windows reboot.
Exit code zero alone was not used as success evidence.

Synthetic transaction tests run on Windows/non-Windows without proprietary files:

```powershell
py -3 -m unittest -v test_patcher.py
```

Actual game acceptance for this portable implementation is recorded in
`verification.json`. This is not a full campaign playthrough, a Steam-build
test, or a compatibility guarantee for other binary versions.

The MIT license in this directory applies only to this newly contributed
patcher/tests/docs. It does not relicense upstream binaries or the SDK's
separate GPL-3.0 distribution.
