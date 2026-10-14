# Small, sanitized technical evidence

## Shared failing path

Both wiltOS branches (with no mods selected / without mods) failed with
`0xC0000005` on the tested build. The early `launcher.dll+0x3CC0` trampoline
was valid; the problem was subsequently identified in engine-target hooks.

The supported engine has preferred image base `0x20000000`. Static bytes:

```text
engine RVA 188FA0: 83 EC 08          sub esp,8       ; function entry
engine RVA 188FA3: 53                push ebx
engine RVA 188FA4: 56                push esi
engine RVA 188FA5: 57                push edi
engine RVA 188FA6: B9 20 00 00 00    mov ecx,20h
engine RVA 188FAB: BE 18 00 39 20    mov esi,20390018h
engine RVA 188FB0: BF F8 2F 6D 20    mov edi,206D2FF8h ; wrong hook target
engine RVA 188FB5: F3 A5             rep movsd
```

The WOS callback at RVA `0x13CD0` calls allocation/keyboard APIs before
`wos+0x13D32: call [trampoline]`. Hooking the middle of the engine function
does not preserve its live volatile ECX value of 32. The trampoline copies
`mov edi,...` and resumes at `rep movsd` with a huge count, corrupting memory.

First-chance telemetry (not a debugger-attached launch and not a live-dump
guess) recorded:

| Observation | EIP / location | ECX | Attempted write | Stack top |
|---|---|---|---|---|
| without-mods failure | VA `20188FB5` = engine RVA `188FB5` | `74452B80` | `20745000` | WOS RVA `13D38` (return after trampoline call) |
| independent negative control, original bootstrap + old WOS, all mods unchecked | VA `20188FB5` | `C2951DBB` | `20745000` | WOS RVA `13D38` |

Reintroducing only the original WOS DLL restored this fault and exit
`C0000005`. The adjacent corrected control reached the real game menu.

## Discriminating fixes

Fixing only the first WOS entry eliminated the runaway copy and exposed
`C0000096` at engine RVA `188C71`. The other old target `188C70` is inside
`188C6F: mov edx,[eax]`; the correct entry is `188C60`.

After correcting WOS, enabling SDK exposed two further mid-function targets:
`176D20` is a `mov edi,eax` inside a function starting at `176D10`;
`174950` is the last byte of `17494D: mov eax,[esp+0Ch]`, not the function
entry at `174940`. Correcting these SDK operands enabled stable gameplay.
The SDK's separate engine hook at `172490` was already correct and is unchanged.

The upstream protected EXE also produced a later relocated-server failure
at server RVA `158230` in this environment. Retaining the supported original
bootstrap and changing its DLL-path string stabilized the observed mappings
at engine/server/client `20000000 / 22000000 / 24000000`. The source of all
previous memory reservations was not established; this patch does not claim
that every old crash had the same cause or perform speculative relocation repairs.

## Byte provenance

The patch metadata was checked against the actual upstream input DLLs and
the locally verified outputs, not copied from a narrative summary alone.
The complete-byte input/output SHA checks are embedded in `patcher.py`.
Bootstrap original bytes at RVA `E1A4`:

```text
before: 62 69 6E 5C 6C 61 75 6E 63 68 65 72 2E 64 6C 6C 00
after:  62 69 6E 5C 77 6F 73 5F 64 6D 6D 6D 2E 64 6C 6C 00
```

No raw process memory, personal filenames, credentials, screenshots of a
desktop, copyrighted executables, or complete DLLs are attached here.
