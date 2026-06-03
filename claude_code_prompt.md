# Claude Code Prompt — ASRock RX 9070 XT RGB Controller Next Steps

You are continuing a stalled reverse-engineering project to control the RGB LEDs on an **ASRock RX 9070 XT Steel Legend** GPU from Python (stdlib + ctypes only, no third-party Python packages at runtime; Frida is used only for investigation).

## Current state (read before doing anything)

The project lives in the current working directory. There is a file `session.md` with the full investigation history — **read it first** so you have full context. The short version:

- ADL I2C is a dead end. The working protocol is `D3DKMTEscape` with an 868-byte AMD private driver buffer.
- The buffer format has been fully reverse-engineered via Frida hooking `AsrPolychromeRGB.exe` (the vendor app, 32-bit WoW64). R/G/B sit at offsets 255/256/257.
- When we replay the captured buffer from our 64-bit Python via `gdi32.dll!D3DKMTEscape`:
  - Adapter[0] (likely iGPU) → `STATUS_SUCCESS` but no LED change
  - Adapter[2] (likely dGPU) → `STATUS_NOT_SUPPORTED`
- Polychrome uses `d3d11.dll!D3DKMTEscape` (not `gdi32`) and opens its adapter via `D3DKMTOpenAdapterFromGdiDisplayName` / `FromHdc` (not `EnumAdapters`).
- A field at buffer offset 212 (`2b 00 11 00 00 00 00 00` = `0x0011002b`) is suspected to be a session/context token returned by an earlier escape we haven't captured.

## Hypotheses, in order of likelihood

1. There is a **setup `D3DKMTEscape` call** Polychrome makes before the first I2C write that returns the `0x0011002b` token. We need to capture and replay it.
2. The adapter must be opened via `D3DKMTOpenAdapterFromGdiDisplayName` (matching Polychrome's path) instead of `EnumAdapters`.
3. We must call `d3d11.dll!D3DKMTEscape`, not `gdi32.dll!D3DKMTEscape` — loading `d3d11.dll` also pulls in the AMD user-mode driver which may register the process with the kernel driver.
4. Bitness mismatch — Polychrome is 32-bit; we're 64-bit. Worth trying 32-bit Python only if (1)–(3) don't resolve it.

## Your task

Work through the steps below in order. **Stop and ask the user** at any checkpoint marked **[USER ACTION]**. Do not proceed past a checkpoint until the user confirms. Do not pull in any third-party Python runtime dependencies in the production code (`adl_i2c.py`, `main.py`); Frida-based scripts for investigation are fine.

### Step 0 — Orient

1. Read `session.md` end to end.
2. List the project files with `dir` (or `ls`) and skim `adl_i2c.py`, `capture_escape.py`, `frida_open_adapter.py`, and `test_exact_buffer.py`. Confirm what's there matches the session notes.
3. **Sanity-check adapter identity.** Run a small one-off script that calls `D3DKMTEnumAdapters` and for each adapter calls `D3DKMTQueryAdapterInfo` with `KMTQAITYPE_ADAPTERREGISTRYINFO` (info type 16) to retrieve the adapter description string. Print `index | hAdapter | LUID | DeviceName`. **Confirm that the adapter we've been calling "adapter[2]" really is the RX 9070 XT** and not the other way around. Save this as `tools/identify_adapters.py`. Report results before continuing.

### Step 1 — Capture the full escape stream from Polychrome startup

Goal: find any `D3DKMTEscape` (and `D3DKMTQueryAdapterInfo`) calls Polychrome makes **before** the first I2C write, which is the most likely source of the `0x0011002b` token.

1. Create `tools/frida_full_trace.py`. It should:
   - Attach to `AsrPolychromeRGB.exe` (32-bit; use `frida.get_local_device().attach(...)` with the correct arch handling).
   - Hook **both** `d3d11.dll!D3DKMTEscape` **and** `gdi32.dll!D3DKMTEscape` (whichever are present in the process), enumerating module exports by address since `findExportByName` is unreliable in WoW64.
   - Also hook `D3DKMTQueryAdapterInfo`, `D3DKMTOpenAdapterFromGdiDisplayName`, `D3DKMTOpenAdapterFromHdc`, and `D3DKMTCreateDevice` — every one Polychrome's process actually exports.
   - For each call, log: timestamp, function name, all struct fields (`hAdapter`, `Type`, `Flags`, `DataSize`, etc.), and the full private buffer **on entry and on return** (the driver writes back into the buffer — we care about the diffs).
   - Number each call sequentially and write a JSON log to `captures/trace_<timestamp>.json` plus a human-readable `.txt` summary.

2. **[USER ACTION]** Ask the user to:
   - Fully close Polychrome (check Task Manager for `AsrPolychromeRGB.exe`).
   - Run your Frida script.
   - Launch Polychrome fresh.
   - Wait until the Polychrome UI is fully loaded but **do not change any colors yet**.
   - Tell you when this is done. Then they should change one color (e.g., to red), wait 2 seconds, then close Polychrome.

3. Analyze the capture:
   - Identify every escape that happened **before** the first I2C escape (the one with `iLine=2`, `iAddress=0x6C`, `DataSize=12`).
   - For each pre-I2C escape, diff the input buffer against the output buffer. Look for `0x0011002b` (or `2b 00 11 00`) appearing as an **output**.
   - Identify which adapter handle Polychrome uses and trace it back to the `D3DKMTOpenAdapterFrom...` call that produced it. Record the display device name passed in.

4. Write a short markdown report to `captures/analysis.md` summarizing:
   - The full ordered sequence of D3DKMT calls.
   - Where the `0x0011002b` token first appears and what call produced it.
   - The display name + LUID Polychrome's adapter resolves to.
   - Whether Polychrome calls `d3d11!D3DKMTEscape` or `gdi32!D3DKMTEscape` (or both).

**Stop and show the user the analysis report before continuing.**

### Step 2 — Implement the corrected escape path

Based on Step 1's findings, rewrite `adl_i2c.py` so that it:

1. Loads `d3d11.dll` (this forces the AMD UMD to load and register).
2. Resolves `D3DKMTEscape`, `D3DKMTOpenAdapterFromGdiDisplayName`, `D3DKMTCloseAdapter`, and any other functions needed — preferring `d3d11.dll` exports where present, falling back to `gdi32.dll`.
3. Opens the adapter via `D3DKMTOpenAdapterFromGdiDisplayName` using the display name captured in Step 1.
   - If multiple displays could match, iterate `EnumDisplayDevicesW` and pick the one whose `DeviceString` contains "Radeon RX 9070 XT" (case-insensitive); fall back to matching PCI device ID `7550` via the registry path if needed.
4. If Step 1 revealed a setup escape, **replay it first** with the freshly opened `hAdapter`, capture the output buffer, and extract whatever token the driver returns. Cache it.
5. Builds the I2C escape buffer from a template, patching in:
   - The captured token (if any) at the correct offset
   - R, G, B at 255/256/257
   - Any other dynamic fields identified in Step 1
6. Calls `D3DKMTEscape` and checks NTSTATUS. On non-zero, raise with a decoded error name.
7. Closes the adapter cleanly.

Keep the public API of `adl_i2c.py` compatible with what `main.py` already calls (look at `main.py` to confirm the function signatures it uses — likely something like `set_color(r, g, b)`).

### Step 3 — Test

1. Create `tools/test_d3dkmt.py` — a minimal standalone test that calls the new `set_color` with bright red, waits 2 seconds, bright green, waits 2 seconds, bright blue, waits 2 seconds, then restores the user's saved color from `config.json`. Print the NTSTATUS for each call.
2. **[USER ACTION]** Ask the user to:
   - Make sure Polychrome is **fully closed** (it holds the I2C bus).
   - Run `python tools/test_d3dkmt.py` in an Administrator terminal.
   - Report what they see on the GPU and what NTSTATUS values printed.

### Step 4 — Decision point

- **If LEDs change correctly:** clean up, run `main.py` end-to-end, confirm the GUI works, and report done.
- **If LEDs don't change but NTSTATUS is `STATUS_SUCCESS`:** we're talking to the iGPU. Recheck adapter selection in Step 2.
- **If NTSTATUS is `STATUS_NOT_SUPPORTED` (`0xC00000BB`) again:**
  - Re-examine the Step 1 capture for any additional escapes you may have missed.
  - Hook `NtDeviceIoControlFile` in Polychrome and look for AMD-driver IOCTLs going to `\\.\AMDKMDAG` or similar device names — the token might come through a separate IOCTL path, not through D3DKMT.
  - Report findings and ask the user before going further.
- **If NTSTATUS is `STATUS_INVALID_PARAMETER` (`0xC000000D`):** the buffer template needs a field we haven't accounted for. Diff our buffer byte-by-byte against the most recent captured Polychrome buffer and report all differences.

### Step 5 — Last-resort options (only mention these if Steps 1–4 conclude unsuccessfully)

Do not implement these without the user's explicit go-ahead:

- **32-bit Python**: install a 32-bit Python alongside, retest there to rule out bitness gating.
- **Tiny native helper**: a small C program that does the D3DKMT calls, invoked via `subprocess` from the Python GUI. Keeps Python pure-stdlib.
- **Frida agent embedded in our own host process**: spawn a Frida session against a stub process and have it issue the escapes.

## Rules of engagement

- **Pause at every [USER ACTION] checkpoint.** Do not assume the user has run Polychrome or moved on.
- **Don't refactor existing files beyond what's necessary** for the changes above. `main.py` should stay structurally the same; only the import surface from `adl_i2c.py` changes if needed.
- **Don't add Python package dependencies** to the production code. ctypes only.
- **Log every NTSTATUS** with its symbolic name. Maintain a small mapping dict (`0x00000000`→`STATUS_SUCCESS`, `0xC000000D`→`STATUS_INVALID_PARAMETER`, `0xC00000BB`→`STATUS_NOT_SUPPORTED`, etc.) in a shared helper.
- **Preserve the `captures/` and `tools/` directories** — useful for the user later.
- **If a Frida hook fails** with `findExportByName` returning null in WoW64, fall back to `Module.enumerateExports(name).find(...)` and hook by absolute address. This is a known issue from prior session.
- **Before any irreversible action** (deleting files, force-killing Polychrome, etc.), ask first.

## Start now

Begin with Step 0. Print a one-paragraph plan of what you're about to do, then proceed.
