# CLAUDE.md — ASRock RX 9070 XT RGB Controller

Combined project instructions + investigation history for Claude Code sessions.

---

## Project Goal

Build a Python tool (stdlib + ctypes only, no runtime third-party packages) to control RGB LEDs on an **ASRock RX 9070 XT Steel Legend** GPU on Windows. Uses tkinter GUI, runs as Administrator.

**Working solution exists**: `AsrPolychromeRGB.exe` (Polychrome, 32-bit WoW64) controls the LEDs via `D3DKMTEscape`. We are reverse-engineering that path and reimplementing it in Python.

---

## Rules for Claude

- **Pause at every [USER ACTION] checkpoint.** Do not assume the user ran Polychrome or moved on.
- **No third-party Python runtime deps.** ctypes + stdlib only in `adl_i2c.py` and `main.py`. Frida is fine for investigation scripts in `tools/`.
- **Don't refactor beyond the task.** `main.py` stays structurally the same.
- **Log every NTSTATUS** with its symbolic name (mapping dict in every test script).
- **Preserve `captures/` and `tools/` directories.**
- **Before any irreversible action** (deleting files, force-killing Polychrome), ask first.
- **If a Frida hook fails** with `findExportByName` returning null in WoW64, fall back to `Module.enumerateExports(name).find(...)` and hook by absolute address.

---

## Protocol — What We Know (Confirmed)

### D3DKMTEscape, 868-byte buffer

```
offset 0:8     = 02 00 00 00 02 00 01 00
offset 72:92   = 64 03 00 00 80 00 00 00 00 00 01 00 00 00 00 02 05 00 00 00
offset 204:212 = 50 01 00 00 50 01 00 00
offset 212:220 = 2b 00 11 00 00 00 00 00   (AMD subcommand ID — STATIC, confirmed)
offset 224:232 = 40 01 00 00 04 00 00 00   (I2C struct size + type)
offset 232:236 = 02 00 00 00               (iLine = 2)
offset 236:240 = 6c 00 00 00               (iAddress = 0x6C)
offset 240:244 = 10 00 00 00               (iOffset = 0x10)
offset 244:248 = 64 00 00 00               (iSpeed = 100)
offset 248:252 = 0c 00 00 00               (iDataSize = 12)
offset 252:263   I2C data payload (12 bytes)
offset 255       R
offset 256       G
offset 257       B
offset 540:548 = 40 01 00 00 40 01 00 00
```

D3DKMT_ESCAPE struct fields: `hDevice=0, hContext=0, Type=0, Flags=0`. No D3DKMTCreateDevice needed.

### DLL and display names

- **Must use `d3d11.dll!D3DKMTEscape`** — `gdi32.dll!D3DKMTEscape` returns `STATUS_INVALID_PARAMETER`.
- **Active dGPU displays**: `\\.\ DISPLAY17` and `\\.\ DISPLAY18` (AMD Radeon RX 9070 XT). These are the only ones that open successfully.
- **DISPLAY19-21** (inactive 9070 XT displays): return `STATUS_UNSUCCESSFUL` in both 32-bit and 64-bit.
- Display names and LUID both change on reboot. Must enumerate via `EnumDisplayDevicesW` at runtime, matching on "9070" in DeviceString.

### Adapter handle ranges (from Frida trace)

Polychrome uses handles spanning THREE distinct high-bit ranges:
- `0x40xxxxxx` — display adapter handles
- `0x80xxxxxx` — different adapter type (opened via different API or slot state)
- `0xC0xxxxxx` — another adapter type

The handle value encodes the kernel slot. Opening the same display in two different processes gives different slot numbers (e.g. our Python gets `0x40000000` for DISPLAY17, Polychrome gets `0x80000340` — same underlying adapter, different slot due to different number of pre-existing handles in the process's handle table). **Slot numbers are irrelevant for function.**

### Adapter identity (64-bit D3DKMTEnumAdapters2)

```
adapter[0]  iGPU   AMD Radeon(TM) Graphics      LUID varies
adapter[1]  dGPU   AMD Radeon RX 9070 XT         <- target
adapter[2]  render node
```

D3DKMTEnumAdapters2 returns exactly **3 adapters** regardless of 32-bit or 64-bit Python.

---

## Current Blocker — Cannot Open LED Adapter Handles

We can open DISPLAY17/18 and get `STATUS_SUCCESS` on D3DKMTEscape with the correct 868-byte buffer, but **LEDs do not change**.

### Root Cause (Confirmed)

The I2C LED escape writes do NOT go to the DISPLAY17/18 adapter handles. From the Frida trace (second trace with fixed script), Polychrome sends 868-byte I2C escapes to handles like `0x80001C00`, `0xC0000000`, `0x40000140`, etc. — **completely different adapter objects** from the display adapters.

These LED adapter handles were opened by Polychrome **at startup**, before our Frida script could attach. We do not yet know what API Polychrome uses to open them.

### What We Know About the LED Handles

- 868-byte I2C escapes (LED writes) go to ~50+ handles spread across 0x40/0x80/0xC0 ranges
- Most return `STATUS_SUCCESS`; a few return `STATUS_UNSUCCESSFUL` (not the right hardware)
- These handles are NOT opened via `D3DKMTOpenAdapterFromGdiDisplayName` (only DISPLAY17/18 use that)
- `D3DKMTEnumAdapters2` returns only 3 adapters — the LED handles are NOT from EnumAdapters
- In Polychrome's process: `D3DKMTEnumAdapters`, `D3DKMTEnumAdapters2`, `D3DKMTOpenAdapterFromDeviceName` are NOT exported by name in any loaded module (Frida can't hook them)
- `D3DKMTOpenAdapterFromHdc` IS in GDI32.dll — called twice (after DISPLAY17/18 open) — return values NOT yet captured

---

## Current Next Step — Spawn Mode Frida Trace

`tools/frida_full_trace.py` now has **spawn mode**: it launches Polychrome fresh so all startup adapter-open calls are captured before any code runs.

**Polychrome path**: `C:\Program Files (x86)\ASRock Utility\ASRRGBLED\Bin\AsrPolychromeRGB.exe`

**[USER ACTION]**
1. Kill any running Polychrome
2. Run: `python tools\frida_full_trace.py`
3. Script spawns Polychrome automatically
4. When UI appears, change a color
5. Press Enter to save logs

The trace will capture which API opens the LED handles and what parameters it uses. Look for `D3DKMTOpenAdapterFromDeviceName`, `D3DKMTOpenAdapterFromHdc`, or any other open calls that produce the 0x80/0xC0-range handles used for LED writes.

---

## Investigation History

### Phase 1 — ADL I2C (FAILED)
`atiadlxx.dll!ADL_Display_WriteAndReadI2C` only accesses DDC monitor buses, not the internal GPU I2C bus. Dead end.

### Phase 2 — Frida capture of Polychrome
Confirmed: 868-byte private buffer, RGB at offsets 255/256/257, iLine=2, iAddress=0x6C, iOffset=0x10. Polychrome uses `d3d11.dll!D3DKMTEscape`, adapter opened via `D3DKMTOpenAdapterFromGdiDisplayName`.

### Phase 3 — Early 64-bit escape attempts (FAILED)
Wrong display names (DISPLAY1/2 vs DISPLAY17/18). Wrong DLL (gdi32 vs d3d11). `D3DKMTEnumAdapters` adapter[0] gave STATUS_SUCCESS silently (iGPU no-op).

### Phase 4 — Full Frida trace (`captures/trace_20260603_112233.json`)
- 172 escape calls captured, 131 unique hAdapter values, three handle ranges (0x40/0x80/0xC0)
- buf[212] = `2b 00 11 00 00 00 00 00` confirmed static across all 58 DataSize=868 escapes
- hDevice=0, hContext=0 always, no D3DKMTCreateDevice calls
- D3DKMTEnumAdapters hook captured ZERO calls — function not exported by name in WoW64

### Phase 5 — Display names + DLL confirmed
Found DISPLAY17/DISPLAY18. Confirmed d3d11 needed. STATUS_SUCCESS now returned.

### Phase 6 — STATUS_SUCCESS but no LED change
All combinations tested (32-bit Python, exact capture replay, scan-then-set, DISPLAY17+18, all 3 EnumAdapters adapters) — SUCCESS but nothing happens.

### Phase 7 — Adapter handle mystery (current)
Discovered: 32-bit Python gets same 3 adapters from EnumAdapters2 as 64-bit. Scan of DISPLAY1-50 in 32-bit opens only DISPLAY17/18 (same as 64-bit).

Second Frida trace (attach to running) confirmed: LED writes go to pre-opened handles not from display name API. Script updated with spawn mode + OpenAdapterFromHdc reader + OpenAdapterFromDeviceName reader + full EnumAdapters array dump. Spawn trace pending.

---

## Tests That Have Failed

| Test | Result |
|------|--------|
| ADL_Display_WriteAndReadI2C | Wrong bus (DDC only) |
| gdi32.dll D3DKMTEscape | STATUS_INVALID_PARAMETER |
| DISPLAY1/2 with d3d11 | STATUS_UNSUCCESSFUL (wrong display name) |
| DISPLAY17/18 with d3d11 (64-bit) | STATUS_SUCCESS, no LED change |
| DISPLAY17/18 with d3d11 (32-bit Python) | STATUS_SUCCESS, no LED change |
| All 3 D3DKMTEnumAdapters2 adapters | STATUS_SUCCESS, no LED change |
| Scan of DISPLAY1-50 (32-bit) | Only DISPLAY17/18 open; no LED change |
| Exact captured 868-byte buffer replay | STATUS_SUCCESS, no LED change |
| Scan-phase + color-set (scan_then_set.py) | STATUS_SUCCESS, no LED change |

---

## NTSTATUS Reference

| Code | Meaning |
|------|---------|
| `0x00000000` | STATUS_SUCCESS |
| `0xC000000D` | STATUS_INVALID_PARAMETER |
| `0xC00000BB` | STATUS_NOT_SUPPORTED |
| `0xC0000001` | STATUS_UNSUCCESSFUL |
| `0xC0000022` | STATUS_ACCESS_DENIED |

---

## Hardware / System Info

- GPU: ASRock RX 9070 XT Steel Legend, PCI DEV=7550, SubVendor=0x1849
- iGPU: AMD Ryzen integrated, DEV=164E
- OS: Windows 11
- Polychrome: `C:\Program Files (x86)\ASRock Utility\ASRRGBLED\Bin\AsrPolychromeRGB.exe` — 32-bit WoW64
- Python: 64-bit Windows + 32-bit Python installed at default path
- dGPU active displays: DISPLAY17, DISPLAY18 (LUID changes each boot, e.g. 0x00BD5640 on 2026-06-03)

---

## File Inventory

| File | Purpose | Status |
|------|---------|--------|
| `adl_i2c.py` | Hardware interface — D3DKMTEscape | Uses DISPLAY17/18 + d3d11; works but hits wrong adapter |
| `main.py` | tkinter GUI | Unchanged |
| `tools/identify_adapters.py` | Enumerate adapters via D3DKMTQueryAdapterInfo | Done |
| `tools/frida_full_trace.py` | Full D3DKMT trace — **spawn mode + HDC/DeviceName/EnumAdapters readers** | Updated; spawn trace pending |
| `tools/extract_i2c.py` | Extract 868-byte escapes from trace JSON | Done |
| `tools/find_led_adapter.py` | Map hAdapter->devName from trace | Done |
| `tools/check_hdevice.py` | Verify hDevice/hContext in trace | Done — both zero |
| `tools/test_d3dkmt.py` | Escape test with display enumeration | Done |
| `tools/replay_capture.py` | Replay exact Polychrome buffer | Done — STATUS_SUCCESS, no LED change |
| `tools/scan_then_set.py` | Scan phase then color-set | Done — STATUS_SUCCESS, no LED change |
| `tools/enum_adapters_escape.py` | D3DKMTEnumAdapters2 + escape to all handles (32-bit) | Done — 3 adapters, no LED change |
| `tools/scan_all_displays_32bit.py` | Try DISPLAY1-50 in 32-bit Python | Done — only 17/18 open, no LED change |
| `tools/analyze_trace_adapters.py` | Extract unique hAdapter values + slots from trace JSON | Done |
| `captures/trace_20260603_112233.json` | First Frida trace (attach mode) | 131 unique handles, key reference |
| `captures/trace_20260603_130800.json` | Second Frida trace (attach mode, improved hooks) | Confirmed LED handles pre-opened at startup |
| `.info/session.md` | Verbose session notes | Updated |
| `config.json` | Saved color + dll_path | gitignored |
