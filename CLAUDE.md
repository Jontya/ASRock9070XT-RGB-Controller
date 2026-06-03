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
- **Display names on this machine**: `\\.\ DISPLAY17` and `\\.\ DISPLAY18` (ACTIVE, AMD Radeon RX 9070 XT). Not DISPLAY1/DISPLAY2.
- **DISPLAY19-21** (inactive 9070 XT displays): return `STATUS_UNSUCCESSFUL` when opened from a 64-bit process.
- Display names and LUID both change on reboot. Must enumerate via `EnumDisplayDevicesW` at runtime, matching on "9070" in DeviceString.

### Adapter identity (64-bit D3DKMTEnumAdapters)

```
adapter[0]  iGPU   AMD Radeon(TM) Graphics
adapter[1]  dGPU   AMD Radeon RX 9070 XT    <- target (LUID changes each boot)
adapter[2]  render node (D3DKMTQueryAdapterInfo fails)
```

---

## Current Blocker — STATUS_SUCCESS but No LED Change

We open `\\.\ DISPLAY17` via `D3DKMTOpenAdapterFromGdiDisplayName`, call `d3d11.D3DKMTEscape` with the exact 868-byte buffer captured from Polychrome — get `STATUS_SUCCESS` but LEDs do not change.

### Root cause hypothesis

Polychrome (32-bit WoW64) sends its LED-changing escape to `hAdapter=0x40000E40` — slot 57 in the kernel's 0x4000xxxx handle table. Our 64-bit process opens DISPLAY17 and gets slot 0 (`0x40000000`).

These are **different kernel adapter objects**. Slot 0 is the display output adapter (accepts escape, no LED hardware). Slot 57 is the I2C LED controller adapter, only reachable from 32-bit D3DKMTEnumAdapters (which may return more entries than 64-bit — we couldn't hook it to verify).

All tests tried:

| Test | Buffer | Result |
|------|--------|--------|
| Template buffer, 5 buf[212] variants | test_d3dkmt.py | SUCCESS, no LED change |
| Exact Polychrome capture (seq 133) | replay_capture.py | SUCCESS, no LED change |
| Scan phase (10 escapes) then color-set | scan_then_set.py | SUCCESS, no LED change |
| DISPLAY17 + DISPLAY18, scan+set each | scan_then_set.py Ph3 | SUCCESS, no LED change |

---

## Next Steps — In Priority Order

### 1. Try 32-bit Python (quickest)

Install 32-bit Python from python.org → Windows 32-bit installer. Run `tools/replay_capture.py` unchanged. A 32-bit process gets the same WoW64 D3DKMTEnumAdapters adapter space as Polychrome. This should open the correct slot.

**[USER ACTION]** Try 32-bit Python first. Report what NTSTATUS and whether LEDs change.

### 2. Fix Frida EnumAdapters hook

In `tools/frida_full_trace.py`: the D3DKMTEnumAdapters hook targets `gdi32.dll` which doesn't export this in 32-bit WoW64 (it's in `gdi32full.dll` or `win32u.dll`). Fix:

1. Enumerate ALL loaded modules' exports looking for `D3DKMTEnumAdapters` / `D3DKMTEnumAdapters2`.
2. Log each `{hAdapter, LUID}` pair from the returned array (struct: `UINT NumAdapters` + array of 20-byte `D3DKMT_ADAPTERINFO` entries).
3. Also fix devName capture: use `ptr.readUtf16String()` without length arg.
4. Re-run trace. Use `tools/find_led_adapter.py` to identify which LUID Polychrome's slot 57 (`0x40000E40`) corresponds to.
5. Open that LUID from 64-bit via `D3DKMTOpenAdapterFromLuid`.

### 3. Test adapter[2] (render node) with d3d11

Adapter[2] from 64-bit EnumAdapters previously returned `STATUS_NOT_SUPPORTED` — but with gdi32, not d3d11. Update `tools/replay_capture.py` to iterate all 3 EnumAdapters results with `d3d11.D3DKMTEscape` + exact captured buffer.

### 4. 32-bit C helper (last resort)

Small 32-bit `.exe` (MinGW `i686-w64-mingw32-gcc`) calling D3DKMTEnumAdapters + D3DKMTEscape. Invoked via `subprocess` from Python. Keeps stdlib-only constraint.

---

## Investigation History Summary

### Phase 1 — ADL I2C (FAILED)
`atiadlxx.dll!ADL_Display_WriteAndReadI2C` only accesses DDC monitor buses, not the internal GPU I2C bus. Dead end.

### Phase 2 — Frida capture of Polychrome
Confirmed: 868-byte private buffer, RGB at offsets 255/256/257, iLine=2, iAddress=0x6C, iOffset=0x10. Polychrome uses `d3d11.dll!D3DKMTEscape`, adapter opened via `D3DKMTOpenAdapterFromGdiDisplayName`.

### Phase 3 — Early 64-bit escape attempts
Wrong display names (DISPLAY1/2 vs DISPLAY17/18). Wrong DLL (gdi32 vs d3d11). `D3DKMTEnumAdapters` adapter[0] gave STATUS_SUCCESS silently (iGPU no-op).

### Phase 4 — Full Frida trace (captures/trace_20260603_112233.json)
- 172 NtGdiDdDDIEscape calls captured
- buf[212] confirmed static across all 58 DataSize=868 escapes
- hDevice=0, hContext=0 always, no D3DKMTCreateDevice calls
- Polychrome scans ~31 adapters then color-sets to ~27 handles simultaneously
- D3DKMTEnumAdapters hook captured ZERO calls (wrong module in 32-bit WoW64)

### Phase 5 — Display names + DLL confirmed
Found DISPLAY17/DISPLAY18. Confirmed d3d11 needed. STATUS_SUCCESS now returned.

### Phase 6 — STATUS_SUCCESS but no LED change (current state)
Exact captured buffer, scan-then-set, all combinations — SUCCESS but nothing happens. Hypothesis: wrong adapter object (slot 0 vs slot 57 in kernel handle table).

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
- Polychrome: `AsrPolychromeRGB.exe` — 32-bit WoW64, confirmed working
- Python: 64-bit Windows, run as Administrator
- dGPU active displays: DISPLAY17, DISPLAY18
- dGPU LUID: changes each boot (0x00016B5B earlier; 0x00BD5640 on 2026-06-03)

---

## File Inventory

| File | Purpose | Status |
|------|---------|--------|
| `adl_i2c.py` | Hardware interface — D3DKMTEscape | Updated, uses DISPLAY17/18 + d3d11 |
| `main.py` | tkinter GUI | Unchanged |
| `tools/identify_adapters.py` | Enumerate adapters via D3DKMTQueryAdapterInfo | Done |
| `tools/frida_full_trace.py` | Full D3DKMT trace of Polychrome | Done — needs EnumAdapters fix |
| `tools/extract_i2c.py` | Extract 868-byte escapes from trace JSON | Done |
| `tools/find_led_adapter.py` | Map hAdapter->devName from trace (key: devName) | Done |
| `tools/check_hdevice.py` | Verify hDevice/hContext in trace | Done — both zero |
| `tools/test_d3dkmt.py` | Escape test with display enumeration | Done |
| `tools/replay_capture.py` | Replay exact Polychrome buffer | Done — SUCCESS, no LED change |
| `tools/scan_then_set.py` | Scan phase then color-set | Done — SUCCESS, no LED change |
| `captures/trace_20260603_112233.json` | Frida trace from 2026-06-03 | Key data file |
| `.info/session.md` | Verbose session notes (full detail) | Updated |
| `config.json` | Saved color + dll_path | gitignored |
