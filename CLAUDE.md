# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Python RGB controller for the ASRock RX 9070 XT Steel Legend GPU on Windows. Uses AMD ADL SDK (`atiadlxx.dll`) via `ctypes` — no third-party Python dependencies. Developed in WSL; runs on Windows.

## Running / testing

All execution must happen via **Windows Python** (not WSL Python). From WSL:

```bash
cmd.exe /c run.bat              # GUI
cmd.exe /c run.bat --nogui      # headless apply

# Diagnostic (run this first when testing ADL changes):
python.exe test_adl.py          # or: /mnt/c/Python3x/python.exe test_adl.py
```

There are no automated tests. Manual verification via `test_adl.py` is the test step.

## Architecture

Two-layer split — keep it that way:

- **`adl_i2c.py`** — all ADL/I2C logic. No GUI imports. `ASRockRGBController` class manages DLL lifetime and I2C writes. `apply_color()` is the convenience one-shot function. `load_config()` / `save_config()` handle `config.json`.
- **`main.py`** — tkinter GUI + `--nogui` entry point. Imports from `adl_i2c` only. Never put hardware logic here.

## Key protocol details

- DLL: `C:\Windows\System32\atiadlxx.dll` (overridable via `config.json` `dll_path`)
- I2C address: `0x36`, command byte: `0x10`
- Channels: 3 (ARGB header), 6 (top side), 7 (fan) — all three written on every color change
- Static color payload: `[0x01, R, G, B, 0xFF, 0x00, 0x00, 0x00]`
- Tries `ADL2_Display_WriteAndReadI2CRev_Get` first, falls back to `ADL_Display_WriteAndReadI2C`
- SubVendor detection via `ADL_Adapter_SubSystem_Get`; falls back to accepting first adapter if that function is absent from the driver version

## config.json

Auto-created at script directory on first save. Fields: `r`, `g`, `b`, `dll_path`. Missing file → defaults to white `(255, 255, 255)`.

## Constraints

- `tkinter` and `ctypes` only — no pip installs
- GUI must not be resizable
- Window must not show until saved color has been silently applied
- `--nogui` must exit with code 0 on success, 1 on failure
- Must run as Administrator on Windows for I2C access
