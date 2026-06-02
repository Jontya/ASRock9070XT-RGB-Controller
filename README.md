# ASRock RX 9070 XT Steel Legend — RGB Controller

Lightweight Python tool to control the RGB lighting on the ASRock RX 9070 XT Steel Legend via the AMD ADL SDK I2C bus. No third-party dependencies.

## Requirements

- Windows 11 with AMD drivers installed (`atiadlxx.dll` in `C:\Windows\System32\`)
- Windows Python 3.8+ (must be the **Windows** interpreter — not WSL's Python)
- Run as **Administrator** (required for I2C access)

## Files

| File | Purpose |
|---|---|
| `main.py` | GUI entry point |
| `adl_i2c.py` | ADL/I2C logic (headless, reusable) |
| `test_adl.py` | Standalone diagnostic — run this first |
| `run.bat` | Launch from Windows or WSL (`cmd.exe /c run.bat`) |
| `run.ps1` | Launch from PowerShell or WSL (`powershell.exe -File run.ps1`) |
| `config.json` | Auto-created on first save; stores last color + optional DLL path |

## Setup

1. Clone/copy this repo to a Windows path (e.g. `C:\Tools\asrock-rgb\`)
2. Open an **Administrator** command prompt
3. Run the diagnostic first:
   ```
   python test_adl.py
   ```
   Expected output ends with `RESULT: ASRock RGB controller FOUND`.
4. If that passes, launch the GUI:
   ```
   python main.py
   ```
   Or from WSL:
   ```bash
   cmd.exe /c run.bat
   ```

## Usage

- **Pick Color…** — opens system color picker
- **Hex field** — type any `#RRGGBB` value directly; swatch updates live
- **Apply & Save** — writes color to GPU (channels 3, 6, 7) and saves to `config.json`

On every launch the saved color is applied silently before the GUI appears.

## Task Scheduler (startup auto-apply)

| Field | Value |
|---|---|
| Trigger | At log on |
| Program | `C:\Path\To\pythonw.exe` |
| Arguments | `C:\Path\To\main.py --nogui` |
| Run with highest privileges | ✅ Yes |
| Start in | Directory containing `main.py` |

`--nogui` applies the saved color and exits immediately with zero UI overhead.

## config.json

Auto-created on first "Apply & Save". Can be edited manually:

```json
{
  "r": 255,
  "g": 0,
  "b": 128,
  "dll_path": "C:\\Windows\\System32\\atiadlxx.dll"
}
```

Override `dll_path` if the DLL is in a non-standard location.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ADL DLL not found` | Check AMD drivers are installed; verify `dll_path` in `config.json` |
| `ASRock GPU not found` | Run as Administrator; check `ADL_Adapter_SubSystem_Get` result in `test_adl.py` |
| I2C write fails | Try updating AMD drivers; some driver versions restrict I2C access |
| GUI doesn't open from WSL | Must use Windows Python — WSL Python cannot render Windows native GUI |
