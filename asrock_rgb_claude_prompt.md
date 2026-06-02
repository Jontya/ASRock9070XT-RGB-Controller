# Claude Code Prompt — ASRock RX 9070 XT RGB Controller

A ready-to-paste prompt for building a lightweight Python RGB control tool for the ASRock Steel Legend RX 9070 XT on Windows, developed from WSL.

---

## Part 1 — Core Application Prompt

> Build me a lightweight Python application to control the RGB lighting on my ASRock RX 9070 XT Steel Legend GPU on Windows.
>
> **How it works technically:**
> The AMD ADL (AMD Display Library) SDK is available as `atiadlxx.dll` on Windows via installed AMD drivers. Use Python `ctypes` to call into it and access the GPU's I2C bus to send color commands.
>
> **I2C Protocol details (reverse engineered):**
> - I2C address: `0x36`
> - Detection: Check AMD GPU I2C buses for ASRock SubVendor `0x1849`
> - Color command: Command `0x10`, subcmd = channel index, data bytes = `[mode, R, G, B, brightness, speed, direction, 0x00]`
> - For static color: mode = `0x01`, brightness = `0xFF`, speed = `0x00`, direction = `0x00`
> - Channels to write to: Channel 3 (ARGB Header), Channel 6 (Top Side), Channel 7 (Fan) — write the same color to all 3
>
> **GUI requirements (tkinter only, no third party GUI libraries):**
> - Single color picker/wheel to select RGB color
> - A text field showing the current hex color code that updates live as the color is picked, and can be typed into directly
> - One "Apply & Save" button that writes the color to all 3 zones and saves it to a config file
> - Show a small status label confirming success or any error
> - Minimal, clean window — only what is described above, nothing extra
> - Window should not be resizable
>
> **Saving & startup behavior:**
> - Save the chosen color to a `config.json` file in the same directory as the script
> - On launch, load the saved color from `config.json` and silently apply it to the GPU immediately before the GUI appears, so the color is restored on every boot when run via Windows Task Scheduler
> - If no config exists yet, default to white `(255, 255, 255)`
>
> **Performance & structure requirements:**
> - Use `tkinter` and `ctypes` only — no third party dependencies beyond what is needed to call the ADL DLL
> - The I2C write logic should be in a separate module/file from the GUI so it can be reused or called headlessly in future
> - Keep the tool as lightweight as possible — minimal memory footprint
> - Include a `--nogui` command line flag that applies the saved color silently and exits immediately, for use in Task Scheduler on startup with zero overhead
>
> **Error handling:**
> - If the ADL DLL cannot be found or the GPU is not detected, show a clear error in the status label rather than crashing
> - Wrap all I2C writes in try/except and report failures clearly

---

## Part 2 — WSL & Windows Environment Addendum

> **Development environment & execution notes:**
>
> - The project is developed inside WSL but the final program must run on Windows 11 natively
> - The repo is empty — scaffold the full project structure from scratch including a `README.md` with setup instructions
> - The Python script must be written to run under the Windows Python interpreter, not the WSL one — use a `run.bat` or `run.ps1` launcher script that explicitly calls the Windows Python executable (e.g. `/mnt/c/...` path or via `cmd.exe /c python`) so it can be triggered correctly from WSL during development and from Task Scheduler in production
> - `atiadlxx.dll` lives in the Windows filesystem — hardcode the standard path (`C:\Windows\System32\atiadlxx.dll`) as the default but allow it to be overridden in `config.json` in case the DLL is elsewhere
> - `config.json` should use a Windows-compatible absolute path or be resolved relative to the script's own location using Windows path logic, not WSL paths
> - The `tkinter` GUI must be launched via the Windows Python interpreter since WSL cannot display Windows native GUI windows without extra configuration — the launcher script should handle this transparently
> - Include a `requirements.txt` even if it ends up empty, for consistency

---

## Part 3 — ADL Diagnostic Script Request

> Also create a standalone diagnostic script called `test_adl.py` that:
> - Attempts to load `atiadlxx.dll` via `ctypes` and reports success or failure with a clear message
> - Lists all detected AMD GPU adapters by name and index
> - Attempts to open the I2C bus on each adapter and probe address `0x36` for the ASRock RGB controller
> - Checks for ASRock SubVendor `0x1849` and reports whether the controller was found
> - Prints all results to the console with no GUI — pure diagnostic output only
> - Exits with code `0` on success (controller found) and code `1` on failure, so it can be used in scripts
>
> This script is for verifying the Windows Python + ADL setup is working correctly in isolation, before the GUI and full application are tested on top of it.

---

## Recommended Usage Order

1. Paste **Part 1 + Part 2 + Part 3** together as a single prompt into Claude Code in your WSL terminal
2. Once generated, run `test_adl.py` first via the Windows Python interpreter to confirm ADL loads and your GPU is detected
3. Only once `test_adl.py` reports success, run the full application via `run.bat` or `run.ps1`
4. To set up silent startup, add a Task Scheduler entry pointing to `pythonw.exe yourscript.py --nogui` triggered at log on

---

## Task Scheduler Setup (for reference after build)

| Field | Value |
|---|---|
| Trigger | At log on |
| Program | `C:\Path\To\pythonw.exe` |
| Arguments | `C:\Path\To\main.py --nogui` |
| Run with highest privileges | ✅ Yes (required for I2C access) |
| Start in | Directory containing `main.py` |
