"""
ASRock RX 9070 XT Steel Legend — RGB Controller
Run on Windows Python. Use run.bat or run.ps1 from WSL.
"""

import argparse
import os
import sys
import tkinter as tk
from tkinter import colorchooser

# Resolve paths relative to this script (works whether called from WSL or Windows)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

from adl_i2c import apply_color, load_config, save_config, DEFAULT_DLL_PATH


# ---------------------------------------------------------------------------
# Headless apply
# ---------------------------------------------------------------------------

def apply_saved_color(config: dict) -> str:
    """Apply color from config. Returns '' on success or error string."""
    try:
        apply_color(config["r"], config["g"], config["b"], config.get("dll_path", DEFAULT_DLL_PATH))
        return ""
    except Exception as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class RGBApp(tk.Tk):
    def __init__(self, config: dict):
        super().__init__()
        self._config = config
        self._r = config["r"]
        self._g = config["g"]
        self._b = config["b"]

        self.title("ASRock RGB Controller")
        self.resizable(False, False)
        self._build_ui()
        self._update_swatch()

    def _build_ui(self) -> None:
        pad = {"padx": 12, "pady": 8}

        # Color swatch
        self._swatch = tk.Label(self, width=16, height=4, relief="solid", bd=1)
        self._swatch.grid(row=0, column=0, columnspan=2, **pad)

        # Color picker button
        pick_btn = tk.Button(self, text="Pick Color…", command=self._pick_color)
        pick_btn.grid(row=1, column=0, **pad, sticky="ew")

        # Hex entry
        self._hex_var = tk.StringVar(value=self._rgb_to_hex())
        self._hex_entry = tk.Entry(self, textvariable=self._hex_var, width=10,
                                   justify="center", font=("Consolas", 12))
        self._hex_entry.grid(row=1, column=1, **pad, sticky="ew")
        self._hex_var.trace_add("write", self._on_hex_changed)

        # Apply & Save button
        apply_btn = tk.Button(self, text="Apply & Save", command=self._apply_and_save,
                              bg="#2d7dd2", fg="white", font=("Segoe UI", 10, "bold"),
                              relief="flat", padx=8, pady=4)
        apply_btn.grid(row=2, column=0, columnspan=2, **pad, sticky="ew")

        # Status label
        self._status = tk.Label(self, text="", fg="gray", font=("Segoe UI", 9))
        self._status.grid(row=3, column=0, columnspan=2, pady=(0, 10))

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

    # ------------------------------------------------------------------

    def _pick_color(self) -> None:
        init = self._rgb_to_hex()
        result = colorchooser.askcolor(color=init, title="Choose RGB Color")
        if result and result[0]:
            rgb = result[0]
            self._r, self._g, self._b = int(rgb[0]), int(rgb[1]), int(rgb[2])
            self._hex_var.set(self._rgb_to_hex())
            self._update_swatch()

    def _on_hex_changed(self, *_) -> None:
        raw = self._hex_var.get().lstrip("#")
        if len(raw) == 6:
            try:
                self._r = int(raw[0:2], 16)
                self._g = int(raw[2:4], 16)
                self._b = int(raw[4:6], 16)
                self._update_swatch()
                self._set_status("")
            except ValueError:
                pass

    def _apply_and_save(self) -> None:
        self._set_status("Applying…")
        self.update_idletasks()
        dll = self._config.get("dll_path", DEFAULT_DLL_PATH)
        try:
            apply_color(self._r, self._g, self._b, dll)
            save_config(CONFIG_PATH, self._r, self._g, self._b, dll)
            self._config.update(r=self._r, g=self._g, b=self._b)
            self._set_status(f"Applied #{self._rgb_to_hex()[1:].upper()}", ok=True)
        except Exception as exc:
            self._set_status(f"Error: {exc}", ok=False)

    def _update_swatch(self) -> None:
        self._swatch.configure(bg=self._rgb_to_hex())

    def _rgb_to_hex(self) -> str:
        return f"#{self._r:02x}{self._g:02x}{self._b:02x}"

    def _set_status(self, msg: str, ok: bool = True) -> None:
        color = "#2a9d2a" if ok else "#c0392b"
        self._status.configure(text=msg, fg=color if msg else "gray")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ASRock RX 9070 XT RGB Controller")
    parser.add_argument("--nogui", action="store_true",
                        help="Apply saved color silently and exit (for Task Scheduler)")
    args = parser.parse_args()

    config = load_config(CONFIG_PATH)

    if args.nogui:
        err = apply_saved_color(config)
        if err:
            print(f"ERROR: {err}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # Silently apply saved color before showing GUI
    apply_saved_color(config)

    app = RGBApp(config)
    app.mainloop()


if __name__ == "__main__":
    main()
