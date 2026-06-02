"""
Quick test — set LEDs to red via D3DKMTEscape.
Run as Administrator. Watch for LEDs turning red.
Exits 0 on success, 1 on failure.
"""

import sys
import os

# Allow running from repo root without install
sys.path.insert(0, os.path.dirname(__file__))

from adl_i2c import apply_color

def main():
    print("ASRock RX 9070 XT — D3DKMTEscape RGB test")
    print("Setting LEDs to RED (255, 0, 0) …")
    try:
        apply_color(255, 0, 0, verbose=True)
        print("OK — LEDs should now be red.")
        print("Run again with different values to test other colors:")
        print("  python test_adl.py 0 255 0   <- green")
        print("  python test_adl.py 0 0 255   <- blue")
        sys.exit(0)
    except Exception as e:
        print(f"FAIL: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) == 4:
        r, g, b = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
        print(f"Setting LEDs to RGB({r}, {g}, {b}) …")
        try:
            apply_color(r, g, b, verbose=True)
            print("OK")
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: {e}")
            sys.exit(1)
    main()
