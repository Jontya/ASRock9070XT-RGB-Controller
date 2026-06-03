"""
Extract D3DKMTOpenAdapterFromGdiDisplayName calls from trace JSON.
Maps hAdapter → display name to identify which display Polychrome used for LED writes.

Usage:
    python tools\\find_led_adapter.py
"""

import json
import glob
import os
import sys

files = glob.glob("captures/trace_*.json")
if not files:
    print("No trace files. Run frida_full_trace.py first.")
    sys.exit(1)

f = max(files, key=os.path.getmtime)
print(f"Reading: {f}\n")

data = json.load(open(f))

# --- Build handle → display name map from OpenAdapterFromGdiDisplayName calls ---
handle_to_display = {}

open_calls = [e for e in data if "OpenAdapterFromGdiDisplayName" in e.get("fn", "")
              or e.get("type") == "OpenAdapterFromGdiDisplayName"]

print(f"OpenAdapterFromGdiDisplayName calls: {len(open_calls)}")
if open_calls:
    print(f"\n{'seq':>5}  {'hAdapter':>12}  {'NTSTATUS':>12}  display")
    print("-" * 70)
    for e in open_calls:
        seq = e.get("seq", "?")
        h   = e.get("hAdapter", e.get("hAdapterOut", 0))
        nts = e.get("nts", e.get("NTSTATUS", 0))
        dn  = e.get("DeviceName", e.get("displayName", e.get("display", "?")))
        nts_v = nts & 0xFFFFFFFF if isinstance(nts, int) else 0
        print(f"  {seq:>5}  0x{h:08X}  0x{nts_v:08X}  {dn}")
        if nts_v == 0 and h:
            handle_to_display[h] = dn
else:
    print("  (none — Frida may not have captured these calls)")
    print("  Trying alternate key names in JSON entries...")
    # Dump all unique 'fn' or 'type' values seen
    fns = set()
    for e in data:
        fns.add(e.get("fn", e.get("type", "")))
    print(f"\n  All event types in trace:")
    for fn in sorted(fns):
        if fn:
            print(f"    {fn}")

print()

# --- Identify handles used in color-set escapes (RGB != 0, DataSize=868) ---
color_handles = set()
for e in data:
    if e.get("DataSize") != 868:
        continue
    bi = e.get("bufIn", "")
    if len(bi) < 516:
        continue
    r = int(bi[510:512], 16)
    g = int(bi[512:514], 16)
    b = int(bi[514:516], 16)
    if r != 0 or g != 0 or b != 0:
        color_handles.add(e.get("hAdapter", 0))

print(f"Adapter handles used for color-set escapes (RGB!=0): {len(color_handles)}")
for h in sorted(color_handles):
    dn = handle_to_display.get(h, "(display unknown)")
    print(f"  hAdapter=0x{h:08X}  →  {dn}")

# --- If we have the mapping, identify the display name we need ---
if handle_to_display and color_handles:
    print("\n=== Display names to try for LED control ===")
    for h in sorted(color_handles):
        if h in handle_to_display:
            print(f"  hAdapter=0x{h:08X}  ← open \\\\.\\\\ {handle_to_display[h]}")
        else:
            print(f"  hAdapter=0x{h:08X}  ← handle not in open-call log (may be EnumAdapters)")

# --- Also dump all events to show what frida captured ---
print(f"\n=== All event types and counts ===")
from collections import Counter
c = Counter(e.get("fn", e.get("type", "unknown")) for e in data)
for fn, count in sorted(c.items()):
    print(f"  {count:>5}x  {fn}")
