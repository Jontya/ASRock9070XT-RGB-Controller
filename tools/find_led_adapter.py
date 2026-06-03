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

# --- Build handle → display name map (key is 'devName' in JSON) ---
handle_to_display = {}

open_calls = [e for e in data if "OpenAdapterFromGdiDisplayName" in e.get("fn", "")]

print(f"OpenAdapterFromGdiDisplayName calls: {len(open_calls)}")
if open_calls:
    print(f"\n{'seq':>5}  {'hAdapter':>12}  {'NTSTATUS':>12}  {'devName'}")
    print("-" * 75)
    for e in open_calls:
        seq = e.get("seq", "?")
        h   = e.get("hAdapter", 0)
        nts = e.get("nts", 0) & 0xFFFFFFFF
        dn  = e.get("devName", "(not captured)")
        lll = e.get("luidLow", 0)
        llh = e.get("luidHigh", 0)
        print(f"  {seq:>5}  0x{h:08X}  0x{nts:08X}  {dn}")
        if nts == 0 and h:
            handle_to_display[h] = dn
print()

# --- D3DKMTEnumAdapters events ---
enum_calls = [e for e in data if "EnumAdapters" in e.get("fn", "")]
print(f"D3DKMTEnumAdapters calls: {len(enum_calls)}")
for e in enum_calls:
    print(f"  seq={e['seq']} numAdapters={e.get('numAdapters','?')} nts=0x{e.get('nts',0)&0xFFFFFFFF:08X}")
print()

# --- Identify handles used in color-set escapes (RGB != 0, DataSize=868) ---
color_handles = set()
scan_handles  = set()
for e in data:
    if e.get("DataSize") != 868:
        continue
    bi = e.get("bufIn", "")
    if len(bi) < 516:
        continue
    r = int(bi[510:512], 16)
    g = int(bi[512:514], 16)
    b = int(bi[514:516], 16)
    h = e.get("hAdapter", 0)
    if r != 0 or g != 0 or b != 0:
        color_handles.add(h)
    else:
        scan_handles.add(h)

print(f"Handles used for SCAN escapes (RGB=0): {len(scan_handles)}")
for h in sorted(scan_handles):
    dn = handle_to_display.get(h, "(unknown)")
    print(f"  0x{h:08X}  {dn}")

print(f"\nHandles used for COLOR-SET escapes (RGB!=0): {len(color_handles)}")
for h in sorted(color_handles):
    dn = handle_to_display.get(h, "(unknown)")
    print(f"  0x{h:08X}  {dn}")

# --- All keys present in OpenAdapter events (for debugging) ---
if open_calls:
    all_keys = set()
    for e in open_calls:
        all_keys.update(e.keys())
    print(f"\nAll JSON keys in OpenAdapterFromGdiDisplayName events: {sorted(all_keys)}")

# --- All event types ---
from collections import Counter
c = Counter(e.get("fn", "unknown") for e in data)
print(f"\nAll event types:")
for fn, count in sorted(c.items()):
    print(f"  {count:>5}x  {fn}")
