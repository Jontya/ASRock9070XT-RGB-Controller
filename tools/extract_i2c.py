"""
Extract the I2C escape call (DataSize=868) from the most recent trace JSON.
Run from the project root directory.
"""
import json
import glob
import os

files = glob.glob("captures/trace_*.json")
if not files:
    print("No trace files found in captures/. Run frida_full_trace.py first.")
    raise SystemExit(1)

f = max(files, key=os.path.getmtime)
print(f"Reading: {f}\n")

data = json.load(open(f))
i2c = [e for e in data if e.get("DataSize") == 868]

print(f"Found {len(i2c)} escape(s) with DataSize=868\n")

for e in i2c:
    bi  = e.get("bufIn", "")
    bo  = e.get("bufOut", "")
    seq = e.get("seq", "?")
    h   = e.get("hAdapter", 0)
    nts = e.get("nts", 0)
    print(f"[seq {seq}]  hAdapter=0x{h:08X}  NTSTATUS=0x{nts:08X}")
    if len(bi) >= 440:
        print(f"  buf[212:220] = {bi[424:440]}")
    if len(bi) >= 520:
        print(f"  buf[252:260] = {bi[504:520]}")
    if len(bi) >= 516:
        r = int(bi[510:512], 16)
        g = int(bi[512:514], 16)
        b = int(bi[514:516], 16)
        print(f"  RGB          = ({r}, {g}, {b})")
    if bo and len(bo) >= 440:
        print(f"  bufOut[212:220]={bo[424:440]}")
    diffs = e.get("bufDiff", [])
    if diffs:
        print(f"  driver wrote back {len(diffs)} bytes")
        for d in diffs[:10]:
            print(f"    offset {d['offset']:>5}: {d['from']} -> {d['to']}")
        if len(diffs) > 10:
            print(f"    ... and {len(diffs)-10} more")
    print()

if not i2c:
    print("No 868-byte escape found.")
    print("Possible reasons:")
    print("  - Polychrome didn't change color during the capture")
    print("  - The I2C escape uses a different DataSize in this session")
    print()
    sizes = {}
    for e in data:
        ds = e.get("DataSize")
        if ds:
            sizes[ds] = sizes.get(ds, 0) + 1
    print("DataSize distribution across all captured escapes:")
    for sz, cnt in sorted(sizes.items()):
        print(f"  {sz:>6} bytes: {cnt} calls")
