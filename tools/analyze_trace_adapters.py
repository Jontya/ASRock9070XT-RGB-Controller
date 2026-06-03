"""
analyze_trace_adapters.py — Extract all unique hAdapter values from the Frida trace.
Shows how many escapes each adapter got, what DataSizes, and the slot number pattern.

Usage: python tools\analyze_trace_adapters.py
"""
import json, glob, os, sys

files = glob.glob("captures/trace_*.json")
if not files:
    print("No trace files in captures/"); sys.exit(1)
f = max(files, key=os.path.getmtime)
print(f"Trace: {f}\n")
data = json.load(open(f))
print(f"Total events: {len(data)}")

adapters = {}
for e in data:
    h = e.get("hAdapter")
    if h is None:
        continue
    if h not in adapters:
        adapters[h] = {"count": 0, "sizes": set(), "first_seq": e.get("seq")}
    adapters[h]["count"] += 1
    adapters[h]["sizes"].add(e.get("DataSize", 0))

def slot(h):
    try:
        v = int(h, 16) if isinstance(h, str) else h
        return (v - 0x40000000) // 0x40
    except:
        return -1

print(f"Unique hAdapter values: {len(adapters)}\n")
print(f"{'hAdapter':>12}  {'slot':>4}  {'count':>5}  DataSizes")
for h, info in sorted(adapters.items(), key=lambda x: slot(x[0])):
    sizes = ",".join(str(s) for s in sorted(info["sizes"]))
    s = slot(h)
    h_str = f"0x{int(h,16):08X}" if isinstance(h, str) else f"0x{h:08X}"
    print(f"  {h_str}  {s:>4}  {info['count']:>5}  [{sizes}]")

print()
# Specifically flag slot 57
target = [h for h in adapters if slot(h) == 57]
if target:
    print(f"Slot 57 (0x40000E40): {adapters[target[0]]['count']} escape(s), first_seq={adapters[target[0]]['first_seq']}")
else:
    print("Slot 57 (0x40000E40) NOT found in trace hAdapter values")

# Show min/max slot
slots = [(slot(h), h) for h in adapters]
slots.sort()
print(f"Slot range: {slots[0][0]}..{slots[-1][0]}")
