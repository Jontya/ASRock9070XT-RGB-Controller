"""
Analyze trace JSON: map hAdapter→LUID, show escape sequences per LUID.
Focus on init escapes preceding I2C LED writes.

Usage: python tools\analyze_luid_sequence.py [trace_json]
If no arg, uses latest captures/trace_*.json
"""
import json, sys, os, glob

def latest_trace():
    files = sorted(glob.glob("captures/trace_*.json"))
    return files[-1] if files else None

path = sys.argv[1] if len(sys.argv) > 1 else latest_trace()
if not path:
    print("No trace file found"); sys.exit(1)
print(f"Loading {path}")

with open(path) as f:
    events = json.load(f)

# Build hAdapter → LUID map from EnumAdapters events
handle_luid = {}
for ev in events:
    fn = ev.get("fn", "")
    if fn in ("NtGdiDdDDIEnumAdapters", "D3DKMTEnumAdapters",
              "NtGdiDdDDIEnumAdapters2", "D3DKMTEnumAdapters2"):
        for a in ev.get("adapters", []):
            handle_luid[a["hAdapter"]] = a["luidLow"]
    # Also from open calls
    if fn in ("NtGdiDdDDIOpenAdapterFromLuid", "D3DKMTOpenAdapterFromLuid",
              "NtGdiDdDDIOpenAdapterFromGdiDisplayName", "D3DKMTOpenAdapterFromGdiDisplayName",
              "NtGdiDdDDIOpenAdapterFromHdc", "D3DKMTOpenAdapterFromHdc"):
        if ev.get("nts") == 0 and ev.get("hAdapter"):
            luid = ev.get("luidLow", 0)
            if luid:
                handle_luid[ev["hAdapter"]] = luid

# Escape events with LUID annotation
esc_events = []
for ev in events:
    fn = ev.get("fn", "")
    if fn not in ("NtGdiDdDDIEscape", "D3DKMTEscape"):
        continue
    h = ev.get("hAdapter", 0)
    luid = handle_luid.get(h, 0)
    esc_events.append({
        "seq": ev.get("seq"),
        "hAdapter": h,
        "luid": luid,
        "DataSize": ev.get("DataSize", 0),
        "isI2C": ev.get("isI2C", False),
        "nts": ev.get("nts"),
        "bufIn": ev.get("bufIn", ""),
    })

NTSTATUS = {0: "SUCCESS", 0xC000000D: "INVALID_PARAM", 0xC0000001: "UNSUCCESSFUL", 0xC00000BB: "NOT_SUPPORTED", 0xC0000022: "ACCESS_DENIED"}
def nts(v): return NTSTATUS.get(v, f"0x{v:08X}" if v is not None else "?")

# LUIDs present
luids = sorted(set(e["luid"] for e in esc_events if e["luid"]))
print(f"\nLUIDs seen in escapes: {[hex(l) for l in luids]}")

# I2C escapes
i2c = [e for e in esc_events if e["isI2C"]]
print(f"\nTotal I2C (868-byte LED) escapes: {len(i2c)}")
for e in i2c[:10]:
    print(f"  seq={e['seq']} hAdapter=0x{e['hAdapter']:08X} LUID=0x{e['luid']:08X} {nts(e['nts'])}")
    if e["bufIn"]:
        buf = bytes.fromhex(e["bufIn"])
        r, g, b = buf[255], buf[256], buf[257]
        print(f"    RGB=({r},{g},{b})  iLine={int.from_bytes(buf[232:236],'little')}  iAddr=0x{int.from_bytes(buf[236:240],'little'):02X}")

# For each LUID, show DataSize sequence of escapes (condensed)
print("\n--- Escape DataSize sequence per LUID ---")
for luid in luids:
    evs = [e for e in esc_events if e["luid"] == luid]
    print(f"\nLUID 0x{luid:08X}: {len(evs)} escapes")
    sizes = [e["DataSize"] for e in evs]
    # Condense: show first 40, mark I2C
    for e in evs[:60]:
        marker = " *** I2C ***" if e["isI2C"] else ""
        print(f"  seq={e['seq']:>4} DataSize={e['DataSize']:>5}{marker}  {nts(e['nts'])}")

# Show first I2C escape buffer header
print("\n--- First I2C escape bufIn header (offset 0..263) ---")
for e in i2c[:1]:
    if e["bufIn"]:
        buf = bytes.fromhex(e["bufIn"])
        for off in range(0, min(264, len(buf)), 16):
            chunk = buf[off:off+16]
            hex_s = " ".join(f"{b:02x}" for b in chunk)
            print(f"  {off:>3}: {hex_s}")

# Show escapes immediately BEFORE first I2C for same LUID
if i2c:
    first_i2c = i2c[0]
    target_luid = first_i2c["luid"]
    first_seq = first_i2c["seq"]
    print(f"\n--- Escapes to LUID 0x{target_luid:08X} BEFORE first I2C (seq {first_seq}) ---")
    preceding = [e for e in esc_events if e["luid"] == target_luid and e["seq"] < first_seq]
    for e in preceding[-20:]:
        marker = " I2C" if e["isI2C"] else ""
        buf_preview = e["bufIn"][:32] if e["bufIn"] else ""
        print(f"  seq={e['seq']:>4} DataSize={e['DataSize']:>5}{marker}  {nts(e['nts'])}  buf[0:16]={buf_preview[:32]}")

print("\nDone.")
