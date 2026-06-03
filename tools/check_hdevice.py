"""Extract hDevice and hContext values from the trace to check if Polychrome uses non-zero device handles."""
import json, glob, os, sys

files = glob.glob("captures/trace_*.json")
if not files:
    print("No trace files."); sys.exit(1)
f = max(files, key=os.path.getmtime)
print(f"Reading: {f}\n")
data = json.load(open(f))

# D3DKMTCreateDevice calls
devs = [e for e in data if e.get("fn") == "D3DKMTCreateDevice"]
print(f"D3DKMTCreateDevice calls: {len(devs)}")
for e in devs:
    print(f"  seq={e['seq']} hAdapter=0x{e.get('hAdapter',0):08X} "
          f"hDevice=0x{e.get('hDevice',0):08X} nts=0x{e.get('nts',0)&0xFFFFFFFF:08X}")

print()
print("868-byte escapes — hDevice and hContext:")
print(f"{'seq':>4}  {'hAdapter':>12}  {'hDevice':>12}  {'hContext':>12}  RGB")
print("-"*65)
for e in data:
    if e.get("DataSize") != 868: continue
    bi = e.get("bufIn","")
    r = int(bi[510:512],16) if len(bi)>=516 else 0
    g = int(bi[512:514],16) if len(bi)>=516 else 0
    b = int(bi[514:516],16) if len(bi)>=516 else 0
    ha = e.get("hAdapter",0)
    hd = e.get("hDevice",0)
    hc = e.get("hContext",0)
    nts = e.get("nts",0) & 0xFFFFFFFF
    flag = " *** COLOR" if (r or g or b) else ""
    print(f"{e['seq']:>4}  0x{ha:08X}  0x{hd:08X}  0x{hc:08X}  ({r},{g},{b}){flag}")
