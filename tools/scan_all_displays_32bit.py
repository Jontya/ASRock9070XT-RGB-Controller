"""
scan_all_displays_32bit.py — Try D3DKMTOpenAdapterFromGdiDisplayName on DISPLAY1..DISPLAY50
in 32-bit Python. Reports every handle that opens and sends LED escape to any NEW handle
(not slot 0x40000000 which we know silently succeeds but does nothing).

Polychrome (32-bit) scans ~31 display names and gets slot 57 (0x40000E40). That handle is
unreachable from 64-bit (DISPLAY19-21 return STATUS_UNSUCCESSFUL in 64-bit). 32-bit may
succeed on those inactive displays and get different adapter slots.

MUST run with 32-bit Python:
    C:\\Python312-32\\python.exe tools\\scan_all_displays_32bit.py

Run as Administrator.
"""

import ctypes
import glob
import json
import os
import struct
import sys
import time

# ---------------------------------------------------------------------------
NTSTATUS = {
    0x00000000: "STATUS_SUCCESS",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000022: "STATUS_ACCESS_DENIED",
}

def nts(v):
    v &= 0xFFFFFFFF
    return f"0x{v:08X} ({NTSTATUS.get(v, '?')})"

if struct.calcsize("P") != 4:
    print(f"ERROR: must run with 32-bit Python (got {struct.calcsize('P')*8}-bit)")
    sys.exit(1)

print(f"Python: {sys.version}")
print(f"Pointer size: {struct.calcsize('P')*8}-bit  OK")

# ---------------------------------------------------------------------------
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

class D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME(ctypes.Structure):
    _fields_ = [
        ("DeviceName",    ctypes.c_wchar * 32),
        ("hAdapter",      ctypes.c_uint32),
        ("AdapterLuid",   LUID),
        ("VidPnSourceId", ctypes.c_uint32),
    ]

class D3DKMT_CLOSEADAPTER(ctypes.Structure):
    _fields_ = [("hAdapter", ctypes.c_uint32)]

class D3DKMT_ESCAPE(ctypes.Structure):
    _fields_ = [
        ("hAdapter",              ctypes.c_uint32),
        ("hDevice",               ctypes.c_uint32),
        ("Type",                  ctypes.c_uint32),
        ("Flags",                 ctypes.c_uint32),
        ("pPrivateDriverData",    ctypes.c_void_p),
        ("PrivateDriverDataSize", ctypes.c_uint32),
        ("hContext",              ctypes.c_uint32),
    ]

# ---------------------------------------------------------------------------
def load_capture():
    files = glob.glob("captures/trace_*.json")
    if not files:
        print("No trace files in captures/")
        sys.exit(1)
    f = max(files, key=os.path.getmtime)
    data = json.load(open(f))
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
            return bytes.fromhex(bi)
    print("No color-set escape in capture")
    sys.exit(1)

def send_escape(escape_fn, h_adapter, buf868: bytes, r: int, g: int, b: int):
    buf = bytearray(buf868)
    buf[255] = r & 0xFF
    buf[256] = g & 0xFF
    buf[257] = b & 0xFF
    c_buf = ctypes.create_string_buffer(bytes(buf))
    esc = D3DKMT_ESCAPE()
    esc.hAdapter              = h_adapter
    esc.hDevice               = 0
    esc.Type                  = 0
    esc.Flags                 = 0
    esc.pPrivateDriverData    = ctypes.cast(c_buf, ctypes.c_void_p)
    esc.PrivateDriverDataSize = 868
    esc.hContext              = 0
    ret = escape_fn(ctypes.byref(esc))
    return ret & 0xFFFFFFFF

# ---------------------------------------------------------------------------
def main():
    captured_buf = load_capture()

    gdi32  = ctypes.WinDLL("gdi32.dll")
    d3d11  = ctypes.WinDLL("d3d11.dll")
    escape_fn = d3d11.D3DKMTEscape

    # Scan DISPLAY1..DISPLAY50
    opened = {}   # devName -> (hAdapter, luid_lo)
    ca = D3DKMT_CLOSEADAPTER()

    print("\n=== Scanning DISPLAY1..DISPLAY50 ===")
    for n in range(1, 51):
        name = f"\\\\.\\DISPLAY{n}"
        st = D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME()
        st.DeviceName = name
        ret = gdi32.D3DKMTOpenAdapterFromGdiDisplayName(ctypes.byref(st))
        v = ret & 0xFFFFFFFF
        if v == 0:
            luid = st.AdapterLuid.LowPart
            h = st.hAdapter
            print(f"  DISPLAY{n:2d}  hAdapter=0x{h:08X}  LUID=0x{luid:08X}  OK")
            opened[name] = (h, luid)
        elif v == 0xC0000001:  # STATUS_UNSUCCESSFUL
            pass  # skip silently
        else:
            print(f"  DISPLAY{n:2d}  {nts(v)}")

    print(f"\n{len(opened)} display(s) opened successfully.")
    if not opened:
        sys.exit(1)

    # Unique adapter handles (one display may share an hAdapter with another)
    unique_handles = {}  # hAdapter -> first devName
    for name, (h, luid) in opened.items():
        if h not in unique_handles:
            unique_handles[h] = (name, luid)

    print(f"{len(unique_handles)} unique hAdapter value(s):")
    for h, (name, luid) in sorted(unique_handles.items()):
        print(f"  hAdapter=0x{h:08X}  LUID=0x{luid:08X}  ({name})")

    print(f"\n=== Sending RED escape to each unique adapter ===")
    print("Watch LEDs.\n")

    for h, (name, luid) in sorted(unique_handles.items()):
        ret = send_escape(escape_fn, h, captured_buf, 255, 0, 0)
        print(f"  hAdapter=0x{h:08X}  {name}  {nts(ret)}")

    # Now iterate and pause on each SUCCESS to observe LEDs
    success = [(h, name, luid) for h, (name, luid) in sorted(unique_handles.items())
               if send_escape(escape_fn, h, captured_buf, 0, 0, 0) == 0]  # reset to off first

    print(f"\n=== Cycling RED/OFF on each SUCCESS handle ===")
    for h, name, luid in success:
        print(f"\n  RED -> hAdapter=0x{h:08X} ({name}) LUID=0x{luid:08X}")
        send_escape(escape_fn, h, captured_buf, 255, 0, 0)
        time.sleep(3)
        print(f"  OFF -> hAdapter=0x{h:08X}")
        send_escape(escape_fn, h, captured_buf, 0, 0, 0)
        time.sleep(1)

    # Close all
    for name, (h, luid) in opened.items():
        ca.hAdapter = h
        gdi32.D3DKMTCloseAdapter(ctypes.byref(ca))

    print("\nDone.")

if __name__ == "__main__":
    main()
