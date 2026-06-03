"""
enum_adapters_escape.py — Enumerate all D3DKMT adapters (WoW64 path) and send
the captured Polychrome escape to every returned handle.

Polychrome (32-bit) sees ~31 adapters via D3DKMTEnumAdapters; our 64-bit
OpenAdapterFromGdiDisplayName only gives slot 0. This script finds slot 57
(0x40000E40) and any other handles that actually move the LEDs.

MUST run with 32-bit Python:
    C:\\Python312-32\\python.exe tools\\enum_adapters_escape.py

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

# ---------------------------------------------------------------------------
if struct.calcsize("P") != 4:
    print("ERROR: must run with 32-bit Python (sys.maxsize should be 2147483647)")
    print(f"       Current pointer size: {struct.calcsize('P')*8}-bit")
    sys.exit(1)

print(f"Python: {sys.version}")
print(f"Pointer size: {struct.calcsize('P')*8}-bit  OK")

# ---------------------------------------------------------------------------
MAX_ADAPTERS = 64  # D3DKMTEnumAdapters2 call; D3DKMTEnumAdapters caps at 16


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]


class D3DKMT_ADAPTERINFO(ctypes.Structure):
    _fields_ = [
        ("hAdapter",                    ctypes.c_uint32),
        ("AdapterLuid",                 LUID),
        ("NumOfSources",                ctypes.c_uint32),
        ("bPresentMoveRegionsPreferred", ctypes.c_uint32),
    ]


class D3DKMT_ENUMADAPTERS(ctypes.Structure):
    _fields_ = [
        ("NumAdapters", ctypes.c_uint32),
        ("Adapters",    D3DKMT_ADAPTERINFO * 16),  # kernel max for v1
    ]


class D3DKMT_ENUMADAPTERS2(ctypes.Structure):
    _fields_ = [
        ("NumAdapters", ctypes.c_uint32),
        ("pAdapters",   ctypes.c_void_p),
    ]


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


class D3DKMT_CLOSEADAPTER(ctypes.Structure):
    _fields_ = [("hAdapter", ctypes.c_uint32)]


# ---------------------------------------------------------------------------
def load_capture():
    files = glob.glob("captures/trace_*.json")
    if not files:
        print("No trace files in captures/")
        sys.exit(1)
    f = max(files, key=os.path.getmtime)
    print(f"Capture: {f}")
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
            buf = bytes.fromhex(bi)
            print(f"Using seq={e['seq']} RGB=({r},{g},{b}) bufLen={len(buf)}")
            return buf
    print("No color-set escape found in capture")
    sys.exit(1)


def enum_adapters(gdi32):
    """Try D3DKMTEnumAdapters2 first (dynamic), fall back to v1 (16 max)."""
    adapters = []

    # --- try EnumAdapters2 ---
    try:
        fn2 = gdi32.D3DKMTEnumAdapters2
        # First call: get count
        ea2 = D3DKMT_ENUMADAPTERS2()
        ea2.NumAdapters = 0
        ea2.pAdapters = None
        ret = fn2(ctypes.byref(ea2))
        count = ea2.NumAdapters
        print(f"D3DKMTEnumAdapters2 count query: {nts(ret)} NumAdapters={count}")
        if (ret & 0xFFFFFFFF) == 0 and count > 0:
            arr = (D3DKMT_ADAPTERINFO * count)()
            ea2.NumAdapters = count
            ea2.pAdapters = ctypes.cast(arr, ctypes.c_void_p)
            ret2 = fn2(ctypes.byref(ea2))
            print(f"D3DKMTEnumAdapters2 fill:  {nts(ret2)} NumAdapters={ea2.NumAdapters}")
            if (ret2 & 0xFFFFFFFF) == 0:
                for i in range(ea2.NumAdapters):
                    adapters.append((arr[i].hAdapter, arr[i].AdapterLuid.LowPart, arr[i].AdapterLuid.HighPart))
                return adapters
    except AttributeError:
        pass

    # --- fall back to EnumAdapters v1 ---
    ea = D3DKMT_ENUMADAPTERS()
    ea.NumAdapters = 16
    ret = gdi32.D3DKMTEnumAdapters(ctypes.byref(ea))
    print(f"D3DKMTEnumAdapters v1: {nts(ret)} NumAdapters={ea.NumAdapters}")
    if (ret & 0xFFFFFFFF) == 0:
        for i in range(ea.NumAdapters):
            adapters.append((ea.Adapters[i].hAdapter, ea.Adapters[i].AdapterLuid.LowPart, ea.Adapters[i].AdapterLuid.HighPart))
    return adapters


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

    gdi32 = ctypes.WinDLL("gdi32.dll")
    d3d11 = ctypes.WinDLL("d3d11.dll")
    escape_fn = d3d11.D3DKMTEscape

    print()
    adapters = enum_adapters(gdi32)
    if not adapters:
        print("No adapters returned — EnumAdapters failed entirely.")
        sys.exit(1)

    print(f"\n{len(adapters)} adapter(s) found:")
    for i, (h, luid_lo, luid_hi) in enumerate(adapters):
        print(f"  [{i:2d}] hAdapter=0x{h:08X}  LUID={luid_hi:08X}:{luid_lo:08X}")

    print(f"\n=== Sending RED escape to all {len(adapters)} adapter(s) ===")
    print("Watch LEDs for each call.\n")

    success_handles = []
    for i, (h, luid_lo, luid_hi) in enumerate(adapters):
        ret = send_escape(escape_fn, h, captured_buf, 255, 0, 0)
        status = nts(ret)
        print(f"  [{i:2d}] hAdapter=0x{h:08X}  {status}")
        if ret == 0:
            success_handles.append((i, h, luid_lo, luid_hi))

    print(f"\n{len(success_handles)} adapter(s) returned STATUS_SUCCESS.")

    if not success_handles:
        print("No SUCCESS — wrong DLL, wrong buffer, or no LED hardware.")
        sys.exit(1)

    if len(success_handles) == 1:
        i, h, luid_lo, luid_hi = success_handles[0]
        print(f"Only one SUCCESS: [{i}] hAdapter=0x{h:08X}")
        print("Did LEDs change to RED? (check hardware)")
    else:
        print("\nMultiple SUCCESS handles — sending color sequence to identify LED handle:")
        for i, h, luid_lo, luid_hi in success_handles:
            print(f"\n  Sending RED to [{i}] hAdapter=0x{h:08X} LUID={luid_hi:08X}:{luid_lo:08X} ...")
            send_escape(escape_fn, h, captured_buf, 255, 0, 0)
            print("  >> Did LEDs go RED? (wait 3s)")
            time.sleep(3)
            send_escape(escape_fn, h, captured_buf, 0, 0, 0)  # off
            time.sleep(1)

    # Close all handles
    ca = D3DKMT_CLOSEADAPTER()
    for _, h, _, _ in success_handles:
        ca.hAdapter = h
        gdi32.D3DKMTCloseAdapter(ctypes.byref(ca))


if __name__ == "__main__":
    main()
