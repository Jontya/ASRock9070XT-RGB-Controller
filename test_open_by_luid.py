"""
Try D3DKMTOpenAdapterFromLuid with the LUID captured from Polychrome (0x0011002b).
If it opens, try D3DKMTEscape with the exact Polychrome buffer.
Also tries D3DKMTEnumAdapters2 to see if it exposes more adapters than D3DKMTEnumAdapters.
"""
import ctypes, sys

POLYCHROME_LUID_LOW  = 0x0011002b
POLYCHROME_LUID_HIGH = 0x00000000


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

class _D3DKMT_ADAPTERINFO(ctypes.Structure):
    _fields_ = [
        ("hAdapter",                     ctypes.c_uint32),
        ("AdapterLuid",                  _LUID),
        ("NumOfSources",                 ctypes.c_uint32),
        ("bPresentMoveRegionsPreferred", ctypes.c_int32),
    ]

class _D3DKMT_ENUMADAPTERS2(ctypes.Structure):
    _fields_ = [
        ("NumAdapters", ctypes.c_uint32),
        ("pAdapters",   ctypes.c_void_p),
    ]

class _D3DKMT_OPENADAPTERFROMLUID(ctypes.Structure):
    _fields_ = [
        ("AdapterLuid", _LUID),
        ("hAdapter",    ctypes.c_uint32),
    ]

class _D3DKMT_ESCAPE(ctypes.Structure):
    _fields_ = [
        ("hAdapter",              ctypes.c_uint32),
        ("hDevice",               ctypes.c_uint32),
        ("Type",                  ctypes.c_uint32),
        ("Flags",                 ctypes.c_uint32),
        ("pPrivateDriverData",    ctypes.c_void_p),
        ("PrivateDriverDataSize", ctypes.c_uint32),
        ("hContext",              ctypes.c_uint32),
    ]


def build_template(r, g, b) -> bytes:
    buf = bytearray(868)
    buf[0:8]     = bytes.fromhex("0200000002000100")
    buf[72:92]   = bytes.fromhex("6403000080000000000001000000000205000000")
    buf[204:212] = bytes.fromhex("5001000050010000")
    buf[212:220] = bytes.fromhex("2b00110000000000")
    buf[224:252] = bytes.fromhex("40010000" "04000000" "02000000"
                                 "6c000000" "10000000" "64000000" "0c000000")
    buf[252:255] = bytes.fromhex("000911")
    buf[255] = r & 0xFF
    buf[256] = g & 0xFF
    buf[257] = b & 0xFF
    buf[258:260] = bytes.fromhex("8cff")
    buf[540:548] = bytes.fromhex("4001000040010000")
    return bytes(buf)


def send_escape(gdi32, h_adapter, r, g, b):
    payload = build_template(r, g, b)
    c_buf = ctypes.create_string_buffer(payload)
    esc = _D3DKMT_ESCAPE()
    esc.hAdapter              = h_adapter
    esc.hDevice               = 0
    esc.Type                  = 0
    esc.Flags                 = 0
    esc.pPrivateDriverData    = ctypes.cast(c_buf, ctypes.c_void_p)
    esc.PrivateDriverDataSize = 868
    esc.hContext              = 0
    return gdi32.D3DKMTEscape(ctypes.byref(esc)) & 0xFFFFFFFF


def main():
    r = int(sys.argv[1]) if len(sys.argv) > 1 else 255
    g = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    b = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    gdi32 = ctypes.WinDLL("gdi32.dll")

    # --- 1. Try D3DKMTEnumAdapters2 (may list render-only adapters) ---
    print("=== D3DKMTEnumAdapters2 ===")
    try:
        MAX = 32
        arr = (_D3DKMT_ADAPTERINFO * MAX)()
        ea2 = _D3DKMT_ENUMADAPTERS2()
        ea2.NumAdapters = MAX
        ea2.pAdapters   = ctypes.cast(arr, ctypes.c_void_p)
        ret = gdi32.D3DKMTEnumAdapters2(ctypes.byref(ea2))
        if ret == 0:
            print(f"  {ea2.NumAdapters} adapters")
            for i in range(ea2.NumAdapters):
                a = arr[i]
                print(f"  [{i}] hAdapter=0x{a.hAdapter:08X} "
                      f"LUID={a.AdapterLuid.LowPart:#010x}:{a.AdapterLuid.HighPart:#010x}")
        else:
            print(f"  FAILED: 0x{ret & 0xFFFFFFFF:08X}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # --- 2. Open the Polychrome adapter directly by LUID ---
    print(f"\n=== D3DKMTOpenAdapterFromLuid (LUID={POLYCHROME_LUID_LOW:#010x}) ===")
    open_data = _D3DKMT_OPENADAPTERFROMLUID()
    open_data.AdapterLuid.LowPart  = POLYCHROME_LUID_LOW
    open_data.AdapterLuid.HighPart = POLYCHROME_LUID_HIGH
    ret = gdi32.D3DKMTOpenAdapterFromLuid(ctypes.byref(open_data))
    nts = ret & 0xFFFFFFFF
    print(f"  ret=0x{nts:08X}  hAdapter=0x{open_data.hAdapter:08X}")

    if nts == 0:
        h = open_data.hAdapter
        print(f"  Opened! Sending escape to hAdapter=0x{h:08X} …")
        nts2 = send_escape(gdi32, h, r, g, b)
        print(f"  D3DKMTEscape → 0x{nts2:08X} {'OK — check LEDs!' if nts2 == 0 else ''}")
    else:
        print("  Could not open adapter by Polychrome LUID.")


if __name__ == "__main__":
    main()
