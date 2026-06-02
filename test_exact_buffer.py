"""
Test using EXACT buffer from Polychrome Frida capture.
R/G/B at offsets 255/256/257 patched at runtime.
All other bytes (including LUID 0x0011002b at offset 212) from capture.
"""
import ctypes, sys

def _build_polychrome_template() -> bytearray:
    buf = bytearray(868)
    # Header (0-7)
    buf[0:8]     = bytes.fromhex("0200000002000100")
    # Size/flags block (72-91)
    buf[72:92]   = bytes.fromhex("6403000080000000000001000000000205000000")
    # Sub-structure sizes (204-211)
    buf[204:212] = bytes.fromhex("5001000050010000")
    # AMD internal LUID (212-219) — from Polychrome capture; NOT a D3DKMT adapter LUID
    buf[212:220] = bytes.fromhex("2b001100" "00000000")
    # I2C command struct (224-251)
    buf[224:252] = bytes.fromhex(
        "40010000"   # struct size = 0x140
        "04000000"
        "02000000"   # iLine = 2
        "6c000000"   # iAddress = 0x6C
        "10000000"   # iOffset = 0x10
        "64000000"   # iSpeed = 100
        "0c000000"   # iDataSize = 12
    )
    # I2C payload prefix (252-254), RGB placeholder (255-257), suffix (258-259)
    buf[252:255] = bytes.fromhex("000911")
    # buf[255] = R  ← patched at runtime
    # buf[256] = G  ← patched at runtime
    # buf[257] = B  ← patched at runtime
    buf[258:260] = bytes.fromhex("8cff")
    # Trailing struct (540-547)
    buf[540:548] = bytes.fromhex("4001000040010000")
    return buf

TEMPLATE = _build_polychrome_template()
assert len(TEMPLATE) == 868


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

class _D3DKMT_ADAPTERINFO(ctypes.Structure):
    _fields_ = [
        ("hAdapter",                     ctypes.c_uint32),
        ("AdapterLuid",                  _LUID),
        ("NumOfSources",                 ctypes.c_uint32),
        ("bPresentMoveRegionsPreferred", ctypes.c_int32),
    ]

class _D3DKMT_ENUMADAPTERS(ctypes.Structure):
    _fields_ = [
        ("NumAdapters", ctypes.c_uint32),
        ("Adapters",    _D3DKMT_ADAPTERINFO * 16),
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


def main():
    r = int(sys.argv[1]) if len(sys.argv) > 1 else 255
    g = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    b = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    gdi32 = ctypes.WinDLL("gdi32.dll")
    enum_data = _D3DKMT_ENUMADAPTERS()
    ret = gdi32.D3DKMTEnumAdapters(ctypes.byref(enum_data))
    if ret != 0:
        print(f"D3DKMTEnumAdapters failed: 0x{ret & 0xFFFFFFFF:08X}")
        sys.exit(1)

    print(f"Sending RGB({r},{g},{b}) — template LUID@212: {TEMPLATE[212:220].hex()}")
    print(f"{enum_data.NumAdapters} adapters")

    for i in range(enum_data.NumAdapters):
        info = enum_data.Adapters[i]
        buf = bytearray(TEMPLATE)
        buf[255] = r & 0xFF
        buf[256] = g & 0xFF
        buf[257] = b & 0xFF

        c_buf = ctypes.create_string_buffer(bytes(buf))
        esc = _D3DKMT_ESCAPE()
        esc.hAdapter              = info.hAdapter
        esc.hDevice               = 0
        esc.Type                  = 0
        esc.Flags                 = 0
        esc.pPrivateDriverData    = ctypes.cast(c_buf, ctypes.c_void_p)
        esc.PrivateDriverDataSize = 868
        esc.hContext              = 0

        nts = gdi32.D3DKMTEscape(ctypes.byref(esc)) & 0xFFFFFFFF
        print(f"  [{i}] hAdapter=0x{info.hAdapter:08X} "
              f"enumLUID={info.AdapterLuid.LowPart:#010x} "
              f"→ 0x{nts:08X} {'OK' if nts==0 else ''}")

    print("Done — check which adapters returned OK and whether LEDs changed after each.")
    sys.exit(0)


if __name__ == "__main__":
    main()
