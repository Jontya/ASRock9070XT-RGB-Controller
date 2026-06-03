"""
Targeted D3DKMTEscape test using D3DKMTOpenAdapterFromGdiDisplayName.

Tries DISPLAY1 and DISPLAY2 (both map to RX 9070 XT, LUID=0x00016B5B).
Tests several values at buffer offset 212 to find what the AMD driver accepts.

Run as Administrator. Close Polychrome first.

Usage:
    python tools\\test_d3dkmt.py
"""

import ctypes
import struct
import sys

# ---------------------------------------------------------------------------
# NTSTATUS
# ---------------------------------------------------------------------------
NTSTATUS = {
    0x00000000: "STATUS_SUCCESS",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000022: "STATUS_ACCESS_DENIED",
}

def nts(ret):
    v = ret & 0xFFFFFFFF
    return f"0x{v:08X} ({NTSTATUS.get(v, '?')})"

# ---------------------------------------------------------------------------
# Structs (x64 layout)
# ---------------------------------------------------------------------------
class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

class _D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME(ctypes.Structure):
    _fields_ = [
        ("DeviceName",    ctypes.c_wchar * 32),
        ("hAdapter",      ctypes.c_uint32),
        ("AdapterLuid",   _LUID),
        ("VidPnSourceId", ctypes.c_uint32),
    ]

class _D3DKMT_CLOSEADAPTER(ctypes.Structure):
    _fields_ = [("hAdapter", ctypes.c_uint32)]

class _D3DKMT_ESCAPE(ctypes.Structure):
    _fields_ = [
        ("hAdapter",             ctypes.c_uint32),
        ("hDevice",              ctypes.c_uint32),
        ("Type",                 ctypes.c_uint32),
        ("Flags",                ctypes.c_uint32),
        ("pPrivateDriverData",   ctypes.c_void_p),
        ("PrivateDriverDataSize",ctypes.c_uint32),
        ("hContext",             ctypes.c_uint32),
    ]

# ---------------------------------------------------------------------------
# 868-byte template (from Polychrome capture)
# ---------------------------------------------------------------------------
_SZ = 868

def _make_template() -> bytearray:
    buf = bytearray(_SZ)
    buf[0:8]     = bytes([0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00])
    buf[72:92]   = bytes([0x64, 0x03, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02,
                          0x05, 0x00, 0x00, 0x00])
    buf[204:212] = bytes([0x50, 0x01, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00])
    # offset 212-219: AMD subcommand field — variants tested below
    buf[224:252] = bytes([
        0x40, 0x01, 0x00, 0x00,   # I2C struct size = 0x140
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,   # iLine    = 2
        0x6c, 0x00, 0x00, 0x00,   # iAddress = 0x6C
        0x10, 0x00, 0x00, 0x00,   # iOffset  = 0x10
        0x64, 0x00, 0x00, 0x00,   # iSpeed   = 100
        0x0c, 0x00, 0x00, 0x00,   # iDataSize= 12
    ])
    buf[252:255] = bytes([0x00, 0x09, 0x11])
    buf[258:260] = bytes([0x8c, 0xff])
    buf[540:548] = bytes([0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00])
    return buf

_TMPL = _make_template()

# ---------------------------------------------------------------------------
# Open adapter from GDI display name
# ---------------------------------------------------------------------------
def open_adapter(gdi32, display_name: str):
    st = _D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME()
    st.DeviceName = display_name
    ret = gdi32.D3DKMTOpenAdapterFromGdiDisplayName(ctypes.byref(st))
    nts_v = ret & 0xFFFFFFFF
    if ret == 0:
        return st.hAdapter, st.AdapterLuid.LowPart, st.AdapterLuid.HighPart
    return None, None, None


def close_adapter(gdi32, h):
    ca = _D3DKMT_CLOSEADAPTER()
    ca.hAdapter = h
    gdi32.D3DKMTCloseAdapter(ctypes.byref(ca))


# ---------------------------------------------------------------------------
# Send escape
# ---------------------------------------------------------------------------
def try_escape(escape_fn, h_adapter, luid_low, luid_high,
               buf212: bytes, r: int, g: int, b: int,
               label: str) -> int:
    buf = bytearray(_TMPL)
    buf[212:220] = buf212
    buf[255] = r & 0xFF
    buf[256] = g & 0xFF
    buf[257] = b & 0xFF

    c_buf = ctypes.create_string_buffer(bytes(buf))
    esc = _D3DKMT_ESCAPE()
    esc.hAdapter              = h_adapter
    esc.hDevice               = 0
    esc.Type                  = 0
    esc.Flags                 = 0
    esc.pPrivateDriverData    = ctypes.cast(c_buf, ctypes.c_void_p)
    esc.PrivateDriverDataSize = _SZ
    esc.hContext              = 0

    ret = escape_fn(ctypes.byref(esc))
    v   = ret & 0xFFFFFFFF
    sym = NTSTATUS.get(v, "?")
    print(f"  [{label}] buf212={buf212.hex()} → {v:#010x} {sym}")
    return v


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    gdi32 = ctypes.WinDLL("gdi32.dll")
    d3d11 = ctypes.WinDLL("d3d11.dll")

    # Escape function options — Polychrome uses NtGdiDdDDIEscape (via gdi32/d3d11)
    escape_fns = [
        (gdi32.D3DKMTEscape, "gdi32"),
        (d3d11.D3DKMTEscape, "d3d11"),
    ]

    # buf[212] variants to test:
    # A: original from Polychrome Frida capture (prior session)
    # B: zeros
    # C: dGPU LUID (0x00016B5B:0x00000000)
    # D: 0x00110001 (seen in 260-byte calls this session at offset 212)
    # E: 0x00110043 (0x0011002b incremented — maybe a counter, or wrong; 0x43=67)
    LUID_LOW  = 0x00016B5B
    LUID_HIGH = 0x00000000
    variants = [
        ("original-capture",  bytes([0x2b, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00])),
        ("zeros",             bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
        ("luid-low-high",     struct.pack("<II", LUID_LOW, LUID_HIGH)),
        ("0x00110001",        bytes([0x01, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00])),
        ("0x0011002b-luid-high", struct.pack("<IQ", 0x0011002b, LUID_LOW)[0:8]),
    ]

    displays = [r"\\.\DISPLAY1", r"\\.\DISPLAY2"]
    r, g, b = 255, 0, 0   # bright red

    any_success = False

    for disp in displays:
        h, ll, lh = open_adapter(gdi32, disp)
        if h is None:
            print(f"\n{disp}: open failed — skipping")
            continue

        print(f"\n{disp}  hAdapter=0x{h:08X}  LUID={ll:#010x}:{lh:#010x}")

        for vname, buf212 in variants:
            for fn, dll_lbl in escape_fns:
                label = f"{disp[-8:]}|{dll_lbl}|{vname}"
                v = try_escape(fn, h, ll, lh, buf212, r, g, b, label)
                if v == 0:
                    print(f"\n  *** STATUS_SUCCESS — check if LEDs changed! ***")
                    any_success = True
                    # Try green to confirm it's real
                    import time; time.sleep(1)
                    try_escape(fn, h, ll, lh, buf212, 0, 255, 0, label + "|green-confirm")

        close_adapter(gdi32, h)

    if not any_success:
        print("\n\nAll attempts failed. Summary of distinct NTSTATUSes above.")
        print("Next: share output and the I2C entry from the JSON trace.")
    else:
        print("\n\nSomething returned SUCCESS. Verify LEDs changed color.")


if __name__ == "__main__":
    main()
