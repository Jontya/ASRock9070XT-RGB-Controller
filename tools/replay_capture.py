"""
Replay the exact Polychrome-captured 868-byte escape buffer, patching only RGB.
If this succeeds → buffer template reconstruction was wrong; diff reveals deltas.
If this fails → something else (adapter, DLL, process context).

Run as Administrator. Close Polychrome first.

Usage:
    python tools\\replay_capture.py
"""

import ctypes
import json
import glob
import os
import sys

# ---------------------------------------------------------------------------
NTSTATUS = {
    0x00000000: "STATUS_SUCCESS",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000022: "STATUS_ACCESS_DENIED",
}

def nts_str(v):
    v &= 0xFFFFFFFF
    return f"0x{v:08X} ({NTSTATUS.get(v, '?')})"

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
        ("hAdapter",              ctypes.c_uint32),
        ("hDevice",               ctypes.c_uint32),
        ("Type",                  ctypes.c_uint32),
        ("Flags",                 ctypes.c_uint32),
        ("pPrivateDriverData",    ctypes.c_void_p),
        ("PrivateDriverDataSize", ctypes.c_uint32),
        ("hContext",              ctypes.c_uint32),
    ]

class _DISPLAY_DEVICEW(ctypes.Structure):
    _fields_ = [
        ("cb",           ctypes.c_uint32),
        ("DeviceName",   ctypes.c_wchar * 32),
        ("DeviceString", ctypes.c_wchar * 128),
        ("StateFlags",   ctypes.c_uint32),
        ("DeviceID",     ctypes.c_wchar * 128),
        ("DeviceKey",    ctypes.c_wchar * 128),
    ]

DISPLAY_DEVICE_ACTIVE = 0x00000001

# ---------------------------------------------------------------------------
def load_capture():
    files = glob.glob("captures/trace_*.json")
    if not files:
        print("No trace files in captures/. Run frida_full_trace.py first.")
        sys.exit(1)
    f = max(files, key=os.path.getmtime)
    print(f"Loading: {f}")
    data = json.load(open(f))

    # Find all color-set escapes (DataSize=868, RGB != 0)
    color_escapes = []
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
            color_escapes.append((e["seq"], r, g, b, bytes.fromhex(bi)))

    if not color_escapes:
        print("No color-set escapes (RGB != 0) found in capture.")
        print("Run Frida trace while Polychrome changes color.")
        sys.exit(1)

    seq, r, g, b, buf = color_escapes[0]
    print(f"Using seq={seq}, original RGB=({r},{g},{b}), bufLen={len(buf)}")
    return buf


def open_dgpu_display(gdi32, user32):
    """Open first ACTIVE display matching 'RX 9070 XT'."""
    dd = _DISPLAY_DEVICEW()
    dd.cb = ctypes.sizeof(_DISPLAY_DEVICEW)
    i = 0
    while True:
        ret = user32.EnumDisplayDevicesW(None, i, ctypes.byref(dd), 0)
        if not ret:
            break
        if "9070" in dd.DeviceString and (dd.StateFlags & DISPLAY_DEVICE_ACTIVE):
            name = dd.DeviceName
            st = _D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME()
            st.DeviceName = name
            ret2 = gdi32.D3DKMTOpenAdapterFromGdiDisplayName(ctypes.byref(st))
            if (ret2 & 0xFFFFFFFF) == 0:
                print(f"Opened {name}  hAdapter=0x{st.hAdapter:08X}  LUID=0x{st.AdapterLuid.LowPart:08X}")
                return st.hAdapter, name
            print(f"  {name}: open failed {nts_str(ret2)}")
        i += 1
    return None, None


def send_escape(d3d11_escape, h_adapter, buf868: bytearray, r: int, g: int, b: int, label: str):
    buf = bytearray(buf868)
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
    esc.PrivateDriverDataSize = 868
    esc.hContext              = 0
    ret = d3d11_escape(ctypes.byref(esc))
    v = ret & 0xFFFFFFFF
    print(f"  [{label}] R={r} G={g} B={b} → {nts_str(v)}")
    return v


def diff_against_template(captured: bytes):
    """Compare captured buffer against our reconstructed template."""
    # Rebuild template inline
    buf = bytearray(868)
    buf[0:8]     = bytes([0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00])
    buf[72:92]   = bytes([0x64, 0x03, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02,
                          0x05, 0x00, 0x00, 0x00])
    buf[204:212] = bytes([0x50, 0x01, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00])
    buf[212:220] = bytes([0x2b, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00])
    buf[224:252] = bytes([
        0x40, 0x01, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x6c, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00,
    ])
    buf[252:255] = bytes([0x00, 0x09, 0x11])
    buf[258:260] = bytes([0x8c, 0xff])
    buf[540:548] = bytes([0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00])

    # Zero out RGB in captured for comparison (treat as "don't care")
    cap = bytearray(captured)
    cap[255] = 0; cap[256] = 0; cap[257] = 0
    buf[255] = 0; buf[256] = 0; buf[257] = 0

    diffs = [(i, buf[i], cap[i]) for i in range(min(len(buf), len(cap))) if buf[i] != cap[i]]
    print(f"\n=== Buffer diff: template vs captured ({len(diffs)} byte(s) differ) ===")
    if diffs:
        print(f"{'offset':>7}  template  capture")
        for off, tv, cv in diffs:
            print(f"  {off:>5}:    0x{tv:02X}     0x{cv:02X}")
    else:
        print("  Buffers identical (excluding RGB bytes).")


# ---------------------------------------------------------------------------
def main():
    captured_buf = load_capture()

    d3d11 = ctypes.WinDLL("d3d11.dll")
    gdi32  = ctypes.WinDLL("gdi32.dll")
    user32 = ctypes.WinDLL("user32.dll")

    h, disp = open_dgpu_display(gdi32, user32)
    if h is None:
        print("Could not open dGPU display adapter. Check Administrator privileges.")
        sys.exit(1)

    escape_fn = d3d11.D3DKMTEscape

    print("\n=== Test 1: Exact captured buffer (RGB patched to solid colors) ===")
    import time
    v = send_escape(escape_fn, h, bytearray(captured_buf), 255, 0, 0, "red")
    if v == 0:
        print("  *** RED sent — did LEDs change? ***")
        time.sleep(2)
        send_escape(escape_fn, h, bytearray(captured_buf), 0, 255, 0, "green")
        time.sleep(2)
        send_escape(escape_fn, h, bytearray(captured_buf), 0, 0, 255, "blue")
        time.sleep(2)
    else:
        print(f"  Captured buffer also failed.")

    # Diff template vs captured regardless
    diff_against_template(captured_buf)

    # Close
    ca = _D3DKMT_CLOSEADAPTER()
    ca.hAdapter = h
    gdi32.D3DKMTCloseAdapter(ctypes.byref(ca))


if __name__ == "__main__":
    main()
