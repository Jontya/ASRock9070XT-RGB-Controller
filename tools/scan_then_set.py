"""
Replicate Polychrome's scan phase (RGB=0 query escapes) before sending color-set.
Hypothesis: driver requires the scan to initialize I2C bus state.

Run as Administrator. Close Polychrome first.
"""

import ctypes
import json
import glob
import os
import sys
import time

NTSTATUS = {
    0x00000000: "STATUS_SUCCESS",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC0000001: "STATUS_UNSUCCESSFUL",
}
def nts_str(v): v &= 0xFFFFFFFF; return f"0x{v:08X} ({NTSTATUS.get(v,'?')})"

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
def load_scan_and_color_buffers():
    """
    Load captured buffers from the trace.
    Returns:
        scan_bufs: list of (seq, bytes) for scan phase (DataSize=868, RGB=0)
        color_buf: bytes for first color-set (RGB!=0)
    """
    files = glob.glob("captures/trace_*.json")
    if not files:
        print("No trace files.")
        sys.exit(1)
    f = max(files, key=os.path.getmtime)
    print(f"Loading: {f}")
    data = json.load(open(f))

    scan_bufs = []
    color_buf = None

    for e in data:
        if e.get("DataSize") != 868:
            continue
        bi = e.get("bufIn", "")
        if len(bi) < 516:
            continue
        r = int(bi[510:512], 16)
        g = int(bi[512:514], 16)
        b = int(bi[514:516], 16)
        seq = e["seq"]
        buf = bytes.fromhex(bi)

        if r == 0 and g == 0 and b == 0:
            scan_bufs.append((seq, buf))
        elif color_buf is None:
            color_buf = (seq, buf, r, g, b)

    print(f"  scan escapes: {len(scan_bufs)}")
    if color_buf:
        seq, _, r, g, b = color_buf
        print(f"  color-set escape: seq={seq}, original RGB=({r},{g},{b})")
    else:
        print("  WARNING: no color-set escape found in trace!")
    return scan_bufs, color_buf


def open_dgpu(gdi32, user32):
    """Open first ACTIVE display matching '9070 XT'."""
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
                return st.hAdapter, name
        i += 1
    return None, None


def send(escape_fn, h_adapter, buf868: bytes, r=None, g=None, b=None, label=""):
    buf = bytearray(buf868)
    if r is not None: buf[255] = r & 0xFF
    if g is not None: buf[256] = g & 0xFF
    if b is not None: buf[257] = b & 0xFF
    c_buf = ctypes.create_string_buffer(bytes(buf))
    esc = _D3DKMT_ESCAPE()
    esc.hAdapter              = h_adapter
    esc.hDevice               = 0
    esc.Type                  = 0
    esc.Flags                 = 0
    esc.pPrivateDriverData    = ctypes.cast(c_buf, ctypes.c_void_p)
    esc.PrivateDriverDataSize = 868
    esc.hContext              = 0
    ret = escape_fn(ctypes.byref(esc))
    v = ret & 0xFFFFFFFF
    sym = NTSTATUS.get(v, "?")
    print(f"  {label}: {nts_str(v)}")
    return v, bytearray(c_buf)


def main():
    scan_bufs, color_buf_entry = load_scan_and_color_buffers()
    if color_buf_entry is None:
        print("No color-set buffer. Aborting.")
        sys.exit(1)

    _, color_buf, orig_r, orig_g, orig_b = color_buf_entry

    d3d11 = ctypes.WinDLL("d3d11.dll")
    gdi32  = ctypes.WinDLL("gdi32.dll")
    user32 = ctypes.WinDLL("user32.dll")
    escape_fn = d3d11.D3DKMTEscape

    h, disp = open_dgpu(gdi32, user32)
    if h is None:
        print("Cannot open dGPU. Aborting.")
        sys.exit(1)
    print(f"Opened {disp}  hAdapter=0x{h:08X}\n")

    # -----------------------------------------------------------------------
    # Phase 1: scan (exact captured buffers, RGB=0 — first 10 scan escapes)
    # -----------------------------------------------------------------------
    print(f"=== Phase 1: scan phase ({min(10, len(scan_bufs))} escapes) ===")
    for seq, buf in scan_bufs[:10]:
        v, out = send(escape_fn, h, buf, label=f"scan seq={seq}")
        # Show driver writeback if any
        diff = [(i, buf[i], out[i]) for i in range(868) if buf[i] != out[i]]
        if diff:
            print(f"    writeback {len(diff)} bytes: " +
                  " ".join(f"[{d[0]}]:{d[1]:02x}→{d[2]:02x}" for d in diff[:5]))
    print()

    # -----------------------------------------------------------------------
    # Phase 2: color-set (exact captured buffer, patch to bright red)
    # -----------------------------------------------------------------------
    print("=== Phase 2: color-set (RED) ===")
    v, _ = send(escape_fn, h, color_buf, r=255, g=0, b=0, label="RED exact-buf")
    if v == 0:
        print("  *** STATUS_SUCCESS — did LEDs go RED? ***")
    time.sleep(3)

    print("\n=== Phase 2b: color-set (GREEN) ===")
    send(escape_fn, h, color_buf, r=0, g=255, b=0, label="GREEN")
    time.sleep(3)

    print("\n=== Phase 2c: color-set (BLUE) ===")
    send(escape_fn, h, color_buf, r=0, g=0, b=255, label="BLUE")
    time.sleep(2)

    # -----------------------------------------------------------------------
    # Phase 3: if still no change, try BOTH displays with scan+set each
    # -----------------------------------------------------------------------
    print("\n=== Phase 3: try DISPLAY17 + DISPLAY18 with scan+set each ===")
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
                h2 = st.hAdapter
                print(f"\n  {name}  h=0x{h2:08X}")
                for seq, buf in scan_bufs[:5]:
                    send(escape_fn, h2, buf, label=f"  scan seq={seq}")
                v, _ = send(escape_fn, h2, color_buf, r=255, g=0, b=0, label=f"  RED via {name}")
                if v == 0:
                    print(f"  *** SUCCESS on {name} — check LEDs! ***")
                    time.sleep(2)
                    send(escape_fn, h2, color_buf, r=0, g=255, b=0, label=f"  GREEN via {name}")
                ca = _D3DKMT_CLOSEADAPTER()
                ca.hAdapter = h2
                gdi32.D3DKMTCloseAdapter(ctypes.byref(ca))
        i += 1

    # Close first handle
    ca = _D3DKMT_CLOSEADAPTER()
    ca.hAdapter = h
    gdi32.D3DKMTCloseAdapter(ctypes.byref(ca))

    print("\nDone. Report whether LEDs changed in any phase.")


if __name__ == "__main__":
    main()
