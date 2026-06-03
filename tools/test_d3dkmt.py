"""
Targeted D3DKMTEscape test using D3DKMTOpenAdapterFromGdiDisplayName.

Phase 1: Enumerate all display devices, try to open each, report NTSTATUS.
Phase 2: For handles that open successfully, test escape variants.

Run as Administrator. Close Polychrome first.

Usage:
    python tools\\test_d3dkmt.py
"""

import ctypes
import ctypes.wintypes
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
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0x00000001: "STATUS_WAIT_1",  # sometimes gdi32 returns 1 on error
}

def nts_str(ret):
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
        ("hAdapter",              ctypes.c_uint32),
        ("hDevice",               ctypes.c_uint32),
        ("Type",                  ctypes.c_uint32),
        ("Flags",                 ctypes.c_uint32),
        ("pPrivateDriverData",    ctypes.c_void_p),
        ("PrivateDriverDataSize", ctypes.c_uint32),
        ("hContext",              ctypes.c_uint32),
    ]

# EnumDisplayDevicesW structs
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
# 868-byte template (from Polychrome capture, buf[212]=0x2b00110000000000)
# ---------------------------------------------------------------------------
_SZ = 868

def _make_template() -> bytearray:
    buf = bytearray(_SZ)
    buf[0:8]     = bytes([0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00])
    buf[72:92]   = bytes([0x64, 0x03, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02,
                          0x05, 0x00, 0x00, 0x00])
    buf[204:212] = bytes([0x50, 0x01, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00])
    buf[212:220] = bytes([0x2b, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00])
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
# Display enumeration
# ---------------------------------------------------------------------------
def enum_display_devices(user32):
    """Return list of (DeviceName, DeviceString, StateFlags) for all adapters + monitors."""
    results = []
    dd = _DISPLAY_DEVICEW()
    dd.cb = ctypes.sizeof(_DISPLAY_DEVICEW)
    i = 0
    while True:
        ret = user32.EnumDisplayDevicesW(None, i, ctypes.byref(dd), 0)
        if not ret:
            break
        results.append((dd.DeviceName, dd.DeviceString, dd.StateFlags))
        i += 1
    return results


# ---------------------------------------------------------------------------
# Adapter open/close
# ---------------------------------------------------------------------------
def open_adapter(gdi32, display_name: str):
    st = _D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME()
    st.DeviceName = display_name
    ret = gdi32.D3DKMTOpenAdapterFromGdiDisplayName(ctypes.byref(st))
    nts_v = ret & 0xFFFFFFFF
    if nts_v == 0:
        return st.hAdapter, st.AdapterLuid.LowPart, st.AdapterLuid.HighPart, None
    return None, None, None, nts_v


def close_adapter(gdi32, h):
    ca = _D3DKMT_CLOSEADAPTER()
    ca.hAdapter = h
    gdi32.D3DKMTCloseAdapter(ctypes.byref(ca))


# ---------------------------------------------------------------------------
# Escape
# ---------------------------------------------------------------------------
def try_escape(escape_fn, h_adapter, buf212: bytes, r: int, g: int, b: int,
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
    print(f"    [{label}] → {v:#010x} {sym}")
    return v


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Load d3d11 first — AMD UMD may need this to register
    try:
        d3d11 = ctypes.WinDLL("d3d11.dll")
        print("d3d11.dll loaded OK")
    except OSError as e:
        print(f"d3d11.dll load failed: {e}")
        d3d11 = None

    gdi32 = ctypes.WinDLL("gdi32.dll")
    user32 = ctypes.WinDLL("user32.dll")

    escape_fns = []
    if d3d11:
        try:
            escape_fns.append((d3d11.D3DKMTEscape, "d3d11"))
        except AttributeError:
            print("d3d11.D3DKMTEscape not found")
    try:
        escape_fns.append((gdi32.D3DKMTEscape, "gdi32"))
    except AttributeError:
        print("gdi32.D3DKMTEscape not found")

    # Phase 1: Enumerate display devices
    print("\n=== Phase 1: Display device enumeration ===")
    devs = enum_display_devices(user32)
    print(f"Found {len(devs)} display adapters via EnumDisplayDevicesW:\n")
    for name, desc, flags in devs:
        active = "ACTIVE" if (flags & DISPLAY_DEVICE_ACTIVE) else "inactive"
        print(f"  {name:<16} [{active:>8}]  {desc}")

    # Phase 2: Try to open each display device
    print("\n=== Phase 2: D3DKMTOpenAdapterFromGdiDisplayName ===")
    print("(Also trying hard-coded DISPLAY1..DISPLAY8 in case enum missed any)\n")

    candidates = [name for name, _, flags in devs]
    # Also brute-force common names
    for i in range(1, 9):
        dn = f"\\\\.\\DISPLAY{i}"
        if dn not in candidates:
            candidates.append(dn)

    opened = []  # (display_name, hAdapter, luid_low, luid_high)
    for dn in candidates:
        h, ll, lh, err = open_adapter(gdi32, dn)
        if h is not None:
            print(f"  {dn}  → hAdapter=0x{h:08X}  LUID=0x{ll:08X}:{lh:08X}  *** OPENED ***")
            opened.append((dn, h, ll, lh))
        else:
            print(f"  {dn}  → open failed: {nts_str(err)}")

    if not opened:
        print("\nNo display opened. Possible causes:")
        print("  1. Not running as Administrator")
        print("  2. D3DKMTOpenAdapterFromGdiDisplayName not present in gdi32.dll")
        print("     — checking export...")
        try:
            fn = gdi32.D3DKMTOpenAdapterFromGdiDisplayName
            print(f"     gdi32 export found: {fn}")
        except AttributeError:
            print("     NOT FOUND in gdi32.dll — need to try via win32u.dll or d3d11.dll")

        # Try via d3d11
        if d3d11:
            print("\n  Trying D3DKMTOpenAdapterFromGdiDisplayName via d3d11.dll...")
            try:
                open_fn_d3d11 = d3d11.D3DKMTOpenAdapterFromGdiDisplayName
                for dn in candidates[:4]:  # just first 4
                    st = _D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME()
                    st.DeviceName = dn
                    ret = open_fn_d3d11(ctypes.byref(st))
                    nts_v = ret & 0xFFFFFFFF
                    if nts_v == 0:
                        print(f"    {dn} → hAdapter=0x{st.hAdapter:08X}  *** OPENED via d3d11 ***")
                        opened.append((dn, st.hAdapter, st.AdapterLuid.LowPart, st.AdapterLuid.HighPart))
                    else:
                        print(f"    {dn} → {nts_str(nts_v)}")
            except AttributeError:
                print("     D3DKMTOpenAdapterFromGdiDisplayName not in d3d11.dll either")

        # Try via win32u.dll (NtGdiDdDDIOpenAdapterFromGdiDisplayName)
        print("\n  Trying NtGdiDdDDIOpenAdapterFromGdiDisplayName via win32u.dll...")
        try:
            win32u = ctypes.WinDLL("win32u.dll")
            nt_open = win32u.NtGdiDdDDIOpenAdapterFromGdiDisplayName
            for dn in candidates[:4]:
                st = _D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME()
                st.DeviceName = dn
                ret = nt_open(ctypes.byref(st))
                nts_v = ret & 0xFFFFFFFF
                if nts_v == 0:
                    print(f"    {dn} → hAdapter=0x{st.hAdapter:08X}  *** OPENED via win32u ***")
                    opened.append((dn, st.hAdapter, st.AdapterLuid.LowPart, st.AdapterLuid.HighPart))
                else:
                    print(f"    {dn} → {nts_str(nts_v)}")
        except (OSError, AttributeError) as e:
            print(f"    win32u approach failed: {e}")

        if not opened:
            print("\nAll open attempts failed. Paste full output for diagnosis.")
            return

    # Phase 3: Escape test on opened handles
    print(f"\n=== Phase 3: Escape test ({len(opened)} handle(s) opened) ===")
    print("Color: bright red (255,0,0)\n")

    BUF212 = bytes([0x2b, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00])

    any_success = False
    for disp, h, ll, lh in opened:
        print(f"{disp}  hAdapter=0x{h:08X}")
        for fn, dll_lbl in escape_fns:
            label = f"{dll_lbl}"
            v = try_escape(fn, h, BUF212, 255, 0, 0, label)
            if v == 0:
                print(f"    *** STATUS_SUCCESS — check if LEDs changed to RED! ***")
                any_success = True
                import time; time.sleep(2)
                try_escape(fn, h, BUF212, 0, 255, 0, label + "|green")
                time.sleep(2)
                try_escape(fn, h, BUF212, 0, 0, 255, label + "|blue")
        close_adapter(gdi32, h)

    if not any_success:
        print("\nNo STATUS_SUCCESS. Paste full output.")
    else:
        print("\nSUCCESS path found. LEDs should have cycled red→green→blue.")


if __name__ == "__main__":
    main()
