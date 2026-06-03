"""
ASRock RX 9070 XT Steel Legend — RGB controller via D3DKMTEscape.

Protocol reverse-engineered from AsrPolychromeRGB.exe via Frida hook.
Polychrome uses D3DKMTEscape (not ADL_Display_WriteAndReadI2C) to send
I2C commands to the GPU internal bus (line 2, address 0x6C, cmd 0x10).
The escape buffer is 868 bytes; R/G/B sit at fixed offsets 255/256/257.

Adapter discovery: Polychrome uses D3DKMTOpenAdapterFromGdiDisplayName, NOT
D3DKMTEnumAdapters. We enumerate all display devices and open each.
We also try both gdi32.dll and d3d11.dll for D3DKMTEscape (Polychrome uses d3d11.dll).
"""

import ctypes
import json
import os
import struct

DEFAULT_DLL_PATH = r"C:\Windows\System32\atiadlxx.dll"

_TEMPLATE_SIZE = 868

def _build_template() -> bytearray:
    buf = bytearray(_TEMPLATE_SIZE)
    buf[0:8]     = bytes([0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00])
    buf[72:92]   = bytes([0x64, 0x03, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02,
                          0x05, 0x00, 0x00, 0x00])
    buf[204:212] = bytes([0x50, 0x01, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00])
    # AMD-internal ID from Polychrome capture — patched at runtime with real LUID
    buf[212:220] = bytes([0x2b, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00])
    buf[224:252] = bytes([0x40, 0x01, 0x00, 0x00,
                          0x04, 0x00, 0x00, 0x00,
                          0x02, 0x00, 0x00, 0x00,
                          0x6c, 0x00, 0x00, 0x00,
                          0x10, 0x00, 0x00, 0x00,
                          0x64, 0x00, 0x00, 0x00,
                          0x0c, 0x00, 0x00, 0x00])
    buf[252:255] = bytes([0x00, 0x09, 0x11])
    buf[258:260] = bytes([0x8c, 0xff])
    buf[540:548] = bytes([0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00])
    return buf

_TEMPLATE = _build_template()


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

class _D3DKMT_ADAPTERINFO(ctypes.Structure):
    _fields_ = [
        ("hAdapter",                    ctypes.c_uint32),
        ("AdapterLuid",                 _LUID),
        ("NumOfSources",                ctypes.c_uint32),
        ("bPresentMoveRegionsPreferred", ctypes.c_int32),
    ]

class _D3DKMT_ENUMADAPTERS(ctypes.Structure):
    _fields_ = [
        ("NumAdapters", ctypes.c_uint32),
        ("Adapters",    _D3DKMT_ADAPTERINFO * 16),
    ]

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


def _open_from_display_names(gdi32, verbose=False):
    """Try D3DKMTOpenAdapterFromGdiDisplayName for all active GDI displays."""
    user32 = ctypes.WinDLL("user32.dll")

    class DISPLAY_DEVICEW(ctypes.Structure):
        _fields_ = [
            ("cb",           ctypes.c_uint32),
            ("DeviceName",   ctypes.c_wchar * 32),
            ("DeviceString", ctypes.c_wchar * 128),
            ("StateFlags",   ctypes.c_uint32),
            ("DeviceID",     ctypes.c_wchar * 128),
            ("DeviceKey",    ctypes.c_wchar * 128),
        ]

    DISPLAY_DEVICE_ACTIVE = 0x00000001
    results = []
    idx = 0
    while True:
        dd = DISPLAY_DEVICEW()
        dd.cb = ctypes.sizeof(dd)
        if not user32.EnumDisplayDevicesW(None, idx, ctypes.byref(dd), 0):
            break
        idx += 1
        if not (dd.StateFlags & DISPLAY_DEVICE_ACTIVE):
            continue
        name = dd.DeviceName
        st = _D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME()
        st.DeviceName = name
        ret = gdi32.D3DKMTOpenAdapterFromGdiDisplayName(ctypes.byref(st))
        nts = ret & 0xFFFFFFFF
        if verbose:
            print(f"  OpenAdapterFromGdi({name!r}) NTSTATUS=0x{nts:08X}"
                  f" hAdapter=0x{st.hAdapter:08X}"
                  f" LUID={st.AdapterLuid.LowPart:#010x}:{st.AdapterLuid.HighPart:#010x}")
        if ret == 0:
            results.append((st.hAdapter,
                            st.AdapterLuid.LowPart,
                            st.AdapterLuid.HighPart,
                            name))
    return results


def _close_adapter(gdi32, h):
    ca = _D3DKMT_CLOSEADAPTER()
    ca.hAdapter = h
    gdi32.D3DKMTCloseAdapter(ctypes.byref(ca))


def _enum_adapters_legacy(gdi32, verbose=False):
    enum_data = _D3DKMT_ENUMADAPTERS()
    ret = gdi32.D3DKMTEnumAdapters(ctypes.byref(enum_data))
    if ret != 0:
        raise RuntimeError(f"D3DKMTEnumAdapters failed: 0x{ret & 0xFFFFFFFF:08X}")
    results = []
    for i in range(enum_data.NumAdapters):
        info = enum_data.Adapters[i]
        results.append((info.hAdapter,
                        info.AdapterLuid.LowPart,
                        info.AdapterLuid.HighPart,
                        f"enum[{i}]"))
        if verbose:
            print(f"  enum[{i}] hAdapter=0x{info.hAdapter:08X}"
                  f" LUID={info.AdapterLuid.LowPart:#010x}:{info.AdapterLuid.HighPart:#010x}")
    return results


def _try_escape(fn, h, ll, lh, r, g, b, verbose=False, label=""):
    buf = bytearray(_TEMPLATE)
    struct.pack_into("<II", buf, 212, ll, lh & 0xFFFFFFFF)
    buf[255] = r & 0xFF
    buf[256] = g & 0xFF
    buf[257] = b & 0xFF
    c_buf = ctypes.create_string_buffer(bytes(buf))
    esc = _D3DKMT_ESCAPE()
    esc.hAdapter              = h
    esc.hDevice               = 0
    esc.Type                  = 0
    esc.Flags                 = 0
    esc.pPrivateDriverData    = ctypes.cast(c_buf, ctypes.c_void_p)
    esc.PrivateDriverDataSize = _TEMPLATE_SIZE
    esc.hContext              = 0
    ret = fn(ctypes.byref(esc))
    nts = ret & 0xFFFFFFFF
    if verbose:
        print(f"  [{label}] hAdapter=0x{h:08X} -> NTSTATUS=0x{nts:08X}")
    return nts


def _send_escape(r: int, g: int, b: int, verbose: bool = False) -> None:
    gdi32 = ctypes.WinDLL("gdi32.dll")
    d3d11 = ctypes.WinDLL("d3d11.dll")

    # Polychrome uses d3d11.dll; try it first, then gdi32
    escape_fns = [
        (d3d11.D3DKMTEscape, "d3d11"),
        (gdi32.D3DKMTEscape, "gdi32"),
    ]

    if verbose:
        print("[dbg] Primary: D3DKMTOpenAdapterFromGdiDisplayName")
    display_adapters = _open_from_display_names(gdi32, verbose=verbose)

    last_nts = None
    if display_adapters:
        try:
            for h, ll, lh, name in display_adapters:
                for fn, dll_lbl in escape_fns:
                    nts = _try_escape(fn, h, ll, lh, r, g, b, verbose=verbose,
                                      label=f"{name}|{dll_lbl}")
                    if nts == 0:
                        return
                    last_nts = nts
        finally:
            for ha, _, _, _ in display_adapters:
                _close_adapter(gdi32, ha)

    if verbose:
        print("[dbg] Fallback: D3DKMTEnumAdapters")
    try:
        enum_adapters = _enum_adapters_legacy(gdi32, verbose=verbose)
    except RuntimeError as e:
        raise RuntimeError(f"All adapter discovery failed: {e}") from e

    for h, ll, lh, label in enum_adapters:
        for fn, dll_lbl in escape_fns:
            nts = _try_escape(fn, h, ll, lh, r, g, b, verbose=verbose,
                              label=f"{label}|{dll_lbl}")
            if nts == 0:
                return
            last_nts = nts

    raise RuntimeError(
        f"D3DKMTEscape failed on all adapters; last NTSTATUS=0x{last_nts & 0xFFFFFFFF:08X}"
    )


def apply_color(r: int, g: int, b: int, dll_path: str = DEFAULT_DLL_PATH,
                verbose: bool = False) -> None:
    _send_escape(r, g, b, verbose=verbose)


def load_config(config_path: str) -> dict:
    defaults = {"r": 255, "g": 255, "b": 255, "dll_path": DEFAULT_DLL_PATH}
    if not os.path.exists(config_path):
        return defaults
    try:
        with open(config_path, "r") as fh:
            data = json.load(fh)
        for k, v in defaults.items():
            data.setdefault(k, v)
        return data
    except Exception:
        return defaults


def save_config(config_path: str, r: int, g: int, b: int, dll_path: str = DEFAULT_DLL_PATH) -> None:
    with open(config_path, "w") as fh:
        json.dump({"r": r, "g": g, "b": b, "dll_path": dll_path}, fh, indent=2)
