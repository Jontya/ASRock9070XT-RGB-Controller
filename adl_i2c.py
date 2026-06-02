"""
ASRock RX 9070 XT Steel Legend — RGB controller via D3DKMTEscape.

Protocol reverse-engineered from AsrPolychromeRGB.exe via Frida hook.
Polychrome uses D3DKMTEscape (not ADL_Display_WriteAndReadI2C) to send
I2C commands to the GPU's internal bus (line 2, address 0x6C, cmd 0x10).
The escape buffer is 868 bytes; R/G/B sit at fixed offsets 255/256/257.
"""

import ctypes
import json
import os
import struct

DEFAULT_DLL_PATH = r"C:\Windows\System32\atiadlxx.dll"  # kept for config compat

# ---------------------------------------------------------------------------
# D3DKMT escape buffer template (868 bytes, captured from Polychrome)
# Constant parts are set here; LUID (212-219) and RGB (255-257) patched at runtime
# ---------------------------------------------------------------------------

_TEMPLATE_SIZE = 868

def _build_template() -> bytearray:
    buf = bytearray(_TEMPLATE_SIZE)
    # Header
    buf[0:8]     = bytes([0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00])
    # Offset 72: total size field + flags
    buf[72:92]   = bytes([0x64, 0x03, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02,
                          0x05, 0x00, 0x00, 0x00])
    # Offset 204: sub-structure sizes
    buf[204:212] = bytes([0x50, 0x01, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00])
    # Offset 212-219: LUID — patched per-adapter at runtime
    # Offset 224: I2C command structure
    buf[224:252] = bytes([0x40, 0x01, 0x00, 0x00,  # struct size
                          0x04, 0x00, 0x00, 0x00,  # field
                          0x02, 0x00, 0x00, 0x00,  # iLine = 2 (GPU internal I2C bus)
                          0x6c, 0x00, 0x00, 0x00,  # iAddress = 0x6C
                          0x10, 0x00, 0x00, 0x00,  # iOffset  = 0x10 (RGB command)
                          0x64, 0x00, 0x00, 0x00,  # iSpeed   = 100
                          0x0c, 0x00, 0x00, 0x00]) # iDataSize = 12
    # Offset 252: I2C data payload prefix
    buf[252:255] = bytes([0x00, 0x09, 0x11])
    # Offset 255: R — patched at runtime
    # Offset 256: G — patched at runtime
    # Offset 257: B — patched at runtime
    # Offset 258: constant suffix
    buf[258:260] = bytes([0x8c, 0xff])
    # Offset 540: trailing structure
    buf[540:548] = bytes([0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00])
    return buf

_TEMPLATE = _build_template()


# ---------------------------------------------------------------------------
# D3DKMT ctypes structures (x64 layout)
# ---------------------------------------------------------------------------

class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]


class _D3DKMT_ADAPTERINFO(ctypes.Structure):
    _fields_ = [
        ("hAdapter",                    ctypes.c_uint32),
        ("AdapterLuid",                 _LUID),
        ("NumOfSources",                ctypes.c_uint32),
        ("bPresentMoveRegionsPreferred",ctypes.c_int32),
    ]


class _D3DKMT_ENUMADAPTERS(ctypes.Structure):
    _fields_ = [
        ("NumAdapters", ctypes.c_uint32),
        ("Adapters",    _D3DKMT_ADAPTERINFO * 16),
    ]


class _D3DKMT_ESCAPE(ctypes.Structure):
    # x64: 4×uint32 (16 bytes) → void* at offset 16 (naturally 8-byte aligned)
    _fields_ = [
        ("hAdapter",             ctypes.c_uint32),
        ("hDevice",              ctypes.c_uint32),
        ("Type",                 ctypes.c_uint32),   # 0 = D3DKMT_ESCAPE_DRIVERPRIVATE
        ("Flags",                ctypes.c_uint32),
        ("pPrivateDriverData",   ctypes.c_void_p),
        ("PrivateDriverDataSize",ctypes.c_uint32),
        ("hContext",             ctypes.c_uint32),
    ]


# ---------------------------------------------------------------------------
# Core: send escape to GPU
# ---------------------------------------------------------------------------

def _send_escape(r: int, g: int, b: int, verbose: bool = False) -> None:
    """Send one D3DKMTEscape call per enumerated adapter until one succeeds."""
    gdi32 = ctypes.WinDLL("gdi32.dll")

    enum_data = _D3DKMT_ENUMADAPTERS()
    ret = gdi32.D3DKMTEnumAdapters(ctypes.byref(enum_data))
    if ret != 0:
        raise RuntimeError(f"D3DKMTEnumAdapters failed: 0x{ret & 0xFFFFFFFF:08X}")

    if verbose:
        print(f"[dbg] {enum_data.NumAdapters} adapters")

    last_ret = None
    for i in range(enum_data.NumAdapters):
        info = enum_data.Adapters[i]

        buf = bytearray(_TEMPLATE)
        # Patch LUID
        struct.pack_into("<II", buf, 212,
                         info.AdapterLuid.LowPart,
                         info.AdapterLuid.HighPart & 0xFFFFFFFF)
        # Patch RGB
        buf[255] = r & 0xFF
        buf[256] = g & 0xFF
        buf[257] = b & 0xFF

        c_buf = ctypes.create_string_buffer(bytes(buf))

        esc = _D3DKMT_ESCAPE()
        esc.hAdapter              = info.hAdapter
        esc.hDevice               = 0
        esc.Type                  = 0   # D3DKMT_ESCAPE_DRIVERPRIVATE
        esc.Flags                 = 1   # HardwareAccess bit required for I2C
        esc.pPrivateDriverData    = ctypes.cast(c_buf, ctypes.c_void_p)
        esc.PrivateDriverDataSize = _TEMPLATE_SIZE
        esc.hContext              = 0

        ret = gdi32.D3DKMTEscape(ctypes.byref(esc))
        nts = ret & 0xFFFFFFFF
        if verbose:
            print(f"[dbg] adapter[{i}] hAdapter=0x{info.hAdapter:08X} "
                  f"LUID={info.AdapterLuid.LowPart:#010x}:{info.AdapterLuid.HighPart:#010x} "
                  f"→ NTSTATUS=0x{nts:08X}")
        if ret == 0:
            return  # STATUS_SUCCESS
        last_ret = ret

    raise RuntimeError(
        f"D3DKMTEscape failed on all {enum_data.NumAdapters} adapters; "
        f"last NTSTATUS=0x{last_ret & 0xFFFFFFFF:08X}"
    )


# ---------------------------------------------------------------------------
# Public API (mirrors original adl_i2c interface)
# ---------------------------------------------------------------------------

def apply_color(r: int, g: int, b: int, dll_path: str = DEFAULT_DLL_PATH,
                verbose: bool = False) -> None:
    """Apply static RGB color to all GPU LED zones. dll_path ignored (kept for compat)."""
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
