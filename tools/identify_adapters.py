"""
Identify D3DKMT adapters by querying their registry info strings.
Run as Administrator on Windows (64-bit Python).

Output: index | hAdapter | LUID | AdapterString (GPU name)
"""
import ctypes
import struct

gdi32 = ctypes.WinDLL("gdi32.dll")

# ---------------------------------------------------------------------------
# Structs
# ---------------------------------------------------------------------------

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

class _D3DKMT_QUERYADAPTERINFO(ctypes.Structure):
    # x64 layout: hAdapter(4) Type(4) [pad4] pPrivData(8) DataSize(4) [pad4]
    _fields_ = [
        ("hAdapter",             ctypes.c_uint32),
        ("Type",                 ctypes.c_uint32),
        ("pPrivateDriverData",   ctypes.c_void_p),
        ("PrivateDriverDataSize",ctypes.c_uint32),
    ]

# D3DKMT_ADAPTERREGISTRYINFO: 4 WCHAR[MAX_PATH] fields
# MAX_PATH = 260, WCHAR = 2 bytes → each field 520 bytes, total 2080 bytes
_REG_INFO_SIZE = 4 * 260 * 2

# KMTQUERYADAPTERINFOTYPE values — try both candidates for ADAPTERREGISTRYINFO
# KMTQAITYPE_ADAPTERREGISTRYINFO is 8 in older WDK, sometimes cited as 16
KMTQAITYPE_UMDRIVERNAME        = 1   # well-established, returns UMD .dll path
KMTQAITYPE_ADAPTERREGISTRYINFO_V8  = 8
KMTQAITYPE_ADAPTERREGISTRYINFO_V16 = 16

NTSTATUS_NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC0000001: "STATUS_UNSUCCESSFUL",
}


def query_adapter_info(h_adapter, query_type, buf_size):
    buf = ctypes.create_string_buffer(buf_size)
    qi = _D3DKMT_QUERYADAPTERINFO()
    qi.hAdapter              = h_adapter
    qi.Type                  = query_type
    qi.pPrivateDriverData    = ctypes.cast(buf, ctypes.c_void_p)
    qi.PrivateDriverDataSize = buf_size
    ret = gdi32.D3DKMTQueryAdapterInfo(ctypes.byref(qi))
    nts = ret & 0xFFFFFFFF
    if ret == 0:
        return nts, bytes(buf)
    return nts, None


def decode_wchar_field(data, offset, max_chars=260):
    end = offset + max_chars * 2
    chunk = data[offset:end]
    try:
        s = chunk.decode("utf-16-le").rstrip("\x00")
        return s
    except Exception:
        return repr(chunk[:32])


def main():
    # Enumerate adapters
    enum_data = _D3DKMT_ENUMADAPTERS()
    ret = gdi32.D3DKMTEnumAdapters(ctypes.byref(enum_data))
    if ret != 0:
        print(f"D3DKMTEnumAdapters failed: 0x{ret & 0xFFFFFFFF:08X}")
        return

    n = enum_data.NumAdapters
    print(f"D3DKMTEnumAdapters: {n} adapters\n")
    print(f"{'idx':<4} {'hAdapter':<12} {'LUID':<26} {'AdapterString'}")
    print("-" * 90)

    for i in range(n):
        info  = enum_data.Adapters[i]
        h     = info.hAdapter
        ll    = info.AdapterLuid.LowPart
        lh    = info.AdapterLuid.HighPart & 0xFFFFFFFF
        luid_str = f"{ll:#010x}:{lh:#010x}"

        adapter_str = "(query failed)"

        # Try ADAPTERREGISTRYINFO at type 8 and 16
        for qtype in (KMTQAITYPE_ADAPTERREGISTRYINFO_V8,
                      KMTQAITYPE_ADAPTERREGISTRYINFO_V16):
            nts, data = query_adapter_info(h, qtype, _REG_INFO_SIZE)
            if nts == 0 and data:
                adapter_str = decode_wchar_field(data, 0)   # AdapterString is first field
                bios_str    = decode_wchar_field(data, 260*2)
                chip_str    = decode_wchar_field(data, 260*2*3)
                break
            elif nts not in (0xC000000D, 0xC00000BB):
                pass  # unexpected status — try next type

        # Also try UMD driver name (type 1) for extra confirmation
        nts_umd, umd_data = query_adapter_info(h, KMTQAITYPE_UMDRIVERNAME, 1024)
        umd_str = ""
        if nts_umd == 0 and umd_data:
            try:
                # D3DKMT_UMDFILENAMEINFO: WCHAR UmdFileName[MAX_PATH]
                umd_str = umd_data.decode("utf-16-le").rstrip("\x00").split("\x00")[0]
            except Exception:
                umd_str = repr(umd_data[:64])

        print(f"{i:<4} 0x{h:08X}   {luid_str}   {adapter_str}")
        if umd_str:
            print(f"     UMD driver: {umd_str}")
        print()

    print("\nLook for 'Radeon RX 9070 XT' or '7550' to confirm dGPU index.")


if __name__ == "__main__":
    main()
