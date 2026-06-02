"""
ADL diagnostic script — run via Windows Python (as Administrator) to verify setup.
Exits 0 if ASRock RGB controller found and I2C probe succeeds, 1 otherwise.
"""

import ctypes
import os
import sys

DEFAULT_DLL = r"C:\Windows\System32\atiadlxx.dll"
ADL_OK = 0
ADL_MAX_PATH = 256
ASROCK_SUBVENDOR = 0x1849
RGB_I2C_ADDR = 0x36


# Windows-only ADLAdapterInfo layout (matches AMD ADL SDK adl_structures.h)
class ADLAdapterInfo(ctypes.Structure):
    _fields_ = [
        ("iSize",            ctypes.c_int),
        ("iAdapterIndex",    ctypes.c_int),
        ("strUDID",          ctypes.c_char * ADL_MAX_PATH),
        ("iBusNumber",       ctypes.c_int),
        ("iDeviceNumber",    ctypes.c_int),
        ("iFunctionNumber",  ctypes.c_int),
        ("iVendorID",        ctypes.c_int),
        ("strAdapterName",   ctypes.c_char * ADL_MAX_PATH),
        ("strDisplayName",   ctypes.c_char * ADL_MAX_PATH),
        ("iPresent",         ctypes.c_int),
        ("iExist",           ctypes.c_int),
        ("strDriverPath",    ctypes.c_char * ADL_MAX_PATH),
        ("strDriverPathExt", ctypes.c_char * ADL_MAX_PATH),
        ("strPNPString",     ctypes.c_char * ADL_MAX_PATH),
        ("iOSDisplayIndex",  ctypes.c_int),
    ]


class ADLI2CData(ctypes.Structure):
    _fields_ = [
        ("iSize",     ctypes.c_int),
        ("iLine",     ctypes.c_int),
        ("iAddress",  ctypes.c_int),
        ("iOffset",   ctypes.c_int),
        ("iAction",   ctypes.c_int),
        ("iSpeed",    ctypes.c_int),
        ("iDataSize", ctypes.c_int),
        ("pcData",    ctypes.c_char_p),
    ]


ADL_MALLOC_CB = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int)


@ADL_MALLOC_CB
def _malloc(size):
    return ctypes.cast(ctypes.create_string_buffer(size), ctypes.c_void_p).value


def sep(char="-", n=60):
    print(char * n)


def main():
    dll_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DLL

    print("ASRock RX 9070 XT RGB — ADL Diagnostic")
    sep()

    # 1. Load DLL
    print(f"[1] Loading DLL: {dll_path}")
    if not os.path.exists(dll_path):
        print("    FAIL — file not found")
        sys.exit(1)
    try:
        adl = ctypes.WinDLL(dll_path)
        print("    OK")
    except OSError as e:
        print(f"    FAIL — {e}")
        sys.exit(1)

    # 2. Init ADL
    print("[2] ADL_Main_Control_Create …")
    ret = adl.ADL_Main_Control_Create(_malloc, 1)
    if ret != ADL_OK:
        print(f"    FAIL (ret={ret})")
        sys.exit(1)
    print("    OK")

    # 3. Enumerate adapters
    print("[3] Enumerating AMD adapters …")
    num = ctypes.c_int(0)
    adl.ADL_Adapter_NumberOfAdapters_Get(ctypes.byref(num))
    count = num.value
    print(f"    Adapter count: {count}")

    if count == 0:
        print("    No adapters found — is AMD driver installed?")
        adl.ADL_Main_Control_Destroy()
        sys.exit(1)

    InfoArray = ADLAdapterInfo * count
    info_array = InfoArray()
    ctypes.memset(info_array, 0, ctypes.sizeof(info_array))

    adl.ADL_Adapter_AdapterInfo_Get(
        ctypes.cast(info_array, ctypes.POINTER(ADLAdapterInfo)),
        ctypes.sizeof(info_array),
    )

    sep()
    asrock_index = None
    for info in info_array:
        if not info.iPresent:
            continue
        name = info.strAdapterName.decode(errors="replace")
        pnp  = info.strPNPString.decode(errors="replace")
        print(f"  Adapter {info.iAdapterIndex:2d}: {name}")
        print(f"             VendorID=0x{info.iVendorID:04X}  PNP={pnp[:60]}")

        # Try SubSystem API
        subvendor = None
        try:
            sv = ctypes.c_int(0)
            ss = ctypes.c_int(0)
            r = adl.ADL_Adapter_SubSystem_Get(info.iAdapterIndex, ctypes.byref(sv), ctypes.byref(ss))
            if r == ADL_OK:
                subvendor = sv.value
                print(f"             SubVendorID=0x{subvendor:04X}  SubSystemID=0x{ss.value:04X}")
        except AttributeError:
            print("             ADL_Adapter_SubSystem_Get not in DLL")

        is_asrock = (subvendor == ASROCK_SUBVENDOR) or (subvendor is None and "1849" in pnp)
        if is_asrock and asrock_index is None:
            asrock_index = info.iAdapterIndex
            print(f"             *** ASRock match ***")

    sep()

    # Fallback: first present adapter
    if asrock_index is None:
        print("[!] ASRock adapter not positively identified — using first present adapter")
        for info in info_array:
            if info.iPresent:
                asrock_index = info.iAdapterIndex
                break

    if asrock_index is None:
        print("FAIL — no usable adapter found")
        adl.ADL_Main_Control_Destroy()
        sys.exit(1)

    # 4. Probe I2C on channels 3, 6, 7
    print(f"[4] Probing I2C on adapter {asrock_index} (channels 3, 6, 7) …")

    found = False
    for channel in [3, 6, 7]:
        buf = ctypes.create_string_buffer(8)
        data = ADLI2CData()
        data.iSize    = ctypes.sizeof(ADLI2CData)
        data.iLine    = channel
        data.iAddress = RGB_I2C_ADDR
        data.iOffset  = 0x10
        data.iAction  = 1      # ADL_DL_I2C_ACTIONREAD
        data.iSpeed   = 10
        data.iDataSize = 8
        data.pcData   = ctypes.cast(buf, ctypes.c_char_p)

        ret = adl.ADL_Display_WriteAndReadI2C(asrock_index, ctypes.byref(data))
        if ret == ADL_OK:
            raw = buf.raw.hex(" ").upper()
            print(f"    Channel {channel}: OK — bytes: {raw}")
            found = True
        else:
            print(f"    Channel {channel}: ret={ret}")

    sep("=")
    if found:
        print("RESULT: ASRock RGB controller FOUND — setup looks good.")
    else:
        print("RESULT: I2C probe failed — controller not responding.")
        print("        Check: run as Administrator, driver version, adapter index.")

    adl.ADL_Main_Control_Destroy()
    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()
