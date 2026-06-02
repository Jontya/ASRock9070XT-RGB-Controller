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
ASROCK_SUBVENDOR = "1849"
RGB_I2C_ADDR = 0x36
DISCRETE_DEV_IDS = {"7550"}


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


def i2c_write(adl, adapter: int, line: int, addr: int, offset: int, data: bytes) -> int:
    buf = ctypes.create_string_buffer(data)
    d = ADLI2CData()
    d.iSize     = ctypes.sizeof(ADLI2CData)
    d.iLine     = line
    d.iAddress  = addr
    d.iOffset   = offset
    d.iAction   = 2       # WRITE
    d.iSpeed    = 100
    d.iDataSize = len(data)
    d.pcData    = ctypes.cast(buf, ctypes.c_char_p)
    return adl.ADL_Display_WriteAndReadI2C(adapter, ctypes.byref(d))


def i2c_read(adl, adapter: int, line: int, addr: int, offset: int, length: int = 8) -> tuple:
    buf = ctypes.create_string_buffer(length)
    d = ADLI2CData()
    d.iSize     = ctypes.sizeof(ADLI2CData)
    d.iLine     = line
    d.iAddress  = addr
    d.iOffset   = offset
    d.iAction   = 1       # READ
    d.iSpeed    = 100
    d.iDataSize = length
    d.pcData    = ctypes.cast(buf, ctypes.c_char_p)
    ret = adl.ADL_Display_WriteAndReadI2C(adapter, ctypes.byref(d))
    return ret, buf.raw


def main():
    dll_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DLL

    print("ASRock RX 9070 XT RGB — ADL Diagnostic")
    sep()

    print(f"[1] Loading DLL: {dll_path}")
    if not os.path.exists(dll_path):
        print("    FAIL — file not found"); sys.exit(1)
    try:
        adl = ctypes.WinDLL(dll_path)
        print("    OK")
    except OSError as e:
        print(f"    FAIL — {e}"); sys.exit(1)

    print("[2] ADL_Main_Control_Create …")
    if adl.ADL_Main_Control_Create(_malloc, 1) != ADL_OK:
        print("    FAIL"); sys.exit(1)
    print("    OK")

    print("[3] Enumerating AMD adapters …")
    num = ctypes.c_int(0)
    adl.ADL_Adapter_NumberOfAdapters_Get(ctypes.byref(num))
    count = num.value
    print(f"    Adapter count: {count}")

    if count == 0:
        print("    No adapters"); adl.ADL_Main_Control_Destroy(); sys.exit(1)

    InfoArray = ADLAdapterInfo * count
    info_array = InfoArray()
    ctypes.memset(info_array, 0, ctypes.sizeof(info_array))
    adl.ADL_Adapter_AdapterInfo_Get(
        ctypes.cast(info_array, ctypes.POINTER(ADLAdapterInfo)),
        ctypes.sizeof(info_array),
    )

    sep()
    discrete = []
    for info in info_array:
        if not info.iPresent:
            continue
        name = info.strAdapterName.decode(errors="replace")
        pnp  = info.strPNPString.decode(errors="replace").upper()
        dev  = next((p[4:8] for p in pnp.split("&") if p.startswith("DEV_")), "")
        tag  = " *** ASRock ***" if ASROCK_SUBVENDOR in pnp else ""
        print(f"  Adapter {info.iAdapterIndex:2d}: {name}  DEV={dev}{tag}")
        if ASROCK_SUBVENDOR in pnp and dev in DISCRETE_DEV_IDS:
            discrete.append(info.iAdapterIndex)

    sep()

    # Use only the first discrete adapter for scanning — they're all the same physical GPU
    if not discrete:
        print("No discrete ASRock adapter found — aborting")
        adl.ADL_Main_Control_Destroy(); sys.exit(1)

    scan_adapter = discrete[0]
    print(f"[4] Scanning adapter {scan_adapter} — I2C bus line sweep (lines 0-15)")
    print(f"    Address 0x{RGB_I2C_ADDR:02X}, offset 0x10, write [0x01,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00]")
    sep()

    hits = []
    test_payload = bytes([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00])

    for line in range(16):
        ret = i2c_write(adl, scan_adapter, line, RGB_I2C_ADDR, 0x10, test_payload)
        if ret == ADL_OK:
            print(f"  Line {line:2d}: WRITE OK  *** controller may be here ***")
            hits.append(line)
        else:
            # Also try read so we can distinguish "bus exists, no device" from "bus invalid"
            rret, rdata = i2c_read(adl, scan_adapter, line, RGB_I2C_ADDR, 0x10)
            if rret == ADL_OK:
                print(f"  Line {line:2d}: READ  OK  data={rdata.hex(' ').upper()}  *** controller here ***")
                hits.append(line)
            else:
                print(f"  Line {line:2d}: write ret={ret}  read ret={rret}")

    sep()

    # Also try alternate I2C address 0x6C (0x36 shifted left — some ADL variants expect 8-bit addr)
    print(f"[5] Same scan with alternate address 0x6C (0x36 << 1) …")
    sep()
    for line in range(16):
        ret = i2c_write(adl, scan_adapter, line, 0x6C, 0x10, test_payload)
        if ret == ADL_OK:
            print(f"  Line {line:2d} @ 0x6C: WRITE OK  *** try addr=0x6C ***")
            hits.append(f"line={line},addr=0x6C")

    sep("=")
    if hits:
        print(f"RESULT: Responding lines: {hits}")
        print("        Update RGB_I2C_ADDR / channel constants with these values.")
    else:
        print("RESULT: No I2C response on any line 0-15 at either address.")
        print("        Possible causes:")
        print("          - ADL_Display_WriteAndReadI2C not the right function for this driver")
        print("          - I2C access requires a specific initialisation sequence first")
        print("          - Try with a display connected to the GPU (some drivers gate I2C on active output)")

    adl.ADL_Main_Control_Destroy()
    sys.exit(0 if hits else 1)


if __name__ == "__main__":
    main()
