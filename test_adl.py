"""
ADL diagnostic — full adapter × line sweep at 0x36 (true RGB controller address).
Run as Administrator. Exits 0 if any write succeeds at 0x36, 1 otherwise.
"""

import ctypes
import os
import sys

DEFAULT_DLL = r"C:\Windows\System32\atiadlxx.dll"
ADL_OK = 0
ADL_MAX_PATH = 256

RGB_I2C_ADDR = 0x36   # 7-bit address of ASRock RGB controller


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


def i2c_write(adl, adapter, line, addr, offset, data, speed=100):
    buf = ctypes.create_string_buffer(bytes(data))
    d = ADLI2CData()
    d.iSize     = ctypes.sizeof(ADLI2CData)
    d.iLine     = line
    d.iAddress  = addr
    d.iOffset   = offset
    d.iAction   = 2
    d.iSpeed    = speed
    d.iDataSize = len(data)
    d.pcData    = ctypes.cast(buf, ctypes.c_char_p)
    return adl.ADL_Display_WriteAndReadI2C(adapter, ctypes.byref(d))


def sep(char="-", n=64):
    print(char * n)


def main():
    dll_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DLL

    print("ASRock RX 9070 XT — Full I2C sweep at address 0x36")
    sep()

    if not os.path.exists(dll_path):
        print(f"DLL not found: {dll_path}"); sys.exit(1)
    adl = ctypes.WinDLL(dll_path)
    if adl.ADL_Main_Control_Create(_malloc, 1) != ADL_OK:
        print("ADL init failed"); sys.exit(1)

    num = ctypes.c_int(0)
    adl.ADL_Adapter_NumberOfAdapters_Get(ctypes.byref(num))
    count = num.value
    print(f"Adapters: {count}")

    InfoArray = ADLAdapterInfo * count
    info_array = InfoArray()
    ctypes.memset(info_array, 0, ctypes.sizeof(info_array))
    adl.ADL_Adapter_AdapterInfo_Get(
        ctypes.cast(info_array, ctypes.POINTER(ADLAdapterInfo)),
        ctypes.sizeof(info_array),
    )

    # Test payload: bright red static color
    # Format C (original spec): offset=channel, data=[mode, R, G, B, br, sp, dir, 0x00]
    # Format A: offset=0x10, data=[ch, mode, R, G, B, br, sp, dir]
    test_cases = [
        ("off=0x10 data=[3,mode,R,G,B]", 0x10, [3, 0x01, 255, 0, 0, 0xFF, 0x00, 0x00]),
        ("off=0x03 data=[mode,R,G,B]",   0x03, [0x01, 255, 0, 0, 0xFF, 0x00, 0x00, 0x00]),
    ]

    hits = []

    for info in info_array:
        if not info.iPresent:
            continue
        idx  = info.iAdapterIndex
        name = info.strAdapterName.decode(errors="replace")
        print(f"\nAdapter {idx}: {name}")

        for line in range(8):
            results = []
            for label, offset, data in test_cases:
                for speed in [10, 100]:
                    ret = i2c_write(adl, idx, line, RGB_I2C_ADDR, offset, data, speed)
                    if ret == ADL_OK:
                        results.append(f"{label} speed={speed} -> OK ***")
                        hits.append((idx, line, label, speed))
                    else:
                        results.append(f"ret={ret}")
            # Only print non-boring lines (anything other than all -1 or all -3)
            unique = set(r for r in results if "OK" in r or ("ret=" in r and "ret=-1" not in r and "ret=-3" not in r))
            if unique or any("OK" in r for r in results):
                print(f"  line {line}: {' | '.join(results)}")

    sep("=")
    if hits:
        print("HITS (adapter, line, format, speed):")
        for h in hits:
            print(f"  {h}")
        print("\nLEDs should have changed to RED. If they did, note adapter+line above.")
    else:
        print("No ADL_OK at address 0x36 on any adapter/line combination.")
        print()
        print("Conclusions:")
        print("  - The RGB controller is not accessible via ADL_Display_WriteAndReadI2C")
        print("  - Possible alternatives:")
        print("    1. Check if ASRock Polychrome Sync app is installed and interfering")
        print("    2. Try OpenRGB — it may use a different detection method for 9070 XT")
        print("    3. The 9070 XT may use USB HID or a different I2C init sequence")

    adl.ADL_Main_Control_Destroy()
    sys.exit(0 if hits else 1)


if __name__ == "__main__":
    main()
