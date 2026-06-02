"""
ADL diagnostic script — run via Windows Python (as Administrator) to verify setup.
Phase 2: payload format probe. Watch for LED color changes to identify correct format.
Exits 0 on success, 1 on failure.
"""

import ctypes
import os
import sys
import time

DEFAULT_DLL = r"C:\Windows\System32\atiadlxx.dll"
ADL_OK = 0
ADL_MAX_PATH = 256
ASROCK_SUBVENDOR = "1849"
DISCRETE_DEV_IDS = {"7550"}

# Confirmed from scan: ADL expects 8-bit (pre-shifted) address
RGB_I2C_ADDR = 0x6C

# Lines that responded in the previous scan
CANDIDATE_LINES = [1, 3, 4, 5, 6, 7]


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


def i2c_write(adl, adapter, line, addr, offset, data):
    buf = ctypes.create_string_buffer(bytes(data))
    d = ADLI2CData()
    d.iSize     = ctypes.sizeof(ADLI2CData)
    d.iLine     = line
    d.iAddress  = addr
    d.iOffset   = offset
    d.iAction   = 2
    d.iSpeed    = 100
    d.iDataSize = len(data)
    d.pcData    = ctypes.cast(buf, ctypes.c_char_p)
    return adl.ADL_Display_WriteAndReadI2C(adapter, ctypes.byref(d))


def sep(char="-", n=60):
    print(char * n)


def load_adl(dll_path):
    adl = ctypes.WinDLL(dll_path)
    adl.ADL_Main_Control_Create(_malloc, 1)
    return adl


def get_discrete_adapter(adl):
    num = ctypes.c_int(0)
    adl.ADL_Adapter_NumberOfAdapters_Get(ctypes.byref(num))
    InfoArray = ADLAdapterInfo * num.value
    info_array = InfoArray()
    ctypes.memset(info_array, 0, ctypes.sizeof(info_array))
    adl.ADL_Adapter_AdapterInfo_Get(
        ctypes.cast(info_array, ctypes.POINTER(ADLAdapterInfo)),
        ctypes.sizeof(info_array),
    )
    for info in info_array:
        if not info.iPresent:
            continue
        pnp = info.strPNPString.decode(errors="replace").upper()
        dev = next((p[4:8] for p in pnp.split("&") if p.startswith("DEV_")), "")
        if ASROCK_SUBVENDOR in pnp and dev in DISCRETE_DEV_IDS:
            return info.iAdapterIndex
    return None


def main():
    dll_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DLL

    print("ASRock RX 9070 XT RGB — Payload Format Probe")
    print("Watch your GPU LEDs for color changes during each test.")
    sep()

    adl = load_adl(dll_path)
    adapter = get_discrete_adapter(adl)
    if adapter is None:
        print("Discrete adapter not found"); sys.exit(1)
    print(f"Using adapter {adapter}")
    sep()

    # -----------------------------------------------------------------------
    # Payload format candidates (bright RED = 255,0,0 so changes are obvious)
    # Each format is described + tested across all candidate lines.
    # The first format that causes a visible LED change is correct.
    # -----------------------------------------------------------------------
    R, G, B = 255, 0, 0  # bright red — easy to see

    formats = [
        # (label, offset, data_fn)
        # data_fn(channel) -> list of ints
        (
            "A: offset=0x10, data=[ch, mode, R, G, B, br, sp, dir]",
            lambda ch: (0x10, [ch, 0x01, R, G, B, 0xFF, 0x00, 0x00]),
        ),
        (
            "B: offset=0x00, data=[0x10, ch, mode, R, G, B, br, sp, dir]",
            lambda ch: (0x00, [0x10, ch, 0x01, R, G, B, 0xFF, 0x00, 0x00]),
        ),
        (
            "C: offset=ch, data=[mode, R, G, B, br, sp, dir, 0x00]  (original spec)",
            lambda ch: (ch, [0x01, R, G, B, 0xFF, 0x00, 0x00, 0x00]),
        ),
        (
            "D: offset=0x10, data=[mode, R, G, B, br, sp, dir, 0x00]  (no ch byte)",
            lambda ch: (0x10, [0x01, R, G, B, 0xFF, 0x00, 0x00, 0x00]),
        ),
    ]

    rgb_channels = [3, 6, 7]

    for fmt_label, fmt_fn in formats:
        print(f"\nFormat {fmt_label}")
        input("  Press ENTER to send this format to all lines/channels, then watch LEDs …")
        any_ok = False
        for line in CANDIDATE_LINES:
            for ch in rgb_channels:
                offset, data = fmt_fn(ch)
                ret = i2c_write(adl, adapter, line, RGB_I2C_ADDR, offset, data)
                if ret == ADL_OK:
                    any_ok = True
            # brief pause between lines so a change is noticeable
            time.sleep(0.1)
        print(f"  Sent. Did LEDs change? (y/n): ", end="", flush=True)
        ans = input().strip().lower()
        if ans == "y":
            print(f"\n  *** FORMAT CONFIRMED: {fmt_label} ***")
            print(f"      Lines tried: {CANDIDATE_LINES}")
            print(f"      Now running fine-grained line test to find exact bus …")
            sep()
            # Find which specific line triggers the change
            colors = [(255,0,0), (0,255,0), (0,0,255)]
            color_names = ["RED", "GREEN", "BLUE"]
            for line in CANDIDATE_LINES:
                c = colors[CANDIDATE_LINES.index(line) % 3]
                cn = color_names[CANDIDATE_LINES.index(line) % 3]
                for ch in rgb_channels:
                    offset, data_tpl = fmt_fn(ch)
                    # Replace R,G,B in data with current test color
                    data = list(data_tpl)
                    # Find and patch RGB bytes
                    for i, v in enumerate(data):
                        if v == R: data[i] = c[0]
                        elif v == G and c[1] != R: data[i] = c[1]
                    i2c_write(adl, adapter, line, RGB_I2C_ADDR, offset, data)
                print(f"  Line {line}: sent {cn} to channels 3,6,7 — did a zone change? (y/n): ", end="", flush=True)
                if input().strip().lower() == "y":
                    print(f"      -> iLine={line} confirmed as active RGB bus")
            sep("=")
            print("RESULT: Protocol confirmed. Update adl_i2c.py with format and line above.")
            adl.ADL_Main_Control_Destroy()
            sys.exit(0)

    sep("=")
    print("RESULT: No format caused visible LED change.")
    print("        The I2C device at 0x6C may not be the RGB controller,")
    print("        or the controller needs a different initialisation sequence.")
    adl.ADL_Main_Control_Destroy()
    sys.exit(1)


if __name__ == "__main__":
    main()
