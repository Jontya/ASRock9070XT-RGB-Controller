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

# Known discrete GPU PCI device IDs for ASRock RX 9070 XT
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


def pnp_dev_id(pnp: str) -> str:
    """Extract DEV_xxxx value from PNP string."""
    for part in pnp.upper().split("&"):
        if part.startswith("DEV_"):
            return part[4:8]
    return ""


def probe_i2c(adl, adapter_index: int, channel: int) -> tuple:
    """Try read then write probe. Returns (ok: bool, detail: str)."""
    for action, label in ((1, "READ"), (2, "WRITE")):
        buf = ctypes.create_string_buffer(8)
        if action == 2:
            # Static white as test write — harmless
            buf = ctypes.create_string_buffer(bytes([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]))
        data = ADLI2CData()
        data.iSize     = ctypes.sizeof(ADLI2CData)
        data.iLine     = channel
        data.iAddress  = RGB_I2C_ADDR
        data.iOffset   = 0x10
        data.iAction   = action
        data.iSpeed    = 10
        data.iDataSize = 8
        data.pcData    = ctypes.cast(buf, ctypes.c_char_p)
        ret = adl.ADL_Display_WriteAndReadI2C(adapter_index, ctypes.byref(data))
        if ret == ADL_OK:
            raw = buf.raw.hex(" ").upper()
            return True, f"{label} OK — bytes: {raw}"
    return False, f"ret={ret}"


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

    # Collect all ASRock adapters; prefer discrete GPU (DEV_7550) over iGPU
    discrete_matches = []
    all_matches = []

    for info in info_array:
        if not info.iPresent:
            continue
        name = info.strAdapterName.decode(errors="replace")
        pnp  = info.strPNPString.decode(errors="replace")
        dev  = pnp_dev_id(pnp)
        is_asrock = ASROCK_SUBVENDOR in pnp.upper()
        tag = " *** ASRock match ***" if is_asrock else ""
        print(f"  Adapter {info.iAdapterIndex:2d}: {name}")
        print(f"             DEV={dev}  PNP={pnp[:55]}{tag}")
        if is_asrock:
            all_matches.append(info.iAdapterIndex)
            if dev in DISCRETE_DEV_IDS:
                discrete_matches.append(info.iAdapterIndex)

    sep()

    # Prefer discrete; fall back to any ASRock match; last resort: first present
    candidate_pool = discrete_matches if discrete_matches else all_matches
    if not candidate_pool:
        print("[!] No ASRock adapters found — trying all present adapters")
        candidate_pool = [i.iAdapterIndex for i in info_array if i.iPresent]

    print(f"[4] Probing I2C (addr=0x{RGB_I2C_ADDR:02X}) on candidates: {candidate_pool}")
    print(f"    {'discrete' if discrete_matches else 'all-asrock'} pool selected")
    sep()

    found_adapter = None
    for adapter_idx in candidate_pool:
        print(f"  Adapter {adapter_idx}:")
        for channel in [3, 6, 7]:
            ok, detail = probe_i2c(adl, adapter_idx, channel)
            status = "OK  " if ok else "FAIL"
            print(f"    Channel {channel}: {status} — {detail}")
            if ok and found_adapter is None:
                found_adapter = adapter_idx

    sep("=")
    if found_adapter is not None:
        print(f"RESULT: ASRock RGB controller FOUND on adapter {found_adapter}.")
        print(f"        Use adapter_index={found_adapter} in config if needed.")
    else:
        print("RESULT: I2C probe failed on all candidates.")
        print("        Check: run as Administrator, AMD driver version.")

    adl.ADL_Main_Control_Destroy()
    sys.exit(0 if found_adapter is not None else 1)


if __name__ == "__main__":
    main()
