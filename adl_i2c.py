"""
ADL I2C interface for ASRock RX 9070 XT Steel Legend RGB control.
Calls atiadlxx.dll via ctypes. No third-party dependencies.
"""

import ctypes
import json
import os
import sys

# ---------------------------------------------------------------------------
# ADL constants
# ---------------------------------------------------------------------------

ADL_OK = 0
ADL_MAX_PATH = 256

ASROCK_SUBVENDOR = 0x1849
RGB_I2C_ADDR = 0x36
RGB_CMD = 0x10

RGB_CHANNELS = [3, 6, 7]

DEFAULT_DLL_PATH = r"C:\Windows\System32\atiadlxx.dll"


# ---------------------------------------------------------------------------
# ADL structures — Windows layout only
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# ADL memory allocation callback
# ---------------------------------------------------------------------------

ADL_MAIN_MALLOC_CALLBACK = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int)


@ADL_MAIN_MALLOC_CALLBACK
def _adl_malloc(size):
    return ctypes.cast(ctypes.create_string_buffer(size), ctypes.c_void_p).value


# ---------------------------------------------------------------------------
# Controller class
# ---------------------------------------------------------------------------

class ASRockRGBController:
    """Manages ADL initialisation and RGB channel writes."""

    def __init__(self, dll_path: str = DEFAULT_DLL_PATH):
        self._dll_path = dll_path
        self._adl = None
        self._adapter_index = None

    def open(self) -> None:
        if not os.path.exists(self._dll_path):
            raise FileNotFoundError(f"ADL DLL not found: {self._dll_path}")
        try:
            self._adl = ctypes.WinDLL(self._dll_path)
        except OSError as exc:
            raise RuntimeError(f"Failed to load ADL DLL: {exc}") from exc

        ret = self._adl.ADL_Main_Control_Create(_adl_malloc, 1)
        if ret != ADL_OK:
            raise RuntimeError(f"ADL_Main_Control_Create failed: {ret}")

        self._adapter_index = self._find_asrock_adapter()
        if self._adapter_index is None:
            raise RuntimeError("ASRock GPU (SubVendor 0x1849) not found on any AMD adapter")

    def close(self) -> None:
        if self._adl is not None:
            try:
                self._adl.ADL_Main_Control_Destroy()
            except Exception:
                pass
            self._adl = None
            self._adapter_index = None

    def set_color(self, r: int, g: int, b: int) -> None:
        if self._adl is None or self._adapter_index is None:
            raise RuntimeError("Controller not open — call open() first")
        errors = []
        for ch in RGB_CHANNELS:
            try:
                self._write_channel(ch, r, g, b)
            except Exception as exc:
                errors.append(f"Channel {ch}: {exc}")
        if errors:
            raise RuntimeError("; ".join(errors))

    # ------------------------------------------------------------------

    def _find_asrock_adapter(self) -> "int | None":
        num = ctypes.c_int(0)
        ret = self._adl.ADL_Adapter_NumberOfAdapters_Get(ctypes.byref(num))
        if ret != ADL_OK:
            raise RuntimeError(f"ADL_Adapter_NumberOfAdapters_Get failed: {ret}")

        count = num.value
        if count == 0:
            return None

        InfoArray = ADLAdapterInfo * count
        info_array = InfoArray()
        ctypes.memset(info_array, 0, ctypes.sizeof(info_array))

        ret = self._adl.ADL_Adapter_AdapterInfo_Get(
            ctypes.cast(info_array, ctypes.POINTER(ADLAdapterInfo)),
            ctypes.sizeof(info_array),
        )
        if ret != ADL_OK:
            raise RuntimeError(f"ADL_Adapter_AdapterInfo_Get failed: {ret}")

        # First pass: look for ASRock subvendor
        try:
            fn = self._adl.ADL_Adapter_SubSystem_Get
            for info in info_array:
                if not info.iPresent:
                    continue
                sv = ctypes.c_int(0)
                ss = ctypes.c_int(0)
                if fn(info.iAdapterIndex, ctypes.byref(sv), ctypes.byref(ss)) == ADL_OK:
                    if sv.value == ASROCK_SUBVENDOR:
                        return info.iAdapterIndex
        except AttributeError:
            pass

        # Fallback: PNP string contains "1849" (subvendor in hardware ID)
        for info in info_array:
            if not info.iPresent:
                continue
            pnp = info.strPNPString.decode(errors="replace")
            if "1849" in pnp:
                return info.iAdapterIndex

        # Last resort: first present adapter (single-GPU system)
        for info in info_array:
            if info.iPresent:
                return info.iAdapterIndex

        return None

    def _write_channel(self, channel: int, r: int, g: int, b: int) -> None:
        payload = bytes([0x01, r, g, b, 0xFF, 0x00, 0x00, 0x00])
        buf = ctypes.create_string_buffer(payload)

        data = ADLI2CData()
        data.iSize = ctypes.sizeof(ADLI2CData)
        data.iLine = channel
        data.iAddress = RGB_I2C_ADDR
        data.iOffset = RGB_CMD
        data.iAction = 2       # ADL_DL_I2C_ACTIONWRITE
        data.iSpeed = 10
        data.iDataSize = len(payload)
        data.pcData = ctypes.cast(buf, ctypes.c_char_p)

        ret = self._adl.ADL_Display_WriteAndReadI2C(
            self._adapter_index, ctypes.byref(data)
        )
        if ret != ADL_OK:
            raise RuntimeError(f"I2C write failed (ret={ret})")


# ---------------------------------------------------------------------------
# Convenience one-shot function
# ---------------------------------------------------------------------------

def apply_color(r: int, g: int, b: int, dll_path: str = DEFAULT_DLL_PATH) -> None:
    ctrl = ASRockRGBController(dll_path)
    ctrl.open()
    try:
        ctrl.set_color(r, g, b)
    finally:
        ctrl.close()


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
