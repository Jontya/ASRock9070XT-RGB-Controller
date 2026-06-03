"""
Full D3DKMT call trace for AsrPolychromeRGB.exe (32-bit WoW64).

Hooks all D3DKMT functions present in the process, logging every call
with full buffer contents (enter + leave). Produces:
  captures/trace_<timestamp>.json   — machine-readable
  captures/trace_<timestamp>.txt    — human-readable summary

Run BEFORE launching Polychrome. Script will wait for the process to appear.
Alternatively attach after launch — but some adapter-open calls fire at startup.

Usage (Administrator terminal):
    python tools/frida_full_trace.py
"""

import frida
import sys
import json
import time
import os
from datetime import datetime

# ---------------------------------------------------------------------------
# Frida JS payload (32-bit WoW64 context)
# ---------------------------------------------------------------------------

JS = r"""
(function() {
    'use strict';

    var callSeq   = 0;
    var hookedFns = {};

    // All D3DKMT / NtGdi symbols we care about
    var TARGET = [
        "D3DKMTEscape",
        "NtGdiDdDDIEscape",
        "D3DKMTQueryAdapterInfo",
        "D3DKMTOpenAdapterFromGdiDisplayName",
        "D3DKMTOpenAdapterFromHdc",
        "D3DKMTOpenAdapterFromDeviceName",
        "D3DKMTOpenAdapterFromLuid",
        "D3DKMTCreateDevice",
        "D3DKMTDestroyDevice",
        "D3DKMTCloseAdapter",
        "D3DKMTEnumAdapters",
        "D3DKMTEnumAdapters2",
    ];

    function hexOf(ptr, len) {
        if (!ptr || len <= 0) return null;
        try {
            var arr = new Uint8Array(ptr.readByteArray(Math.min(len, 4096)));
            var s = '';
            for (var i = 0; i < arr.length; i++) {
                var h = arr[i].toString(16);
                s += (h.length < 2 ? '0' : '') + h;
            }
            return s;
        } catch(e) {
            return null;
        }
    }

    function readEscapeStruct32(p) {
        // 32-bit D3DKMT_ESCAPE layout (all fields 4 bytes, no padding):
        // [0]  hAdapter
        // [4]  hDevice
        // [8]  Type
        // [12] Flags
        // [16] pPrivateDriverData  (32-bit pointer)
        // [20] PrivateDriverDataSize
        // [24] hContext
        try {
            return {
                hAdapter  : p.readU32(),
                hDevice   : p.add(4).readU32(),
                Type      : p.add(8).readU32(),
                Flags     : p.add(12).readU32(),
                pData     : ptr(p.add(16).readU32()),
                DataSize  : p.add(20).readU32(),
                hContext  : p.add(24).readU32(),
            };
        } catch(e) {
            return {err: e.message};
        }
    }

    function readQueryAdapterInfoStruct32(p) {
        // 32-bit D3DKMT_QUERYADAPTERINFO:
        // [0]  hAdapter
        // [4]  Type
        // [8]  pPrivateDriverData (32-bit pointer)
        // [12] PrivateDriverDataSize
        try {
            return {
                hAdapter : p.readU32(),
                Type     : p.add(4).readU32(),
                pData    : ptr(p.add(8).readU32()),
                DataSize : p.add(12).readU32(),
            };
        } catch(e) {
            return {err: e.message};
        }
    }

    function readOpenAdapterGdiStruct32(p) {
        // 32-bit D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME:
        // [0]    DeviceName WCHAR[32] = 64 bytes
        // [64]   hAdapter
        // [68]   LUID.LowPart
        // [72]   LUID.HighPart
        // [76]   VidPnSourceId
        try {
            var name = p.readUtf16String(32);
            return {devName: name};
        } catch(e) {
            return {err: e.message};
        }
    }

    // -----------------------------------------------------------------------

    Process.enumerateModules().forEach(function(mod) {
        try {
            mod.enumerateExports().forEach(function(exp) {
                if (TARGET.indexOf(exp.name) < 0) return;
                // Only hook first occurrence of each name
                if (hookedFns[exp.name]) return;

                var fnName  = exp.name;
                var modName = mod.name;
                var isEscape = (fnName === "D3DKMTEscape" || fnName === "NtGdiDdDDIEscape");
                var isQuery  = (fnName === "D3DKMTQueryAdapterInfo");
                var isOpenGdi= (fnName === "D3DKMTOpenAdapterFromGdiDisplayName");

                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            this.seq    = ++callSeq;
                            this.fn     = fnName;
                            this.mod    = modName;
                            this.pStruct= args[0];
                            this.ts     = Date.now();

                            var ev = {
                                seq: this.seq, fn: fnName, mod: modName,
                                phase: "enter", ts: this.ts,
                            };

                            if (isEscape) {
                                var s = readEscapeStruct32(this.pStruct);
                                this.esc = s;
                                ev.hAdapter = s.hAdapter;
                                ev.hDevice  = s.hDevice;
                                ev.Type     = s.Type;
                                ev.Flags    = s.Flags;
                                ev.DataSize = s.DataSize;
                                ev.hContext = s.hContext;
                                ev.bufIn    = hexOf(s.pData, s.DataSize);

                                // Mark I2C escapes (offset 8 contains line/addr info)
                                // iLine=2 is at buf[236] (offset 224+12), iAddress=0x6C at [240]
                                if (s.DataSize >= 244) {
                                    try {
                                        var line = s.pData.add(232).readU32();
                                        var addr = s.pData.add(236).readU32();
                                        if (line === 2 && addr === 0x6c) {
                                            ev.isI2C = true;
                                        }
                                    } catch(e) {}
                                }

                            } else if (isQuery) {
                                var s = readQueryAdapterInfoStruct32(this.pStruct);
                                this.qi = s;
                                ev.hAdapter = s.hAdapter;
                                ev.Type     = s.Type;
                                ev.DataSize = s.DataSize;

                            } else if (isOpenGdi) {
                                var s = readOpenAdapterGdiStruct32(this.pStruct);
                                ev.devName  = s.devName || s.err;

                            } else if (fnName === "D3DKMTCreateDevice") {
                                try { ev.hAdapter = this.pStruct.readU32(); } catch(e) {}

                            } else if (fnName === "D3DKMTCloseAdapter") {
                                try { ev.hAdapter = this.pStruct.readU32(); } catch(e) {}
                            }

                            send(ev);
                        },

                        onLeave: function(retval) {
                            var nts = retval.toUInt32();
                            var ev  = {
                                seq: this.seq, fn: this.fn, mod: this.mod,
                                phase: "leave", ts: Date.now(), nts: nts,
                            };

                            if (isEscape && this.esc && this.esc.pData) {
                                ev.bufOut = hexOf(this.esc.pData, this.esc.DataSize);
                            } else if (isQuery && this.qi && this.qi.pData && nts === 0) {
                                ev.bufOut = hexOf(this.qi.pData, Math.min(this.qi.DataSize, 512));
                            } else if (isOpenGdi && nts === 0) {
                                try {
                                    var p = this.pStruct;
                                    ev.hAdapter    = p.add(64).readU32();
                                    ev.luidLow     = p.add(68).readU32();
                                    ev.luidHigh    = p.add(72).readU32();
                                    ev.vidPnSource = p.add(76).readU32();
                                } catch(e) { ev.openErr = e.message; }
                            } else if (this.fn === "D3DKMTCreateDevice" && nts === 0) {
                                // hDevice is written back at offset 0 of struct
                                try { ev.hDevice = this.pStruct.readU32(); } catch(e) {}
                            } else if (this.fn === "D3DKMTEnumAdapters" && nts === 0) {
                                // Dump adapter count
                                try {
                                    ev.numAdapters = this.pStruct.readU32();
                                } catch(e) {}
                            }

                            send(ev);
                        }
                    });
                    hookedFns[fnName] = modName + '!' + fnName;
                    console.log("[+] " + modName + "!" + fnName);
                } catch(ex) {
                    console.log("[!] hook failed: " + fnName + " — " + ex.message);
                }
            });
        } catch(ex) {}
    });

    var hooked = Object.keys(hookedFns);
    console.log("[*] " + hooked.length + " hooks: " + JSON.stringify(hooked));
    if (hooked.length === 0) {
        send({error: "no D3DKMT functions found in process"});
    }
})();
"""

# ---------------------------------------------------------------------------
# Python driver
# ---------------------------------------------------------------------------

NTSTATUS = {
    0x00000000: "STATUS_SUCCESS",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC000A000: "STATUS_ILLEGAL_INSTRUCTION",
}


def nts_str(nts):
    name = NTSTATUS.get(nts, f"0x{nts:08X}")
    return name


def buf_diff(a_hex, b_hex):
    """Return list of (offset, old_byte, new_byte) for differing bytes."""
    if not a_hex or not b_hex:
        return []
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    diffs = []
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            diffs.append((i, x, y))
    return diffs


def find_polychrome():
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        n = proc.name.lower()
        if "polychrome" in n or "asrpolychrome" in n:
            return proc
    return None


def main():
    os.makedirs("captures", exist_ok=True)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join("captures", f"trace_{ts_str}.json")
    txt_path  = os.path.join("captures", f"trace_{ts_str}.txt")

    print("Waiting for AsrPolychromeRGB.exe ...")
    proc = None
    while proc is None:
        proc = find_polychrome()
        if proc is None:
            time.sleep(1)
            sys.stdout.write(".")
            sys.stdout.flush()
    print(f"\nAttaching to {proc.name} (pid {proc.pid}) ...")

    device  = frida.get_local_device()
    session = device.attach(proc.pid)
    script  = session.create_script(JS)

    events = []   # list of dicts (enter + leave, keyed by seq)
    pending = {}  # seq -> enter event, waiting for leave

    def on_message(msg, _data):
        if msg.get("type") == "error":
            print(f"[frida error] {msg.get('description', msg)}")
            return
        if msg.get("type") != "send":
            return
        p = msg["payload"]
        if "error" in p:
            print(f"[ERROR] {p['error']}")
            return

        phase = p.get("phase")
        seq   = p.get("seq")

        if phase == "enter":
            pending[seq] = p
        elif phase == "leave":
            enter_ev = pending.pop(seq, {})
            combined = {**enter_ev, **p}
            combined.pop("phase", None)

            # Compute buffer diff for escapes
            if combined.get("fn") in ("D3DKMTEscape", "NtGdiDdDDIEscape"):
                diffs = buf_diff(combined.get("bufIn"), combined.get("bufOut"))
                if diffs:
                    combined["bufDiff"] = [
                        {"offset": o, "from": f"{a:02x}", "to": f"{b:02x}"}
                        for o, a, b in diffs
                    ]
                    # Check if 0x0011002b appears in output at ANY offset
                    out = combined.get("bufOut", "")
                    token = "2b001100"
                    if token in out:
                        idx = out.index(token) // 2
                        combined["tokenFound"] = f"0x0011002b at output offset {idx}"

            events.append(combined)
            _print_event(combined)

    def _print_event(ev):
        fn  = ev.get("fn", "?")
        seq = ev.get("seq", "?")
        nts = ev.get("nts", None)
        nts_s = f" → {nts_str(nts)}" if nts is not None else ""
        h   = ev.get("hAdapter", 0)
        extra = ""
        if fn in ("D3DKMTEscape", "NtGdiDdDDIEscape"):
            ds = ev.get("DataSize", 0)
            t  = ev.get("Type", 0)
            is_i2c = ev.get("isI2C", False)
            extra = f"  hAdapter=0x{h:08X}  Type={t}  DataSize={ds}"
            if is_i2c:
                extra += "  *** I2C write ***"
        elif fn == "D3DKMTOpenAdapterFromGdiDisplayName":
            extra = f"  DeviceName={ev.get('devName','?')!r}"
            if nts == 0:
                ll = ev.get("luidLow", 0)
                lh = ev.get("luidHigh", 0)
                extra += f"  hAdapter=0x{ev.get('hAdapter',0):08X}  LUID={ll:#010x}:{lh:#010x}"
        elif fn == "D3DKMTQueryAdapterInfo":
            extra = f"  hAdapter=0x{h:08X}  Type={ev.get('Type',0)}"
        elif fn == "D3DKMTCreateDevice":
            extra = f"  hAdapter=0x{h:08X}"
            if nts == 0:
                extra += f"  → hDevice=0x{ev.get('hDevice',0):08X}"
        elif fn == "D3DKMTCloseAdapter":
            extra = f"  hAdapter=0x{h:08X}"

        token_note = ""
        if "tokenFound" in ev:
            token_note = f"  !!! TOKEN: {ev['tokenFound']}"

        print(f"  [{seq:>4}] {fn}{extra}{nts_s}{token_note}")

    script.on("message", on_message)
    script.load()

    print("\nReady. Now:")
    print("  1. Let Polychrome fully load (UI visible).")
    print("  2. Change one color (e.g. to red).")
    print("  3. Press Enter here to stop and write logs.\n")
    input()
    session.detach()

    # Write JSON
    with open(json_path, "w") as f:
        json.dump(events, f, indent=2)
    print(f"\nJSON log  : {json_path}")

    # Write human-readable summary
    _write_txt(txt_path, events)
    print(f"Text log  : {txt_path}")

    # Analysis
    _analyze(events)


def _write_txt(path, events):
    with open(path, "w") as f:
        f.write(f"D3DKMT Trace — {datetime.now().isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        i2c_seen = False
        for ev in events:
            fn  = ev.get("fn", "?")
            seq = ev.get("seq", "?")
            nts = ev.get("nts")
            nts_s = f"NTSTATUS={nts_str(nts)}" if nts is not None else ""

            if fn in ("D3DKMTEscape", "NtGdiDdDDIEscape") and ev.get("isI2C") and not i2c_seen:
                f.write("\n--- FIRST I2C ESCAPE BELOW ---\n\n")
                i2c_seen = True

            f.write(f"[{seq}] {fn}  {nts_s}\n")
            for key in ("hAdapter","hDevice","Type","Flags","DataSize","hContext",
                        "devName","luidLow","luidHigh","hDevice","numAdapters"):
                if key in ev:
                    v = ev[key]
                    if isinstance(v, int) and key not in ("Type","DataSize","numAdapters"):
                        f.write(f"  {key} = 0x{v:08X}\n")
                    else:
                        f.write(f"  {key} = {v}\n")

            if "tokenFound" in ev:
                f.write(f"  !!! {ev['tokenFound']}\n")

            if "bufIn" in ev and ev["bufIn"]:
                b = ev["bufIn"]
                f.write(f"  bufIn[0:32]  = {b[:64]}\n")
                if len(b) > 64:
                    f.write(f"  bufIn[212:228]= {b[424:456]}\n")
                    f.write(f"  bufIn[252:264]= {b[504:528]}\n")

            if "bufDiff" in ev:
                diffs = ev["bufDiff"]
                f.write(f"  bufDiff ({len(diffs)} bytes changed):\n")
                for d in diffs[:32]:
                    f.write(f"    offset {d['offset']:>5}: {d['from']} -> {d['to']}\n")
                if len(diffs) > 32:
                    f.write(f"    ... and {len(diffs)-32} more\n")

            f.write("\n")


def _analyze(events):
    print("\n" + "=" * 60)
    print("ANALYSIS")
    print("=" * 60)

    # Find first I2C escape
    i2c_idx = None
    for i, ev in enumerate(events):
        if ev.get("fn") in ("D3DKMTEscape", "NtGdiDdDDIEscape") and ev.get("isI2C"):
            i2c_idx = i
            break

    if i2c_idx is None:
        print("WARNING: No I2C escape detected (iLine=2, iAddress=0x6C).")
        print("  Either Polychrome didn't change color, or offset math is wrong.")
        print("  Check raw JSON for escape calls.")
        return

    pre_i2c = events[:i2c_idx]
    print(f"\nCalls before first I2C escape ({i2c_idx} total):\n")

    token_sources = []
    for ev in pre_i2c:
        fn  = ev.get("fn", "?")
        nts = ev.get("nts")
        seq = ev.get("seq", "?")
        print(f"  [{seq}] {fn}  {nts_str(nts) if nts is not None else ''}")
        if "tokenFound" in ev:
            print(f"         ^-- TOKEN 0x0011002b appears in OUTPUT at {ev['tokenFound']}")
            token_sources.append(ev)

    # Adapter open calls
    print("\nAdapter open calls:")
    for ev in events:
        if ev.get("fn") == "D3DKMTOpenAdapterFromGdiDisplayName":
            nts = ev.get("nts", -1)
            dev = ev.get("devName", "?")
            h   = ev.get("hAdapter", 0)
            ll  = ev.get("luidLow", 0)
            lh  = ev.get("luidHigh", 0)
            print(f"  {dev!r}  hAdapter=0x{h:08X}  LUID={ll:#010x}:{lh:#010x}  {nts_str(nts)}")

    if token_sources:
        print(f"\nToken 0x0011002b sourced from call [{token_sources[0].get('seq')}] "
              f"{token_sources[0].get('fn')}")
    else:
        print("\nToken 0x0011002b NOT found as output in any pre-I2C call.")
        print("It may come from a different API (IOCTL, registry read, etc.)")

    # Which DLL was used for I2C escape
    i2c_ev = events[i2c_idx]
    print(f"\nI2C escape (call [{i2c_ev.get('seq')}]) via: {i2c_ev.get('mod','?')}")


if __name__ == "__main__":
    main()
