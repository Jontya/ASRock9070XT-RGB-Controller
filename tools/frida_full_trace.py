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
        } catch(e) { return null; }
    }

    function readEscapeStruct32(p) {
        try {
            return {
                hAdapter : p.readU32(),
                hDevice  : p.add(4).readU32(),
                Type     : p.add(8).readU32(),
                Flags    : p.add(12).readU32(),
                pData    : ptr(p.add(16).readU32()),
                DataSize : p.add(20).readU32(),
                hContext : p.add(24).readU32(),
            };
        } catch(e) { return {err: e.message}; }
    }

    function readQueryAdapterInfoStruct32(p) {
        try {
            return {
                hAdapter : p.readU32(),
                Type     : p.add(4).readU32(),
                pData    : ptr(p.add(8).readU32()),
                DataSize : p.add(12).readU32(),
            };
        } catch(e) { return {err: e.message}; }
    }

    function dumpAdapterArray(pBase, count) {
        // D3DKMT_ADAPTERINFO: 20 bytes
        //   [0]  hAdapter (4)
        //   [4]  LUID.LowPart (4)
        //   [8]  LUID.HighPart (4)
        //   [12] NumOfSources (4)
        //   [16] bPresentMoveRegionsPreferred (4)
        var list = [];
        for (var i = 0; i < count && i < 128; i++) {
            try {
                var b = pBase.add(i * 20);
                list.push({
                    hAdapter : b.readU32(),
                    luidLow  : b.add(4).readU32(),
                    luidHigh : b.add(8).readU32(),
                });
            } catch(e) { break; }
        }
        return list;
    }

    Process.enumerateModules().forEach(function(mod) {
        try {
            mod.enumerateExports().forEach(function(exp) {
                if (TARGET.indexOf(exp.name) < 0) return;
                if (hookedFns[exp.name]) return;

                var fnName  = exp.name;
                var modName = mod.name;
                var isEscape  = (fnName === "D3DKMTEscape" || fnName === "NtGdiDdDDIEscape");
                var isQuery   = (fnName === "D3DKMTQueryAdapterInfo");
                var isOpenGdi = (fnName === "D3DKMTOpenAdapterFromGdiDisplayName");
                var isOpenDev = (fnName === "D3DKMTOpenAdapterFromDeviceName");
                var isOpenLuid= (fnName === "D3DKMTOpenAdapterFromLuid");
                var isEnum    = (fnName === "D3DKMTEnumAdapters");
                var isEnum2   = (fnName === "D3DKMTEnumAdapters2");

                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            this.seq     = ++callSeq;
                            this.fn      = fnName;
                            this.mod     = modName;
                            this.pStruct = args[0];
                            this.ts      = Date.now();

                            var ev = {seq: this.seq, fn: fnName, mod: modName, phase: "enter", ts: this.ts};

                            if (isEscape) {
                                var s = readEscapeStruct32(this.pStruct);
                                this.esc = s;
                                ev.hAdapter = s.hAdapter; ev.hDevice = s.hDevice;
                                ev.Type = s.Type; ev.Flags = s.Flags;
                                ev.DataSize = s.DataSize; ev.hContext = s.hContext;
                                ev.bufIn = hexOf(s.pData, s.DataSize);
                                if (s.DataSize >= 244) {
                                    try {
                                        var line = s.pData.add(232).readU32();
                                        var addr = s.pData.add(236).readU32();
                                        if (line === 2 && addr === 0x6c) ev.isI2C = true;
                                    } catch(e) {}
                                }
                            } else if (isQuery) {
                                var s = readQueryAdapterInfoStruct32(this.pStruct);
                                this.qi = s;
                                ev.hAdapter = s.hAdapter; ev.Type = s.Type; ev.DataSize = s.DataSize;
                            } else if (isOpenGdi) {
                                try { ev.devName = this.pStruct.readUtf16String(); } catch(e) { ev.devName = "err:" + e.message; }
                            } else if (isOpenDev) {
                                // [0] pDeviceName (PCWSTR pointer, 4 bytes in 32-bit)
                                try {
                                    var pName = ptr(this.pStruct.readU32());
                                    ev.devName = pName.readUtf16String();
                                } catch(e) { ev.devName = "err:" + e.message; }
                            } else if (isOpenLuid) {
                                // [0] LUID.LowPart, [4] LUID.HighPart (input)
                                try { ev.luidLow = this.pStruct.readU32(); ev.luidHigh = this.pStruct.add(4).readU32(); } catch(e) {}
                            } else if (fnName === "D3DKMTCreateDevice") {
                                try { ev.hAdapter = this.pStruct.readU32(); } catch(e) {}
                            } else if (fnName === "D3DKMTCloseAdapter") {
                                try { ev.hAdapter = this.pStruct.readU32(); } catch(e) {}
                            }

                            send(ev);
                        },

                        onLeave: function(retval) {
                            var nts = retval.toUInt32();
                            var ev  = {seq: this.seq, fn: this.fn, mod: this.mod, phase: "leave", ts: Date.now(), nts: nts};

                            if (isEscape && this.esc && this.esc.pData) {
                                ev.bufOut = hexOf(this.esc.pData, this.esc.DataSize);
                            } else if (isQuery && this.qi && this.qi.pData && nts === 0) {
                                ev.bufOut = hexOf(this.qi.pData, Math.min(this.qi.DataSize, 512));
                            } else if (isOpenGdi && nts === 0) {
                                try {
                                    ev.hAdapter    = this.pStruct.add(64).readU32();
                                    ev.luidLow     = this.pStruct.add(68).readU32();
                                    ev.luidHigh    = this.pStruct.add(72).readU32();
                                    ev.vidPnSource = this.pStruct.add(76).readU32();
                                } catch(e) { ev.openErr = e.message; }
                            } else if (isOpenDev && nts === 0) {
                                // [4] hAdapter, [8] LUID.LowPart, [12] LUID.HighPart
                                try {
                                    ev.hAdapter = this.pStruct.add(4).readU32();
                                    ev.luidLow  = this.pStruct.add(8).readU32();
                                    ev.luidHigh = this.pStruct.add(12).readU32();
                                } catch(e) { ev.openErr = e.message; }
                            } else if (isOpenLuid && nts === 0) {
                                // [8] hAdapter
                                try { ev.hAdapter = this.pStruct.add(8).readU32(); } catch(e) {}
                            } else if (isEnum && nts === 0) {
                                // [0] NumAdapters, [4] Adapters[16] (each 20 bytes)
                                try {
                                    var count = this.pStruct.readU32();
                                    ev.numAdapters = count;
                                    ev.adapters = dumpAdapterArray(this.pStruct.add(4), count);
                                } catch(e) {}
                            } else if (isEnum2 && nts === 0) {
                                // [0] NumAdapters, [4] pAdapters pointer
                                try {
                                    var count2 = this.pStruct.readU32();
                                    ev.numAdapters = count2;
                                    var pArr = ptr(this.pStruct.add(4).readU32());
                                    ev.adapters = dumpAdapterArray(pArr, count2);
                                } catch(e) {}
                            } else if (this.fn === "D3DKMTCreateDevice" && nts === 0) {
                                try { ev.hDevice = this.pStruct.readU32(); } catch(e) {}
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
    if (hooked.length === 0) { send({error: "no D3DKMT functions found in process"}); }
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
}


def nts_str(nts):
    return NTSTATUS.get(nts, f"0x{nts:08X}")


def buf_diff(a_hex, b_hex):
    if not a_hex or not b_hex:
        return []
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    return [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x != y]


def find_polychrome():
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        if "polychrome" in proc.name.lower() or "asrpolychrome" in proc.name.lower():
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

    events  = []
    pending = {}

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
            combined = {**pending.pop(seq, {}), **p}
            combined.pop("phase", None)
            if combined.get("fn") in ("D3DKMTEscape", "NtGdiDdDDIEscape"):
                diffs = buf_diff(combined.get("bufIn"), combined.get("bufOut"))
                if diffs:
                    combined["bufDiff"] = [{"offset": o, "from": f"{a:02x}", "to": f"{b:02x}"} for o, a, b in diffs]
            events.append(combined)
            _print_event(combined)

    def _print_event(ev):
        fn  = ev.get("fn", "?")
        seq = ev.get("seq", "?")
        nts = ev.get("nts", None)
        nts_s = f" → {nts_str(nts)}" if nts is not None else ""
        h = ev.get("hAdapter", 0)
        extra = ""
        if fn in ("D3DKMTEscape", "NtGdiDdDDIEscape"):
            ds = ev.get("DataSize", 0)
            extra = f"  hAdapter=0x{h:08X}  DataSize={ds}"
            if ev.get("isI2C"): extra += "  *** I2C ***"
        elif fn in ("D3DKMTOpenAdapterFromGdiDisplayName", "D3DKMTOpenAdapterFromDeviceName"):
            extra = f"  devName={ev.get('devName','?')!r}"
            if nts == 0:
                extra += f"  hAdapter=0x{ev.get('hAdapter',0):08X}  LUID=0x{ev.get('luidLow',0):08X}"
        elif fn == "D3DKMTOpenAdapterFromLuid":
            extra = f"  LUID=0x{ev.get('luidLow',0):08X}"
            if nts == 0: extra += f"  hAdapter=0x{ev.get('hAdapter',0):08X}"
        elif fn in ("D3DKMTEnumAdapters", "D3DKMTEnumAdapters2"):
            extra = f"  numAdapters={ev.get('numAdapters','?')}"
            if "adapters" in ev:
                for a in ev["adapters"]:
                    extra += f"\n    hAdapter=0x{a['hAdapter']:08X}  LUID=0x{a['luidLow']:08X}"
        elif fn == "D3DKMTCloseAdapter":
            extra = f"  hAdapter=0x{h:08X}"
        print(f"  [{seq:>4}] {fn}{extra}{nts_s}")

    script.on("message", on_message)
    script.load()
    print("\nReady. Now:")
    print("  1. Let Polychrome fully load (UI visible).")
    print("  2. Change one color (e.g. to red).")
    print("  3. Press Enter here to stop and write logs.\n")
    input()
    session.detach()

    with open(json_path, "w") as f:
        json.dump(events, f, indent=2)
    print(f"\nJSON: {json_path}")

    _write_txt(txt_path, events)
    print(f"TXT:  {txt_path}")
    _analyze(events)


def _write_txt(path, events):
    with open(path, "w") as f:
        f.write(f"D3DKMT Trace — {datetime.now().isoformat()}\n" + "="*80 + "\n\n")
        for ev in events:
            fn  = ev.get("fn", "?")
            nts = ev.get("nts")
            nts_s = f"NTSTATUS={nts_str(nts)}" if nts is not None else ""
            f.write(f"[{ev.get('seq','?')}] {fn}  {nts_s}\n")
            for key in ("hAdapter","hDevice","Type","DataSize","hContext","devName","luidLow","luidHigh","numAdapters"):
                if key in ev:
                    v = ev[key]
                    if isinstance(v, int) and key not in ("Type","DataSize","numAdapters"):
                        f.write(f"  {key} = 0x{v:08X}\n")
                    else:
                        f.write(f"  {key} = {v}\n")
            if "adapters" in ev:
                f.write(f"  adapters ({len(ev['adapters'])}):\n")
                for a in ev["adapters"]:
                    f.write(f"    hAdapter=0x{a['hAdapter']:08X}  LUID=0x{a['luidLow']:08X}\n")
            if "bufIn" in ev and ev["bufIn"]:
                b = ev["bufIn"]
                f.write(f"  bufIn[0:32] = {b[:64]}\n")
            if "bufDiff" in ev:
                f.write(f"  bufDiff ({len(ev['bufDiff'])} bytes):\n")
                for d in ev["bufDiff"][:32]:
                    f.write(f"    offset {d['offset']:>5}: {d['from']} -> {d['to']}\n")
            f.write("\n")


def _analyze(events):
    print("\n" + "="*60 + "\nANALYSIS\n" + "="*60)
    print("\nAdapter open calls:")
    for ev in events:
        fn = ev.get("fn", "")
        if fn in ("D3DKMTOpenAdapterFromGdiDisplayName", "D3DKMTOpenAdapterFromDeviceName", "D3DKMTOpenAdapterFromLuid"):
            nts = ev.get("nts", -1)
            h   = ev.get("hAdapter", 0)
            ll  = ev.get("luidLow", 0)
            dev = ev.get("devName", "?")
            if fn == "D3DKMTOpenAdapterFromLuid":
                print(f"  [Luid] LUID=0x{ll:08X}  hAdapter=0x{h:08X}  {nts_str(nts)}")
            else:
                print(f"  [Open] {dev!r}  hAdapter=0x{h:08X}  {nts_str(nts)}")
    print("\nEnumAdapters results:")
    for ev in events:
        fn = ev.get("fn", "")
        if fn in ("D3DKMTEnumAdapters", "D3DKMTEnumAdapters2") and "adapters" in ev:
            print(f"  {fn}: {ev['numAdapters']} adapter(s)")
            for a in ev["adapters"]:
                print(f"    hAdapter=0x{a['hAdapter']:08X}  LUID=0x{a['luidLow']:08X}")
    i2c_events = [e for e in events if e.get("isI2C")]
    print(f"\nI2C escapes (LED writes): {len(i2c_events)}")
    for e in i2c_events[:5]:
        print(f"  seq={e.get('seq')} hAdapter=0x{e.get('hAdapter',0):08X} mod={e.get('mod','?')}")


if __name__ == "__main__":
    main()
