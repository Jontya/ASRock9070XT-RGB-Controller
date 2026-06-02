"""
Enumerate D3DKMT adapters from WITHIN the Polychrome process.
Polychrome is 32-bit WoW64 so it may see adapters our 64-bit process cannot.
Reports hAdapter + LUID for each adapter Polychrome can see.
"""
import frida, sys

# D3DKMTEnumAdapters struct layout (x86/32-bit):
#   UINT NumAdapters;                         (4 bytes)
#   D3DKMT_ADAPTERINFO Adapters[16];          (16 * 20 bytes = 320 bytes)
#
# D3DKMT_ADAPTERINFO (x86):
#   UINT hAdapter          (4)
#   LUID AdapterLuid       (8)  -- LowPart(4) + HighPart(4)
#   UINT NumOfSources      (4)
#   BOOL bPresentMove...   (4)
#   Total: 20 bytes
JS = """
(function() {
    var gdi32 = Process.findModuleByName("gdi32.dll")
             || Process.findModuleByName("GDI32.DLL");
    if (!gdi32) { send({error: "gdi32.dll not loaded"}); return; }

    var fn_enum = null;
    gdi32.enumerateExports().forEach(function(e) {
        if (e.name === "D3DKMTEnumAdapters" || e.name === "D3DKMTEnumAdapters2") {
            if (e.name === "D3DKMTEnumAdapters") fn_enum = e.address;
        }
    });
    if (!fn_enum) { send({error: "D3DKMTEnumAdapters not found in gdi32"}); return; }

    const D3DKMTEnumAdapters = new NativeFunction(fn_enum, 'int', ['pointer']);

    // Allocate struct: UINT NumAdapters + 16 * D3DKMT_ADAPTERINFO(20 bytes each) = 4 + 320 = 324 bytes
    const ADAPTER_INFO_SIZE = 20;
    const MAX_ADAPTERS = 16;
    const buf = Memory.alloc(4 + MAX_ADAPTERS * ADAPTER_INFO_SIZE);
    buf.writeU32(MAX_ADAPTERS);  // NumAdapters = max we can accept

    const ret = D3DKMTEnumAdapters(buf);
    if (ret !== 0) {
        send({error: "D3DKMTEnumAdapters failed: 0x" + (ret >>> 0).toString(16)});
        return;
    }

    const numAdapters = buf.readU32();
    var adapters = [];
    for (var i = 0; i < numAdapters; i++) {
        const base = buf.add(4 + i * ADAPTER_INFO_SIZE);
        const hAdapter    = base.readU32();
        const luidLow     = base.add(4).readU32();
        const luidHigh    = base.add(8).readU32();
        const numSources  = base.add(12).readU32();
        adapters.push({ idx: i, hAdapter: hAdapter, luidLow: luidLow, luidHigh: luidHigh, numSources: numSources });
    }
    send({adapters: adapters, count: numAdapters});
})();
"""


def find_polychrome():
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        if "polychrome" in proc.name.lower() or "asrpolychrome" in proc.name.lower():
            return proc
    return None


def on_message(message, _data):
    if message.get("type") == "send":
        p = message["payload"]
        if "error" in p:
            print(f"ERROR: {p['error']}")
        else:
            print(f"Polychrome sees {p['count']} adapters:")
            for a in p["adapters"]:
                print(f"  [{a['idx']}] hAdapter=0x{a['hAdapter']:08X}  "
                      f"LUID={a['luidLow']:#010x}:{a['luidHigh']:#010x}  "
                      f"sources={a['numSources']}")
    elif message.get("type") == "error":
        print(f"[frida error] {message['description']}")


def main():
    proc = find_polychrome()
    if proc is None:
        print("Polychrome not running.")
        sys.exit(1)

    print(f"Attaching to {proc.name} (pid {proc.pid}) …")
    device = frida.get_local_device()
    session = device.attach(proc.pid)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()

    import time
    time.sleep(2)
    session.detach()


if __name__ == "__main__":
    main()
