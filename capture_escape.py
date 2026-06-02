"""
Hook D3DKMTEscape in the running Polychrome process and dump
the pPrivateDriverData buffer on every call.

Usage (admin cmd, Polychrome must be running):
    pip install frida-tools
    python capture_escape.py
"""

import frida
import sys

# Handles both 32-bit and 64-bit Polychrome process.
# D3DKMT_ESCAPE layout differs by pointer size.
JS = """
(function() {
    const is64 = Process.pointerSize === 8;
    // D3DKMT_ESCAPE layout:
    //   x86: hAdapter(4) hDevice(4) Type(4) Flags(4) pData(4) Size(4) hContext(4)
    //   x64: hAdapter(4) hDevice(4) Type(4) Flags(4) [pad4] pData(8) Size(4) hContext(4)
    const OFF_HADAPTER = 0x00;
    const OFF_HDEVICE  = 0x04;
    const OFF_TYPE     = 0x08;
    const OFF_FLAGS    = 0x0C;
    const OFF_PDATA    = is64 ? 0x10 : 0x10;  // pointer after 4 uint32s; x64 has padding
    const OFF_SIZE     = is64 ? 0x18 : 0x14;
    const OFF_HCTX     = is64 ? 0x1C : 0x18;

    const HOOK_NAMES = ["D3DKMTEscape", "NtGdiDdDDIEscape"];
    let hooked = 0;

    Process.enumerateModules().forEach(function(m) {
        try {
            m.enumerateExports().forEach(function(e) {
                if (HOOK_NAMES.indexOf(e.name) === -1) return;
                try {
                    Interceptor.attach(e.address, {
                        onEnter: function(args) {
                            try {
                                const pEscape  = args[0];
                                const hAdapter = pEscape.add(OFF_HADAPTER).readU32();
                                const hDevice  = pEscape.add(OFF_HDEVICE).readU32();
                                const type     = pEscape.add(OFF_TYPE).readU32();
                                const flags    = pEscape.add(OFF_FLAGS).readU32();
                                const pData    = pEscape.add(OFF_PDATA).readPointer();
                                const size     = pEscape.add(OFF_SIZE).readU32();
                                const hCtx     = pEscape.add(OFF_HCTX).readU32();
                                if (size === 0 || size > 4096) return;
                                const raw = pData.readByteArray(size);
                                const hex = Array.from(new Uint8Array(raw))
                                    .map(function(b){ return b.toString(16).padStart(2,"0"); })
                                    .join(" ");
                                send({ fn: m.name + "!" + e.name,
                                       hAdapter: hAdapter, hDevice: hDevice,
                                       type: type, flags: flags,
                                       size: size, hContext: hCtx, data: hex });
                            } catch(ex) {}
                        }
                    });
                    console.log("[+] Hooked " + m.name + "!" + e.name + " @ " + e.address);
                    hooked++;
                } catch(ex) {
                    console.log("[!] Attach failed: " + m.name + "!" + e.name + " — " + ex.message);
                }
            });
        } catch(ex) {}
    });

    if (hooked === 0) {
        console.log("[!] No hooks placed");
    }
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
        print(f"\n{'='*60}")
        print(f"Function : {p['fn']}")
        print(f"hAdapter : 0x{p['hAdapter']:08X}")
        print(f"hDevice  : 0x{p['hDevice']:08X}")
        print(f"hContext : 0x{p['hContext']:08X}")
        print(f"EscType  : 0x{p['type']:08X}")
        print(f"Flags    : {p['flags']}")
        print(f"DataSize : {p['size']} bytes")
        print(f"Data     : {p['data']}")
    elif message.get("type") == "error":
        print(f"[frida error] {message['description']}")
        print(f"             {message.get('stack','')}")


def main():
    proc = find_polychrome()
    if proc is None:
        print("Polychrome process not found — start it first then re-run.")
        sys.exit(1)

    print(f"Attaching to {proc.name} (pid {proc.pid}) …")
    device = frida.get_local_device()
    session = device.attach(proc.pid)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()

    print("Hooks active. Change LED color in Polychrome, then press Enter to stop.\n")
    input()


if __name__ == "__main__":
    main()
