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
    // First: find which module actually exports D3DKMTEscape
    const allMods = Process.enumerateModules();
    allMods.forEach(function(m) {
        try {
            const exports = m.enumerateExports();
            exports.forEach(function(e) {
                if (e.name.indexOf("D3DKMT") !== -1 || e.name.indexOf("DdDDI") !== -1) {
                    console.log("[scan] " + m.name + "!" + e.name + " @ " + e.address);
                }
            });
        } catch(e) {}
    });

    const is64 = Process.pointerSize === 8;

    // D3DKMT_ESCAPE offsets
    // x64: hAdapter(8) hDevice(8) Type(4) Flags(4) pData(8) Size(4)
    // x86: hAdapter(4) hDevice(4) Type(4) Flags(4) pData(4) Size(4)
    const OFF_TYPE  = is64 ? 0x10 : 0x08;
    const OFF_FLAGS = is64 ? 0x14 : 0x0C;
    const OFF_PDATA = is64 ? 0x18 : 0x10;
    const OFF_SIZE  = is64 ? 0x20 : 0x14;

    const targets = [
        ["gdi32.dll",     "D3DKMTEscape"],
        ["gdi32full.dll", "D3DKMTEscape"],
        ["win32u.dll",    "NtGdiDdDDIEscape"],
    ];

    let hooked = 0;
    targets.forEach(function(t) {
        const mod = t[0], fn = t[1];
        let addr = null;
        try { addr = Module.findExportByName(mod, fn); } catch(e) {}
        if (!addr) {
            console.log("[-] Not found: " + mod + "!" + fn);
            return;
        }
        try {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    try {
                        const pEscape = args[0];
                        const type  = pEscape.add(OFF_TYPE).readU32();
                        const flags = pEscape.add(OFF_FLAGS).readU32();
                        const pData = pEscape.add(OFF_PDATA).readPointer();
                        const size  = pEscape.add(OFF_SIZE).readU32();
                        if (size === 0 || size > 4096) return;
                        const raw = pData.readByteArray(size);
                        const hex = Array.from(new Uint8Array(raw))
                            .map(function(b){ return b.toString(16).padStart(2,"0"); })
                            .join(" ");
                        send({ fn: fn, type: type, flags: flags, size: size, data: hex });
                    } catch(e) {
                        console.log("[!] onEnter error: " + e.message);
                    }
                }
            });
            console.log("[+] Hooked " + mod + "!" + fn + " @ " + addr + " (arch=" + (is64?"x64":"x86") + ")");
            hooked++;
        } catch(e) {
            console.log("[!] Attach failed for " + fn + ": " + e.message);
        }
    });
    if (hooked === 0) {
        console.log("[!] No hooks placed — D3DKMTEscape not found in any target DLL");
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
