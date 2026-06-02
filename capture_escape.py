"""
Hook D3DKMTEscape in the running Polychrome process and dump
the pPrivateDriverData buffer on every call.

Usage (admin cmd, Polychrome must be running):
    pip install frida-tools
    python capture_escape.py
"""

import frida
import sys

JS = """
// D3DKMTEscape lives in gdi32.dll; the actual kernel thunk is in win32u.dll
// Hook both to be sure.
const targets = [
    { mod: "gdi32.dll",    fn: "D3DKMTEscape"      },
    { mod: "gdi32full.dll",fn: "D3DKMTEscape"      },
    { mod: "win32u.dll",   fn: "NtGdiDdDDIEscape"  },
];

targets.forEach(({ mod, fn }) => {
    const addr = Module.findExportByName(mod, fn);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter(args) {
            // D3DKMT_ESCAPE struct pointer is args[0]
            // Layout (x64):
            //   +0x00  UINT64  hAdapter
            //   +0x08  UINT64  hDevice
            //   +0x10  UINT32  Type
            //   +0x14  UINT32  Flags
            //   +0x18  UINT64  pPrivateDriverData   <- pointer to payload
            //   +0x20  UINT32  PrivateDriverDataSize
            //   +0x24  UINT64  hContext (optional)
            const pEscape = args[0];
            try {
                const type = pEscape.add(0x10).readU32();
                const flags = pEscape.add(0x14).readU32();
                const pData = pEscape.add(0x18).readPointer();
                const size  = pEscape.add(0x20).readU32();

                if (size === 0 || size > 4096) return; // skip noise

                const bytes = Array.from(pData.readByteArray(size))
                    .map(b => b.toString(16).padStart(2, "0"))
                    .join(" ");

                send({
                    fn: fn,
                    type: type,
                    flags: flags,
                    size: size,
                    data: bytes,
                });
            } catch(e) {
                // ignore unreadable memory
            }
        }
    });
    console.log("[+] Hooked " + mod + "!" + fn + " @ " + addr);
});
"""


def find_polychrome():
    for proc in frida.enumerate_processes():
        if "polychrome" in proc.name.lower() or "asrpolychrome" in proc.name.lower():
            return proc
    return None


def on_message(message, _data):
    if message.get("type") == "send":
        p = message["payload"]
        print(f"\n{'='*60}")
        print(f"Function : {p['fn']}")
        print(f"EscType  : {p['type']} (0x{p['type']:08X})")
        print(f"Flags    : {p['flags']}")
        print(f"DataSize : {p['size']} bytes")
        print(f"Data     : {p['data']}")
    elif message.get("type") == "error":
        print(f"[frida error] {message['description']}")


def main():
    proc = find_polychrome()
    if proc is None:
        print("Polychrome process not found — start it first then re-run.")
        sys.exit(1)

    print(f"Attaching to {proc.name} (pid {proc.pid}) …")
    session = frida.attach(proc.pid)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()

    print("Hooks active. Change LED color in Polychrome now.")
    print("Press Ctrl+C to stop.\n")
    sys.stdin.read()


if __name__ == "__main__":
    main()
