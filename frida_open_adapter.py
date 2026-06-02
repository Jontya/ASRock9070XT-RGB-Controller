"""
Hook D3DKMTOpenAdapterFromGdiDisplayName and D3DKMTOpenAdapterFromHdc in Polychrome.
Captures which display device Polychrome opens and what hAdapter + LUID it receives.
"""
import frida, sys, time

# D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME (x86):
#   WCHAR DeviceName[32]  = 64 bytes  (offset 0)
#   D3DKMT_HANDLE hAdapter = 4 bytes  (offset 64)
#   LUID AdapterLuid       = 8 bytes  (offset 68)  LowPart(4)+HighPart(4)
#   UINT VidPnSourceId     = 4 bytes  (offset 76)
JS = """
(function() {
    const TARGET_HOOKS = [
        "D3DKMTOpenAdapterFromGdiDisplayName",
        "D3DKMTOpenAdapterFromHdc",
        "D3DKMTOpenAdapterFromDeviceName",
        "D3DKMTOpenAdapterFromLuid",
    ];

    let hooked = 0;
    Process.enumerateModules().forEach(function(m) {
        try {
            m.enumerateExports().forEach(function(e) {
                if (TARGET_HOOKS.indexOf(e.name) === -1) return;
                try {
                    var savedPtr = null;
                    Interceptor.attach(e.address, {
                        onEnter: function(args) {
                            this.pData = args[0];
                            this.fnName = e.name;
                            if (e.name === "D3DKMTOpenAdapterFromGdiDisplayName") {
                                // DeviceName is WCHAR[32] at offset 0
                                try {
                                    var name = this.pData.readUtf16String(32);
                                    this.devName = name;
                                } catch(ex) { this.devName = "?"; }
                            }
                        },
                        onLeave: function(retval) {
                            var nts = retval.toInt32() >>> 0;
                            if (e.name === "D3DKMTOpenAdapterFromGdiDisplayName") {
                                var hAdapter  = this.pData.add(64).readU32();
                                var luidLow   = this.pData.add(68).readU32();
                                var luidHigh  = this.pData.add(72).readU32();
                                var sourceId  = this.pData.add(76).readU32();
                                send({fn: e.name, nts: nts,
                                      devName: this.devName,
                                      hAdapter: hAdapter,
                                      luidLow: luidLow, luidHigh: luidHigh,
                                      vidPnSourceId: sourceId});
                            } else {
                                var hAdapter = this.pData.readU32();
                                send({fn: e.name, nts: nts, hAdapter: hAdapter});
                            }
                        }
                    });
                    console.log("[+] Hooked " + m.name + "!" + e.name);
                    hooked++;
                } catch(ex) {
                    console.log("[!] " + e.name + " attach failed: " + ex.message);
                }
            });
        } catch(ex) {}
    });
    console.log("[*] " + hooked + " hooks placed. Now trigger a color change in Polychrome.");
    if (hooked === 0) {
        send({error: "No adapter-open functions found in any module"});
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
        if "error" in p:
            print(f"ERROR: {p['error']}")
        else:
            fn  = p.get("fn", "?")
            nts = p.get("nts", 0)
            h   = p.get("hAdapter", 0)
            if fn == "D3DKMTOpenAdapterFromGdiDisplayName":
                ll  = p.get("luidLow", 0)
                lh  = p.get("luidHigh", 0)
                dev = p.get("devName", "?")
                sid = p.get("vidPnSourceId", 0)
                print(f"\n[{fn}]")
                print(f"  DeviceName   : {dev!r}")
                print(f"  hAdapter     : 0x{h:08X}")
                print(f"  LUID         : {ll:#010x}:{lh:#010x}")
                print(f"  VidPnSourceId: {sid}")
                print(f"  NTSTATUS     : 0x{nts:08X}")
            else:
                print(f"\n[{fn}]  hAdapter=0x{h:08X}  NTSTATUS=0x{nts:08X}")
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

    print("Now CLOSE and REOPEN Polychrome so adapter-open calls fire, or change color.")
    print("Press Enter to stop.\n")
    input()
    session.detach()


if __name__ == "__main__":
    main()
