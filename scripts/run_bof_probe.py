#!/usr/bin/env python3
"""Launch iogpu_residency_bof PoC and collect syslog output."""
import sys, asyncio, logging
sys.path.insert(0, r'C:\Users\User\AppData\Roaming\Python\Python311\site-packages')
logging.basicConfig(level=logging.WARNING)

UDID     = '00008150-0019381E1A23401C'
BUNDLE   = 'com.nexus.fengshui3.TMAQ26273N.TMAQ26273N'
RSD_ADDR = 'fdfc:38cc:a28c::1'
RSD_PORT = 50415
COLLECT_SECS = 90

messages = []
syslog_ready = asyncio.Event()

async def collect_syslog(lockdown):
    from pymobiledevice3.services.os_trace import OsTraceService
    svc = OsTraceService(lockdown=lockdown)
    count = 0
    print('[syslog] starting collection via USB lockdown...', flush=True)
    async for msg in svc.syslog(pid=-1):
        text = msg.message if hasattr(msg, 'message') else str(msg)
        if text and '[BOF]' in str(text):
            print(f'[BOF LOG] {text}', flush=True)
            messages.append(str(text))
        count += 1
        if count == 3 and not syslog_ready.is_set():
            syslog_ready.set()
            print('[syslog] ready', flush=True)

async def main():
    import subprocess, threading
    from pymobiledevice3.lockdown import create_using_usbmux

    print('[*] USB lockdown...', flush=True)
    lockdown = await asyncio.wait_for(create_using_usbmux(serial=UDID), timeout=20)
    print(f'[+] Lockdown: {lockdown.product_version}', flush=True)

    syslog_task = asyncio.create_task(collect_syslog(lockdown))

    print('[*] Waiting for syslog ready (max 15s)...', flush=True)
    try:
        await asyncio.wait_for(syslog_ready.wait(), timeout=15)
    except asyncio.TimeoutError:
        print('[!] syslog not ready — proceeding anyway', flush=True)

    # Use CLI dvt launch (avoids suspended-launch API issue with some pymobiledevice3 versions)
    print(f'[*] Launching {BUNDLE} via CLI dvt launch...', flush=True)
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: subprocess.run(
            [sys.executable, '-m', 'pymobiledevice3', 'developer', 'dvt', 'launch', BUNDLE],
            capture_output=True, text=True, timeout=30
        )
    )
    # Extract pid from output
    import re as _re
    combined = result.stdout + result.stderr
    print(f'[DBG] dvt stdout: {result.stdout[-200:]!r}', flush=True)
    print(f'[DBG] dvt stderr: {result.stderr[-200:]!r}', flush=True)
    m = _re.search(r'[Pp]rocess launched with pid[= ]+(\d+)', combined)
    if not m:
        m = _re.search(r'\bpid[= ]+(\d+)', combined, _re.IGNORECASE)
    pid = int(m.group(1)) if m else None
    print(f'[+] LAUNCHED pid={pid}', flush=True)

    print(f'[*] Collecting for {COLLECT_SECS}s...', flush=True)
    await asyncio.sleep(COLLECT_SECS)
    syslog_task.cancel()
    try:
        await syslog_task
    except asyncio.CancelledError:
        pass

    print(f'\n=== {len(messages)} [BOF] messages collected ===', flush=True)
    for m in messages:
        print(m, flush=True)

asyncio.run(main())
