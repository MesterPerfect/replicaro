//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <UserNotifications/UserNotifications.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdlib.h>
#import "native_darwin.h"

extern void replicaroOpenRequested(void);
extern void replicaroTerminateRequested(void);
extern int replicaroConfirmQuit(void);
extern char *replicaroTrayLabel(int quit);

static atomic_int replicaroNotificationStatus = UNAuthorizationStatusNotDetermined;

// Set on the main thread once AppKit has asked to terminate and been told
// NSTerminateLater. From then on the reply from ReplicaroReplyToTerminate
// ends the app, and ReplicaroStopApp leaves the run loop alone.
static atomic_bool replicaroTerminating = false;

// Set while the Quit alert is open. Only the main thread uses it.
static BOOL replicaroQuitAlertOpen = NO;

static atomic_bool replicaroStopRequested = false;
static void replicaroStopRunLoop(void);

// replicaroLabel turns a label from Go (malloc'd, or NULL) into an NSString
// and frees it, falling back to the English label.
static NSString *replicaroLabel(int quit) {
    char *value = replicaroTrayLabel(quit);
    NSString *label = value != NULL ? [NSString stringWithUTF8String:value] : nil;
    free(value);
    if (label == nil || label.length == 0) {
        label = quit ? @"Quit Replicaro" : @"Open Replicaro";
    }
    return label;
}

@interface ReplicaroAppDelegate : NSObject <NSApplicationDelegate, UNUserNotificationCenterDelegate>
@property(nonatomic, strong) NSStatusItem *statusItem;
@end

@implementation ReplicaroAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    // ReplicaroRunApp also queues a call to this (see there), so it normally
    // runs twice. The second call must not add a second menu bar item or open
    // the web UI again. Both calls run on the main thread, so this check is
    // enough.
    if (self.statusItem != nil) {
        return;
    }
    // A quit or logout can be handled before the queued call runs. Don't add
    // a menu bar item or open the web UI for a process that is shutting down.
    if (atomic_load(&replicaroTerminating)) {
        return;
    }
    NSStatusItem *item = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
    self.statusItem = item;

    NSImage *image = nil;
    NSString *path = [[NSBundle mainBundle] pathForResource:@"replicaro-favicon" ofType:@"png"];
    if (path != nil) {
        image = [[NSImage alloc] initWithContentsOfFile:path];
        image.size = NSMakeSize(18.0, 18.0);
    }
    if (image != nil) {
        item.button.image = image;
        item.button.imagePosition = NSImageOnly;
    } else {
        item.button.title = @"R";
    }
    item.button.toolTip = @"Replicaro";

    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Replicaro"];
    // The labels are read once, here, so a language change shows in them
    // after the next start.
    NSMenuItem *open = [[NSMenuItem alloc] initWithTitle:replicaroLabel(0)
                                                   action:@selector(openReplicaro:)
                                            keyEquivalent:@""];
    open.target = self;
    [menu addItem:open];
    [menu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *quit = [[NSMenuItem alloc] initWithTitle:replicaroLabel(1)
                                                   action:@selector(quitReplicaro:)
                                            keyEquivalent:@"q"];
    quit.target = self;
    [menu addItem:quit];
    item.menu = menu;

    if (getenv("REPLICARO_DESKTOP_TEST") == NULL) {
        UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
        center.delegate = self;
        [center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
            atomic_store(&replicaroNotificationStatus, (int)settings.authorizationStatus);
        }];
        replicaroOpenRequested();
    }
}

- (void)openReplicaro:(id)sender {
    (void)sender;
    replicaroOpenRequested();
}

- (void)quitReplicaro:(id)sender {
    // The menu bar item is the same process as the service, so Quit stops
    // every scheduled and running backup until Replicaro is started again,
    // and users can read it as "hide the icon". So this menu item (and its
    // Command-Q) asks first. Logging out, restarting and shutting down don't
    // come through here and never ask; they go straight to
    // applicationShouldTerminate:. A second Quit while the alert is open does
    // nothing, and once a terminate is under way there is nothing to ask.
    if (replicaroQuitAlertOpen) {
        return;
    }
    if (!atomic_load(&replicaroTerminating)) {
        replicaroQuitAlertOpen = YES;
        int confirmed = replicaroConfirmQuit();
        replicaroQuitAlertOpen = NO;
        // The service can stop on its own while the alert is open. The main
        // queue keeps draining during the alert, so ReplicaroStopApp's -stop:
        // then ended the alert's modal loop instead of the app's; stop the
        // app's loop again so Run returns.
        if (atomic_load(&replicaroStopRequested) && !atomic_load(&replicaroTerminating)) {
            replicaroStopRunLoop();
            return;
        }
        if (!confirmed) {
            return;
        }
    }
    // Quit takes AppKit's terminate path, the same one logging out,
    // restarting and shutting down take, so all of them shut down the same
    // way; see applicationShouldTerminate:.
    [NSApp terminate:sender];
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
    (void)sender;
    // NSTerminateCancel here would tell macOS that Replicaro refused to quit,
    // which cancels a logout, restart or shutdown. NSTerminateLater lets it
    // wait instead: AppKit keeps running the main run loop (in
    // NSModalPanelRunLoopMode) until replyToApplicationShouldTerminate:,
    // which ReplicaroReplyToTerminate sends once the staged shutdown has
    // finished, and then exits the process.
    //
    // replicaroTerminateRequested only starts the shutdown on a Go goroutine
    // and returns, so the main thread isn't blocked while it runs. A second
    // request while it runs, such as Quit chosen during a logout, starts
    // nothing new; the one reply answers it.
    if (!atomic_exchange(&replicaroTerminating, true)) {
        replicaroTerminateRequested();
    }
    return NSTerminateLater;
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    (void)sender;
    return NO;
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
 didReceiveNotificationResponse:(UNNotificationResponse *)response
          withCompletionHandler:(void (^)(void))completionHandler {
    (void)center;
    NSString *target = response.notification.request.content.userInfo[@"target"];
    if ([target isKindOfClass:[NSString class]]) {
        NSURL *url = [NSURL URLWithString:target];
        if (url != nil) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[NSWorkspace sharedWorkspace] openURL:url];
            });
        }
    }
    completionHandler();
}

@end

static ReplicaroAppDelegate *replicaroDelegate;

static void replicaroStopRunLoop(void) {
    [NSApp stop:nil];
    NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                       location:NSZeroPoint
                                  modifierFlags:0
                                      timestamp:0
                                   windowNumber:0
                                        context:nil
                                        subtype:0
                                          data1:0
                                          data2:0];
    [NSApp postEvent:wake atStart:NO];
}

void ReplicaroRunApp(void) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        // Start at login is a LaunchAgent, so launchd alone decides whether
        // Replicaro starts at login. Replicaro lets a logout go ahead, and
        // without this "Reopen windows when logging back in" would relaunch it
        // at the next login as well: a second start on top of the LaunchAgent
        // one, or a start at login with Start at login turned off.
        [app disableRelaunchOnLogin];
        replicaroDelegate = [[ReplicaroAppDelegate alloc] init];
        app.delegate = replicaroDelegate;
        if (atomic_load(&replicaroStopRequested)) {
            return;
        }
        // The startup repair question runs a modal alert before this point,
        // and AppKit can finish launching the app while that alert is up,
        // before this delegate exists. -run then doesn't announce the launch
        // again, and without that the menu bar item would be missing and the
        // web UI wouldn't open. So the launch handler is also queued on the
        // main queue, which -run drains once its loop starts. Whichever call
        // comes first sets things up and the other one returns early, so this
        // doesn't depend on whether AppKit already counts the launch as done.
        dispatch_async(dispatch_get_main_queue(), ^{
            [replicaroDelegate applicationDidFinishLaunching:nil];
        });
        [app run];
    }
}

void ReplicaroStopApp(void) {
    atomic_store(&replicaroStopRequested, true);
    dispatch_async(dispatch_get_main_queue(), ^{
        // The staged shutdown of a terminate request stops the HTTP server,
        // which ends the service and calls this. By then AppKit is waiting
        // for the terminate reply, and the reply ends the app. AppKit doesn't
        // say what -stop: does inside that wait, and stopping isn't needed,
        // so it's skipped. The flag is only set on the main thread, which is
        // where this block runs, so the check can't race with it.
        if (atomic_load(&replicaroTerminating)) {
            return;
        }
        replicaroStopRunLoop();
    });
}

void ReplicaroReplyToTerminate(void) {
    // The main queue is drained in the run loop's common modes, which
    // include the modal panel mode AppKit waits in after NSTerminateLater.
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp replyToApplicationShouldTerminate:YES];
    });
}

int ReplicaroIsMainThread(void) {
    return pthread_main_np() != 0;
}

int ReplicaroOpenURL(const char *target) {
    if (target == NULL) {
        return 0;
    }
    NSString *value = [NSString stringWithUTF8String:target];
    NSURL *url = [NSURL URLWithString:value];
    if (url == nil) {
        return 0;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSWorkspace sharedWorkspace] openURL:url];
    });
    return 1;
}

int ReplicaroNotificationCapability(void) {
    return atomic_load(&replicaroNotificationStatus) != UNAuthorizationStatusDenied;
}

int ReplicaroShowNotification(const char *title, const char *message, const char *target, const char *iconPath) {
    if (getenv("REPLICARO_DESKTOP_TEST") != NULL) {
        return 0;
    }
    if (title == NULL || message == NULL || target == NULL) {
        return 0;
    }
    if (!ReplicaroNotificationCapability()) {
        return 0;
    }
    NSString *notificationTitle = [NSString stringWithUTF8String:title];
    NSString *notificationMessage = [NSString stringWithUTF8String:message];
    NSString *notificationTarget = [NSString stringWithUTF8String:target];
    NSString *notificationIcon = iconPath ? [NSString stringWithUTF8String:iconPath] : nil;
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound)
                          completionHandler:^(BOOL granted, NSError *error) {
        if (!granted || error != nil) {
            atomic_store(&replicaroNotificationStatus, UNAuthorizationStatusDenied);
            if (error != nil) {
                NSLog(@"Replicaro notification authorization failed: %@", error);
            } else {
                NSLog(@"Replicaro notification authorization was denied");
            }
            return;
        }
        atomic_store(&replicaroNotificationStatus, UNAuthorizationStatusAuthorized);
        UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
        content.title = notificationTitle;
        content.body = notificationMessage;
        content.userInfo = @{@"target": notificationTarget};
        // macOS owns the header's application icon. A supported image attachment
        // provides outcome artwork in the content when the user's presentation
        // permits it. The notification service takes ownership of its file.
        NSString *temporaryIcon = [NSTemporaryDirectory() stringByAppendingPathComponent:
            [[[NSUUID UUID] UUIDString] stringByAppendingPathExtension:@"png"]];
        if (notificationIcon && [[NSFileManager defaultManager] copyItemAtPath:notificationIcon toPath:temporaryIcon error:nil]) {
            UNNotificationAttachment *attachment = [UNNotificationAttachment attachmentWithIdentifier:@"replicaro-outcome"
                URL:[NSURL fileURLWithPath:temporaryIcon] options:nil error:nil];
            if (attachment) content.attachments = @[attachment];
        }
        UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:[[NSUUID UUID] UUIDString]
                                                                                  content:content
                                                                                  trigger:nil];
        [center addNotificationRequest:request withCompletionHandler:^(NSError *requestError) {
            // Validation/transfer happens when the request is scheduled, not
            // when the attachment object is created. Retain the file until this
            // callback, then remove any residue after success or failure.
            [[NSFileManager defaultManager] removeItemAtPath:temporaryIcon error:nil];
            if (requestError != nil) {
                NSLog(@"Replicaro notification delivery failed: %@", requestError);
            }
        }];
    }];
    return 1;
}

// replicaroPrepareStartupAlert brings the app forward for an alert shown
// before desktop.Run. The app runs as an accessory (LSUIElement), so it has
// no Dock icon and isn't active on launch; without this the alert would open
// behind other windows.
static void replicaroPrepareStartupAlert(void) {
    NSApplication *app = [NSApplication sharedApplication];
    [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [app activateIgnoringOtherApps:YES];
    // macOS 14 deprecates activateIgnoringOtherApps: and can ignore it;
    // activate replaces it there. It goes through performSelector so the
    // file still builds with SDKs that don't declare it.
    if ([app respondsToSelector:@selector(activate)]) {
        [app performSelector:@selector(activate)];
    }
}

void ReplicaroShowStartupFailure(const char *message) {
    if (getenv("REPLICARO_DESKTOP_TEST") != NULL || message == NULL) {
        return;
    }
    @autoreleasepool {
        NSString *text = [NSString stringWithUTF8String:message];
        if (text == nil) {
            text = @"Replicaro couldn't start.";
        }
        replicaroPrepareStartupAlert();
        NSAlert *alert = [[NSAlert alloc] init];
        alert.alertStyle = NSAlertStyleCritical;
        alert.messageText = @"Replicaro";
        alert.informativeText = text;
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
    }
}

int ReplicaroConfirmStartupRepair(const char *message, const char *repairTitle, const char *declineTitle) {
    if (getenv("REPLICARO_DESKTOP_TEST") != NULL || message == NULL || repairTitle == NULL || declineTitle == NULL) {
        return -1;
    }
    @autoreleasepool {
        NSString *text = [NSString stringWithUTF8String:message];
        NSString *repair = [NSString stringWithUTF8String:repairTitle];
        NSString *decline = [NSString stringWithUTF8String:declineTitle];
        if (text == nil || repair == nil || decline == nil) {
            return -1;
        }
        replicaroPrepareStartupAlert();
        NSAlert *alert = [[NSAlert alloc] init];
        alert.alertStyle = NSAlertStyleWarning;
        alert.messageText = @"Replicaro";
        alert.informativeText = text;
        // The first button is the default (Return); Escape picks the second.
        [alert addButtonWithTitle:repair];
        NSButton *declineButton = [alert addButtonWithTitle:decline];
        declineButton.keyEquivalent = @"\033";
        return [alert runModal] == NSAlertFirstButtonReturn ? 1 : 0;
    }
}

int ReplicaroConfirmQuit(const char *message, const char *quitTitle, const char *cancelTitle) {
    // Desktop tests have no one to answer the alert, so Quit goes ahead
    // without asking.
    if (getenv("REPLICARO_DESKTOP_TEST") != NULL) {
        return 1;
    }
    if (message == NULL || quitTitle == NULL || cancelTitle == NULL) {
        return 1;
    }
    @autoreleasepool {
        NSString *text = [NSString stringWithUTF8String:message];
        NSString *quit = [NSString stringWithUTF8String:quitTitle];
        NSString *cancel = [NSString stringWithUTF8String:cancelTitle];
        if (text == nil || quit == nil || cancel == nil) {
            return 1;
        }
        // An accessory app isn't active when its menu bar item is used from
        // another app's window; without this the alert opens behind it.
        replicaroPrepareStartupAlert();
        NSAlert *alert = [[NSAlert alloc] init];
        alert.alertStyle = NSAlertStyleWarning;
        alert.messageText = @"Replicaro";
        alert.informativeText = text;
        // The first button is the default (Return); Escape picks the second.
        [alert addButtonWithTitle:quit];
        NSButton *cancelButton = [alert addButtonWithTitle:cancel];
        cancelButton.keyEquivalent = @"\033";
        return [alert runModal] == NSAlertFirstButtonReturn ? 1 : 0;
    }
}
