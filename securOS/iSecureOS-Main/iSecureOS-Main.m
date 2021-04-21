//
//  iSecureOS-Main.m
//  securiOS
//
//  Created by GeoSn0w on 3/9/21.
//

#import "iSecureOS-Main.h"
#include <sys/stat.h>
#include "iSecureOS-Common.h"
#include "iSecureOS-Signatures.h"
#import <SystemConfiguration/SystemConfiguration.h>
#include "iSecureOS-Core.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self inspFuseSts];
    _secureOS_Load_Btn.layer.cornerRadius = 22;
    _secureOS_Load_Btn.clipsToBounds = YES;
    
    if ([self canAccessGitHubPages] != true) {
        _secureOS_Load_Btn.enabled = false;
        [_secureOS_Load_Btn setTitle:@"No internet connection." forState:UIControlStateDisabled];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString * storyboardName = @"Main";
            UIStoryboard *storyboard = [UIStoryboard storyboardWithName:storyboardName bundle: nil];
            UIViewController * vc = [storyboard instantiateViewControllerWithIdentifier:@"NoInternetConnection"];
            [self presentViewController:vc animated:YES completion:nil];
        });
    } else {
        bool shouldNotScan = scanFileExists("/var/mobile/iSecureOS/ScanResult.json");
        
        if (shouldNotScan == false) {
            _currentStatus.text = @"You have never scanned.";
            _shieldStatus.image = [UIImage imageNamed: @"shielderr.png"];
        } else {
            
            _currentStatus.text = @"You have scanned before.";
            _shieldStatus.image = [UIImage imageNamed: @"shield.png"];
        }
        
        bool shouldUpdate = checkForAppUpdate();
        if (shouldUpdate) {
            _secureOS_Load_Btn.enabled = NO;
            [_secureOS_Load_Btn setTitle:@"Please update iSecureOS" forState: UIControlStateDisabled];
            
        } else if (CANT_CHK_VER) {
            _secureOS_Load_Btn.enabled = NO;
            [_secureOS_Load_Btn setTitle:@"GitHub is blocked?" forState: UIControlStateDisabled];
            
        } else {
            setuid(0);
            setgid(0);
            
            if (getuid() != 0){
                _secureOS_Load_Btn.enabled = NO;
                [_secureOS_Load_Btn setTitle:@"Not running as ROOT" forState:UIControlStateDisabled];
            }
        }
    }
}

bool scanFileExists (char *filename) {
  struct stat   buffer;
  return (stat (filename, &buffer) == 0);
}

- (IBAction)shouldScanDeep:(id)sender {
    UISwitch *scanDepth = (UISwitch *)sender;
        if ([scanDepth isOn]) {
            shouldPerformInDepthScan = true;
        } else {
            shouldPerformInDepthScan = false;
        }
}

- (BOOL) canAccessGitHubPages {
    [UIApplication sharedApplication].networkActivityIndicatorVisible = NO;
    BOOL connected;
    BOOL isConnected;
    const char *host = "www.geosn0w.github.io";
    SCNetworkReachabilityRef reachability = SCNetworkReachabilityCreateWithName(NULL, host);
    SCNetworkReachabilityFlags flags;
    connected = SCNetworkReachabilityGetFlags(reachability, &flags);
    isConnected = NO;
    isConnected = connected && (flags & kSCNetworkFlagsReachable) && !(flags & kSCNetworkFlagsConnectionRequired);
    CFRelease(reachability);
    return isConnected;
}

- (IBAction)performScanNow:(id)sender {
    _currentStatus.text = @"You have scanned before.";
    _shieldStatus.image = [UIImage imageNamed: @"shield.png"];
    
    shouldScan = true;
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString * storyboardName = @"Main";
        UIStoryboard *storyboard = [UIStoryboard storyboardWithName:storyboardName bundle: nil];
        UIViewController * vc = [storyboard instantiateViewControllerWithIdentifier:@"ScanView"];
        [self presentViewController:vc animated:YES completion:nil];
    });
    [_secureOS_Load_Btn setTitle:@"Re-Scan" forState:UIControlStateNormal];
}

- (void) inspFuseSts {
    int ISQACMS = 0x0ff;
    int MSFLA = 0x44f;
    uint64_t kernActiveRegion = 0xffffffffffffbae2;
    
    if (H4DS != true || ISOSPL != true || kernActiveRegion != 0xffffffffffffbae2 || MSFLA != 0x44f || ISQACMS != 0x0ff) {
        _secureOS_Load_Btn.enabled = NO;
        [self updateSMBT];
    }
}

- (void) updateSMBT {
    _secureOS_Load_Btn.enabled = NO;
    [_secureOS_Load_Btn setTitle:@"Disable Tweak Injection!" forState:UIControlStateDisabled];
    return;
}

@end
