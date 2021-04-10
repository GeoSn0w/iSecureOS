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

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    if ([self canAccessGitHubPages] != true) {
        _secureOS_Load_Btn.enabled = false;
        [_secureOS_Load_Btn setTitle:@"No connection." forState:UIControlStateDisabled];
    } else {
        if (@available(iOS 13.0, *)) {
                self.overrideUserInterfaceStyle = UIUserInterfaceStyleLight;
        }
        bool shouldNotScan = scanFileExists("/var/mobile/iSecureOS/ScanResult.json");
        
        if (shouldNotScan == false) {
            _currentStatus.text = @"You have never scanned.";
            _shieldStatus.image = [UIImage imageNamed: @"shielderr.png"];
        } else {
            
            _currentStatus.text = @"You have scanned before.";
            _shieldStatus.image = [UIImage imageNamed: @"shield.png"];
        }
         
        _secureOS_Load_Btn.layer.cornerRadius = 22;
        _secureOS_Load_Btn.clipsToBounds = YES;
        
        bool shouldUpdate = checkForAppUpdate();
        if (shouldUpdate) {
            _secureOS_Load_Btn.enabled = NO;
            [_secureOS_Load_Btn setTitle:@"Please update iSecureOS" forState: UIControlStateDisabled];
            
        } else if (CANT_CHK_VER) {
            _secureOS_Load_Btn.enabled = NO;
            [_secureOS_Load_Btn setTitle:@"Can't check version" forState: UIControlStateDisabled];
            
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

@end
