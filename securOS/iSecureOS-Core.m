//
//  iSecureOS-Core
//  securiOS
//
//  Created by GeoSn0w (@FCE365) on 3/9/21.
//

#import "iSecureOS-Core.h"
#import <QuartzCore/QuartzCore.h>
#include <stdlib.h>
#include <UIKit/UIKit.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>

#include <spawn.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/cdefs.h>
#include <sys/queue.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/lock.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <mach-o/loader.h>
#include <mach/mach.h>

#include <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

#include "iSecureOS-Tampering.h"
#include "iSecureOS-Security.h"
#include "iSecureOS-Networking.h"
#include "iSecureOS-Signatures.h"
#include "iSecureOS-ThreatScreen.h"
#include "iSecureOS-Defaulting.h"
#include "iSecureOS-Common.h"
#include <AWFileHash.h>

#define vm_address_t mach_vm_address_t
#define tfp0 pwnage.kernel_port
#define slide pwnage.kernel_slide
#define kbase pwnage.kernel_base


//***********************************************
int vulnerabilityCount = 0;
bool isPasscodeVulnerable = false;
bool isSSHPasswordVulnerable = false;
bool isProblematicReposPresent = false;
//***********************************************


typedef struct kernel_data_t {
    mach_port_t kernel_port;
    mach_vm_address_t kernel_base;
    mach_vm_offset_t kernel_slide;
} kernel_data_t;

@interface securiOS_Logging () <UITableViewDelegate, UITableViewDataSource>

@end

// For Signatures
NSMutableArray * SecurityRiskRepos;
NSMutableArray *detectedMalware;
//

// For results
NSMutableArray * Vulnerabilities;
NSMutableArray * VulnerabilityDetails;
NSMutableArray * VulnerabilitySeverity;
NSMutableArray * MalwareDefinitions;
NSString *selectedVulnerabilityForDetails;
NSString *tweakInjectionPath;
//

char *mostLikelyJailbreak;

@implementation securiOS_Logging

int shouldScan = 0;

- (void)viewDidLoad {
    [super viewDidLoad];
    if (@available(iOS 13.0, *)) {
            self.overrideUserInterfaceStyle = UIUserInterfaceStyleLight;
    }
    
    if (SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"13.0")){
        // iOS 12 lacks the modals you can close by draging down. We add a manual back button.
        _backButton12.hidden = NO;
    }
    
    printf("iSecureOS v1.05 by GeoSn0w (@FCE365)\n");
    printf("Initializing securiOS...\n", NULL);
    UITapGestureRecognizer *gestureRecognizer = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(dismissKeyboard)];
    [self.view addGestureRecognizer:gestureRecognizer];
        gestureRecognizer.cancelsTouchesInView = NO;
    
    
    // Beginning of UI Button Rounding
    _viewVulnerabilities.layer.cornerRadius = 22;
    _viewVulnerabilities.clipsToBounds = YES;
    _changeRootPassword.layer.cornerRadius = 19;
    _changeRootPassword.clipsToBounds = YES;
    
    // End of UI Rounding
    
    if (shouldScan == 0){
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            if ([self updateSignaturesDB] == 0){
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    [self iSecureOSInitMain];
                });
            } else {
                printf("Could not obtain the signatures for iSecureOS.\n");
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.scanningLabel.text = @"Could not get signatures.";
                });
            }
        });
    }
}
- (int) updateSignaturesDB {
    if (performRepoSignatureUpdate() == 0){
        if (populateVulnerableReposFromSignatures() == 0){
            if (performMalwareSignatureUpdate() == 0){
                if (populateMalwareDefinitionsFromSignatures() == 0){
                    NSLog(@"Finished setting up iSecureOS signatures.\n");
                    return 0;
                } else {
                    NSLog(@"Could not populate malware definitons for iSecureOS.\n");
                    self.scanningLabel.text = @"Could not get signatures.";
                }
            } else {
                NSLog(@"Could not download the malware definitons for iSecureOS.");
                return -1;
            }
           
        } else {
            NSLog(@"Could not populate the signatures for iSecureOS.\n");
            self.scanningLabel.text = @"Could not get signatures.";
        }
    } else {
        NSLog(@"Could not obtain the repo signatures for iSecureOS.\n");
        return -1;
    }
    NSLog(@"Failed to set up iSecureOS signatures.\n");
    return -1;
}

- (void) dismissKeyboard {
     [self.view endEditing:YES];
}

int populateVulnerableReposFromSignatures(){
    SecurityRiskRepos = [[NSMutableArray alloc] init];
    NSString *textFilePath = @"/var/mobile/iSecureOS/repo-signatures";
    NSError *error;
    NSString *fileContentsUrls = [NSString stringWithContentsOfFile:textFilePath encoding:NSUTF8StringEncoding error:&error];
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:fileContentsUrls options: NSDataBase64DecodingIgnoreUnknownCharacters];
    NSString *base64DecodedString = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
    
    SecurityRiskRepos = [[base64DecodedString componentsSeparatedByString:@"\n"] mutableCopy];
    NSLog(@"%@", base64DecodedString);
    if (error == nil) {
        printf("Successfully loaded Repo Signatures into iSecureOS\n");
        return 0;
    } else {
        printf("Failed to get the online version of the signatures. Will default to offline.\n");
        SecurityRiskRepos = [[iSecureOSDefaultingRepos componentsSeparatedByString:@","] mutableCopy];
        return 0;
    }
}

int populateMalwareDefinitionsFromSignatures(){
    MalwareDefinitions = [[NSMutableArray alloc] init];
    NSString *malwareDefinitionsFilePath = @"/var/mobile/iSecureOS/definitions.sec";
    NSError *error;
    NSString *fileContentsUrls = [NSString stringWithContentsOfFile:malwareDefinitionsFilePath encoding:NSUTF8StringEncoding error:&error];
    MalwareDefinitions = [[fileContentsUrls componentsSeparatedByString:@"\n"] mutableCopy];
    if (error == nil) {
        printf("Successfully loaded Malware Signatures into iSecureOS\n");
        return 0;
    } else {
        printf("Failed to get the online version of the signatures.\n");
        return -1;
    }
}

-(void) performCleanupSegue {
    shouldScan = 1;
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    NSDate *currDate = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc]init];
    [dateFormatter setDateFormat:@"dd-MM-YY"];
    
    [userDefaults setObject:currDate
                     forKey:@"LastScan"];
    [userDefaults synchronize];
    
    _viewVulnerabilities.hidden = NO;
    if (isSSHPasswordVulnerable){
        _changeRootPassword.hidden = NO;
    }
    _scanningLabel.text = @"Finished scanning.";
    
    NSString *path = @"/var/mobile/iSecureOS";
    NSURL *url = [NSURL URLWithString:[path stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLHostAllowedCharacterSet]]];
    url = [url URLByAppendingPathComponent:@"ScanResult.json"];
    NSError *e = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:Vulnerabilities options:NSJSONWritingPrettyPrinted error:&e];

    if (jsonData) {
        [jsonData writeToFile:url.path atomically:YES];
    }
    remove("/var/mobile/iSecureOS/repo-signatures");
    remove("/var/mobile/iSecureOS/definitions.sec");
    return;
}

-(NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section{
    return [Vulnerabilities count];
}

-(UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"secuiOSTableCell"];
    cell.textLabel.text = [Vulnerabilities objectAtIndex:(indexPath.row)];
    cell.detailTextLabel.text = [VulnerabilityDetails objectAtIndex:(indexPath.row)];
    [[cell imageView] setTintColor: [VulnerabilitySeverity objectAtIndex:(indexPath.row)]];
    [[cell textLabel] setNumberOfLines:0];
    [[cell textLabel] setLineBreakMode:NSLineBreakByWordWrapping];
    [[cell textLabel] setFont:[UIFont systemFontOfSize: 13.0]];
    return cell;
    
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath{
    selectedVulnerabilityForDetails = [Vulnerabilities objectAtIndex:indexPath.row];
    
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Vulnerability details"
                               message:[VulnerabilityDetails objectAtIndex:indexPath.row]
                               preferredStyle:UIAlertControllerStyleAlert];

    UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                   handler:^(UIAlertAction * action) {}];

    [alert addAction:defaultAction];
    [self presentViewController:alert animated:NO completion:nil];

}

kernel_data_t pwnage = {};
kern_return_t get_kernelport(kernel_data_t* data){
    if(!data){
        return KERN_INVALID_ARGUMENT;
    }
    return host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
}
- (void)redirectNotificationHandle:(NSNotification *)nf{
    
    NSData *data = [[nf userInfo] objectForKey:NSFileHandleNotificationDataItem];
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    self.logmeeh.text = [NSString stringWithFormat:@"%@\n%@",self.logmeeh.text, str];
    NSRange lastLine = NSMakeRange(self.logmeeh.text.length - 1, 1);
    [self.logmeeh scrollRangeToVisible:lastLine];
    [[nf object] readInBackgroundAndNotify];
}

- (void)redirectSTD:(int )fd{
    setvbuf(stdout, nil, _IONBF, 0);
    NSPipe * pipe = [NSPipe pipe] ;
    NSFileHandle *pipeReadHandle = [pipe fileHandleForReading] ;
    dup2([[pipe fileHandleForWriting] fileDescriptor], fd) ;
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(redirectNotificationHandle:)
                                                 name:NSFileHandleReadCompletionNotification
                                               object:pipeReadHandle] ;
    [pipeReadHandle readInBackgroundAndNotify];
}

typedef NS_ENUM (NSUInteger, securiOS_Device_Security){
    DevicePasscodeActive  = 1,
    DeviceNoPasscode  = 2
};

- (securiOS_Device_Security) extractPasscodeStatusWithKeychain {
        NSData* secret = [@"GeoSn0w / FCE365" dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *attributes = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword, (__bridge id)kSecAttrService: @"LocalDeviceServices",  (__bridge id)kSecAttrAccount: @"NoAccount", (__bridge id)kSecValueData: secret, (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly };

        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
        if (status == errSecSuccess) {
            SecItemDelete((__bridge CFDictionaryRef)attributes);
            return DevicePasscodeActive;
        }

        return DeviceNoPasscode;
}

// Main Scanning Stub

- (void) iSecureOSInitMain {
        Vulnerabilities = [[NSMutableArray alloc] init];
        VulnerabilityDetails = [[NSMutableArray alloc] init];
        VulnerabilitySeverity = [[NSMutableArray alloc] init];
        kern_return_t oskernfail = KERN_SUCCESS;
        printf("Performing jailbreak probing...\n", NULL);
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:1.5 animations:^{
                    [self.scannProgressbar setProgress:0.05 animated:YES];
            }];
        });
        int jailbreakProbing = performJailbreakProbingAtPath();
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:1.5 animations:^{
                    [self.scannProgressbar setProgress:0.1 animated:YES];
            }];
        });
    
        if (jailbreakProbing == 0) {
                oskernfail = get_kernelport(&pwnage);
                printf("[ i ] Testing to see if tfp0 / hsp4 is exported...\n");
                if(oskernfail) {
                    printf("[ ! ] Failed to get kernel taskport: %s. Good.\n", mach_error_string(oskernfail));
                } else {
                    printf("[VULNERABILITY] Kernel Task Port IS Exported. Disable it after running securiOS.\n\n");
                    printf("[ i ] Kernel Task Port is 0x%x\n", tfp0);
                }
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    [UIView animateWithDuration:1.5 animations:^{
                            [self.scannProgressbar setProgress:0.15 animated:YES];
                    }];
                });
                
                performSuspectRepoScanning();
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    [UIView animateWithDuration:1.5 animations:^{
                            [self.scannProgressbar setProgress:0.15 animated:YES];
                    }];
                });
                
                checkForUnsafeTweaks();
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    [UIView animateWithDuration:1.5 animations:^{
                            [self.scannProgressbar setProgress:0.15 animated:YES];
                    }];
                });
                tweakInjectionPath = @"/Library/MobileSubstrate/DynamicLibraries";
                if ([self scanForMalwareAtPath] ==0){
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [UIView animateWithDuration:1.5 animations:^{
                                [self.scannProgressbar setProgress:0.20 animated:YES];
                        }];
                    });
                } else {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [UIView animateWithDuration:1.5 animations:^{
                                [self.scannProgressbar setProgress:0.20 animated:YES];
                        }];
                    });
                }
                tweakInjectionPath = @"/usr/lib/TweakInject";
                if ([self scanForMalwareAtPath] ==0){
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [UIView animateWithDuration:1.5 animations:^{
                                [self.scannProgressbar setProgress:0.30 animated:YES];
                        }];
                    });
                } else {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [UIView animateWithDuration:1.5 animations:^{
                                [self.scannProgressbar setProgress:0.30 animated:YES];
                        }];
                    });
                }
                if (shouldPerformInDepthScan == true){
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self.scanningLabel.text = @"Now Deep-scanning...";
                    });
                    tweakInjectionPath = @"/usr/bin/";
                    if ([self scanForMalwareAtPath] ==0){
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.40 animated:YES];
                            }];
                        });
                    } else {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.40 animated:YES];
                            }];
                        });
                    }
                    tweakInjectionPath = @"/usr/libexec/";
                    if ([self scanForMalwareAtPath] ==0){
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.40 animated:YES];
                            }];
                        });
                    } else {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.40 animated:YES];
                            }];
                        });
                    }
                    tweakInjectionPath = @"/usr/sbin/";
                    if ([self scanForMalwareAtPath] ==0){
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.40 animated:YES];
                            }];
                        });
                    } else {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.40 animated:YES];
                            }];
                        });
                    }
                    tweakInjectionPath = @"/usr/lib/";
                    if ([self scanForMalwareAtPath] ==0){
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.50 animated:YES];
                            }];
                        });
                    } else {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.50 animated:YES];
                            }];
                        });
                    }
                    tweakInjectionPath = @"/bin/";
                    if ([self scanForMalwareAtPath] ==0){
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.50 animated:YES];
                            }];
                        });
                    } else {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.50 animated:YES];
                            }];
                        });
                    }
                    tweakInjectionPath = @"/sbin/";
                    if ([self scanForMalwareAtPath] ==0){
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.50 animated:YES];
                            }];
                        });
                    } else {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [UIView animateWithDuration:1.5 animations:^{
                                    [self.scannProgressbar setProgress:0.50 animated:YES];
                            }];
                        });
                    }
                }
                [self checkPasswordDefaulting];
                
            }
           [self checkPasscodeProtectionStatus];
    
            dispatch_async(dispatch_get_main_queue(), ^{
                [UIView animateWithDuration:1.5 animations:^{
                        [self.scannProgressbar setProgress:0.70 animated:YES];
                }];
            });
    
        // After this beta, these will be a database of their own. For now, all jailbreaks are vulnerable to these 3 anyways. Will do better.
        UIColor *orangeColor = [UIColor orangeColor];
        if (SYSTEM_VERSION_LESS_THAN(@"14.2")){
            [Vulnerabilities addObject:@"Vulnerable to CVE-2020-27930"];
            [VulnerabilityDetails addObject:@"CVE-2020-27930 is a FontParser vulnerability that can lead to arbitrary code execution. Apple is aware of reports that an exploit for this issue exists in the wild. Pay attention to the apps you install, and websites you visit."];
            [VulnerabilitySeverity addObject:orangeColor];
        }
    
        if (SYSTEM_VERSION_LESS_THAN(@"14.2")){
            [Vulnerabilities addObject:@"Vulnerable to CVE-2020-27918"];
            [VulnerabilityDetails addObject:@"CVE-2020-27918 is a WebKit vulnerability that can lead to arbitrary code execution. Pay attention to the websites you visit, as a malicious website can trigger an exploit for this vulnerability in order to exfiltrate data. There's not much you can do about this, other than updating to the latest iOS which results in losing your jailbreak."];
            [VulnerabilitySeverity addObject:orangeColor];
        }
       
        if (SYSTEM_VERSION_LESS_THAN(@"14.4")) {
            [Vulnerabilities addObject:@"Vulnerable to CVE-2021-1782 (cicuta_virosa)"];
            [VulnerabilityDetails addObject:@"CVE-2021-1782 (cicuta_virosa) is a race condition in user_data_get_value() leading to ivac entry uaf. This issue has been actively exploited in the wild with the WebKit exploit. Pay attention to the applications you install, as they wouldn't necessarily require a jailbreak to access your data. There's not much you can do about this, other than updating to the latest iOS which results in losing your jailbreak."];
            [VulnerabilitySeverity addObject:orangeColor];
        }
        if (SYSTEM_VERSION_LESS_THAN(@"14.4.1")) {
            [Vulnerabilities addObject:@"Vulnerable to CVE-2021-1844 (WebKit)"];
            [VulnerabilityDetails addObject:@"CVE-2021-1844 is a WebKit memory corruption issue. Using this, processing maliciously crafted web content may lead to arbitrary code execution. Pay attention to the websites you visit. There's not much you can do about this, other than updating to the latest iOS which results in losing your jailbreak."];
            [VulnerabilitySeverity addObject:orangeColor];
        }
        [self performLocationCheck];
    
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:1.5 animations:^{
                    [self.scannProgressbar setProgress:0.75 animated:YES];
            }];
        });
    
        [self checkIfVPNIsActive];
    
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:1.5 animations:^{
                    [self.scannProgressbar setProgress:0.80 animated:YES];
            }];
        });
    
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:1.5 animations:^{
                    [self.scannProgressbar setProgress:0.90 animated:YES];
            }];
        });
       
        // Threat Level
        int threatLevel = checkActiveSSHConnection();
        if (threatLevel == 0){
            NSString *valueToSave = @"0";
            [[NSUserDefaults standardUserDefaults] setObject:valueToSave forKey:@"ThreatLevel"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        } else if (threatLevel == 1) {
            NSString *valueToSave = @"1";
            [[NSUserDefaults standardUserDefaults] setObject:valueToSave forKey:@"ThreatLevel"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        } else if (threatLevel == 2) {
            NSString *valueToSave = @"2";
            [[NSUserDefaults standardUserDefaults] setObject:valueToSave forKey:@"ThreatLevel"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        } else if (threatLevel == 3) {
            NSString *valueToSave = @"3";
            [[NSUserDefaults standardUserDefaults] setObject:valueToSave forKey:@"ThreatLevel"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
    
        if (threatLevel != -1){
            dispatch_async(dispatch_get_main_queue(), ^{
                NSString * storyboardName = @"Main";
                UIStoryboard *storyboard = [UIStoryboard storyboardWithName:storyboardName bundle: nil];
                UIViewController * vc = [storyboard instantiateViewControllerWithIdentifier:@"ThreatMenu"];
                [self presentViewController:vc animated:YES completion:nil];
            });
        }
    
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:1.5 animations:^{
                    [self.scannProgressbar setProgress:1.0 animated:YES];
            }];
        });
    
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:1.5 animations:^{
                [self performCleanupSegue];
                self.currentFile.hidden = YES;
            }];
        });
        
    return;
}

// Location Services

- (void) performLocationCheck {
    UIColor *yellowColor = [UIColor yellowColor];
    int retval = checkLocationServices();
    switch (retval) {
        case 0:
            printf("Location services are enabled. Unless you really use them, they should be disabled.");
            [Vulnerabilities addObject:@"Location Services are enabled."];
            [VulnerabilityDetails addObject:@"Unless you really need GPS, you should keep them off to save battery and ensure applications don't have on-demand unfettered access to your position for tracking purposes. Enable Location Services only for when the app is in use, and do not keep them on for more than you need."];
            [VulnerabilitySeverity addObject:yellowColor];
            break;
        case -1:
            printf("Location services are not enabled. Unless you really use them, they should stay disabled.");
        default:
            break;
    }
}

-(void) checkIfVPNIsActive{
    UIColor *yellowColor = [UIColor yellowColor];
    int retval = performVPNCheck(); //Calls the function iSecureOS-Networking
    switch (retval) {
        case 0:
            printf("Detected an enabled VPN. Great!");
            break;
        case -1:
            printf("There doesn't seem to be a VPN active on this device right now. You should consider a quality one, or build one yourself. These greatly improve the security of your device.");
            [Vulnerabilities addObject:@"You're not using a VPN"];
            [VulnerabilityDetails addObject:@"There doesn't seem to be a VPN active on this device right now. You should consider a quality one, or build one yourself. These greatly improve the security of your device. Be sure to get a quality, no LOGS VPN with preferably a transparent user data collection policies. Not all VPN providers are honest and you may end up worse than without one."];
            [VulnerabilitySeverity addObject:yellowColor];
        default:
            break;
    }
}

// Passcode / FaceID / TouchID

- (void) checkPasscodeProtectionStatus{
    UIColor *orangeColor = [UIColor orangeColor];
    if ([self extractPasscodeStatusWithKeychain] == 0){
        printf("[ ! ] Could not detect if the device has a passcode!\n\n");
        [Vulnerabilities addObject:@"Cannot detect if passcode is set."];
        [VulnerabilityDetails addObject:@"This device may not have a Passcode set. Data may be accessible to anybody with physical access."];
        [VulnerabilitySeverity addObject:orangeColor];
    } else if ([self extractPasscodeStatusWithKeychain] == 1){
        printf("[ i ] Passcode is active on the device. Great!\n\n");
    } else if ([self extractPasscodeStatusWithKeychain] == 2){
        printf("[VULNERABILITY] Passcode is NOT enabled on this device. That's BAD.\n\n");
        [Vulnerabilities addObject:@"Passcode not set!"];
        [VulnerabilityDetails addObject:@"This device does not have a Passcode set. Data is accessible to anybody with physical access."];
        [VulnerabilitySeverity addObject:orangeColor];
    }
    return;
}

void printUnsafeRepoWarning(const char *problematicRepo){
    printf("[VULNERABILITY] %s is a problematic piracy repo which can contain malware, outdated tweaks or otherwise modified tweaks. You should remove it, and everything installed from it.\n\n", problematicRepo);
    return;
}

void printUnsafeTweakWarning(const char *problematicTweak){
    printf("[VULNERABILITY] %s is a problematic tweak which can contain malware. Tweaks used to pirate Cydia tweaks, like CyDown, create botnets on your device to attempt to grab tweaks and share them with pirates from your UDID. In the case of LocaliAPStore, many applications detect this and may refuze to work and may ban you.\n\n", problematicTweak);
    return;
}
- (int) checkPasswordDefaulting {
    UIColor *redColor = [UIColor redColor];
    setuid(0);
    setgid(0);
    if (getuid() == 0){
          FILE *filepointer;
          char *searchString="root:/smx7MYTQIi2M";
          filepointer = fopen("/etc/master.passwd", "r");
          char buf[100];
          while((fgets(buf, 100, filepointer)!=NULL)) {
            if(strstr(buf, searchString)!=NULL) {
                printf("[VULNERABILITY] Your SSH password is the default, alpine! You should change it.\n\n");
                [Vulnerabilities addObject:@"Default SSH password detected."];
                [VulnerabilityDetails addObject:@"This device has the default alpine password for remote SSH access. You must change it."];
                [VulnerabilitySeverity addObject: redColor];
                isSSHPasswordVulnerable = true;
                fclose(filepointer);
                return -1;
                break;
            }
          }
          fclose(filepointer);
          printf("[ i ] Your SSH password does not seem to be the default, great!\n");
          return (0);
    } else {
        printf("[ ! ] Could not assess the ROOT password. You are not root.\n");
    }
    return -1;
}



int potentiallyMalwareRepoCheck(const char *repoToCheck) {
    UIColor *redColor = [UIColor redColor];
    
    FILE *filepointer;
    filepointer = fopen("/etc/apt/sources.list.d/cydia.list", "r");
    if (filepointer){
        fclose(filepointer);
        filepointer = fopen("/etc/apt/sources.list.d/cydia.list", "r");
        char buf[100];
            if (filepointer){
                while((fgets(buf, 100, filepointer)!=NULL)) {
                    if(strstr(buf, repoToCheck)!=NULL) {
                        NSString * actual_vulnerability = [NSString stringWithCString:repoToCheck encoding:NSASCIIStringEncoding];
                        [Vulnerabilities addObject:[actual_vulnerability stringByAppendingString:@" is an unsafe pirate repo. [In Cydia]"]];
                        [VulnerabilityDetails addObject:@"Pirate repos contain old, outdated and even modified or weaponized tweaks."];
                        [VulnerabilitySeverity addObject:redColor];
                        fclose(filepointer);
                        return 0;
                        break;
                    }
                }
                fclose(filepointer);
            }
    } else {
        fclose(filepointer);
        printf("[ ! ] Cydia's sources list isn't present. Will skip checking that one.\n");
    }
    
    // Prepare to also check for Sileo's packages.
    
    filepointer = fopen("/etc/apt/sources.list.d/sileo.sources", "r");
    if (filepointer){
        fclose(filepointer);
        filepointer = fopen("/etc/apt/sources.list.d/sileo.sources", "r");
        char buf[100];
            if (filepointer){
                while((fgets(buf, 100, filepointer)!=NULL)) {
                    if(strstr(buf, repoToCheck)!=NULL) {
                        NSString * actual_vulnerability = [NSString stringWithCString:repoToCheck encoding:NSASCIIStringEncoding];
                        [Vulnerabilities addObject:[actual_vulnerability stringByAppendingString:@" is an unsafe pirate repo. [In SILEO]"]];
                        [VulnerabilityDetails addObject:@"Pirate repos contain old, outdated and even modified or weaponized tweaks."];
                        [VulnerabilitySeverity addObject:redColor];
                        fclose(filepointer);
                        return 0;
                        break;
                    }
                }
                fclose(filepointer);
            }
    } else {
        fclose(filepointer);
        printf("[ ! ] Sileo's sources list isn't present. Will skip checking that one.\n");
    }
    
    filepointer = fopen("/var/mobile/Library/Application Support/xyz.willy.Zebra/sources.list", "r");
    if (filepointer){
        fclose(filepointer);
        filepointer = fopen("/var/mobile/Library/Application Support/xyz.willy.Zebra/sources.list", "r");
        char buf[200];
            if (filepointer){
                
                while((fgets(buf, 100, filepointer)!=NULL)) {
                    if(strstr(buf, repoToCheck)!=NULL) {
                        NSString * actual_vulnerability = [NSString stringWithCString:repoToCheck encoding:NSASCIIStringEncoding];
                        [Vulnerabilities addObject:[actual_vulnerability stringByAppendingString:@" is an unsafe pirate repo. [In Zebra]"]];
                        [VulnerabilityDetails addObject:@"Pirate repos contain old, outdated and even modified or weaponized tweaks."];
                        [VulnerabilitySeverity addObject:redColor];
                        fclose(filepointer);
                        return 0;
                        break;
                    }
                }
                fclose(filepointer);
            }
    } else {
        fclose(filepointer);
        printf("[ ! ] Zebra's sources list isn't present. Will skip checking that one.\n");
    }
    return -1;
}
bool file_exists (char *filename) {
  struct stat   buffer;
  return (stat (filename, &buffer) == 0);
}

int performJailbreakProbingAtPath(){
    int result = 2;
    printf("Attempting to detect if the device is jailbroken...\n");
    FILE * f = fopen("/var/mobile/iSecureOS-Sandbox", "w");
       if (!f) {
           fclose(f);
           fprintf(stderr,"Random processes are running sandboxed. Will attempt to check further.\n");
       } else {
           printf("Detected sandbox escape. This device is likely jailbroken.\n");
           result = 0;
           fclose(f);
           return result;
       }
    if(file_exists("/Applications/Cydia.app" )) {
        printf("[ i ] Found Cydia installed. This device is jailbroken.\n");
        result = 1;
    } else {
        printf("[ - ] Cydia is not installed on this device.\n");
    }
    
    if(file_exists("/Applications/Sileo.app")) {
        printf("[ i ] Found dog medicine (Sileo) installed. This device is jailbroken.\n");
        result = 1;
    } else {
        printf("[ - ] Sileo is not installed on this device.\n");
    }
    
    if(file_exists("/Applications/Zebra.app")) {
        printf("[ i ] Found Zebra installed. This device is jailbroken.\n");
        result = 1;
    } else {
        printf("[ - ] Zebra is not installed on this device.\n");
    }
    
    // Detect most likely signature of the jailbreak currently active.
    
    if (file_exists("/.bit_of_fun")){
        mostLikelyJailbreak = "Electra";
        result = 1;
    }
    return result;
}
int checkForUnsafeTweaks(){
    UIColor *redColor = [UIColor redColor];
    if(file_exists("/Library/MobileSubstrate/DynamicLibraries/CyDown.dylib" )) {
        printUnsafeTweakWarning("CyDown");
        [Vulnerabilities addObject:@"CyDown is an unsafe pirate tweak / Botnet."];
        [VulnerabilityDetails addObject:@"This is a pirate tweak used to get paid tweaks for free. There are reports in the community from developers (LaughingQuoll et al.), that the tweak acts as a botnet and uses your device / UDID to grab tweaks from Packix and other legitimate repos in your name, and then share them with pirates. It's advised to uninstall it for your safety."];
        [VulnerabilitySeverity addObject: redColor];
    }
    if(file_exists("/Library/MobileSubstrate/DynamicLibraries/LocalIAPStore.dylib") || file_exists("/Library/MobileSubstrate/DynamicLibraries/LocalIAPStore13.dylib")) {
        printUnsafeTweakWarning("LocaliAPStore");
        [Vulnerabilities addObject:@"LocaliAPStore is an unsafe pirate tweak that can get you banned."];
        [VulnerabilityDetails addObject:@"LocaliAPStore is a pirate tweak that makes some applications believe you made a real in-app purchase / microtransaction. Many applications are nowadays immune to it, but may ban you because you have it installed."];
        [VulnerabilitySeverity addObject: redColor];
    }
    return 0;
}
void performSuspectRepoScanning(){
    // Performing repo sanity checks. This will check if the user has installed any problematic repos.
    
    for (NSString *Repo in SecurityRiskRepos) {
        const char *EndOfFile = "EOF";
        const char *repoToCheck = [Repo UTF8String];
        if (strcmp(EndOfFile, repoToCheck) == 0){
            printf("Reached End of Signature Files\n");
            break;
        } else {
            if (potentiallyMalwareRepoCheck(repoToCheck) == 0){
                printUnsafeRepoWarning(repoToCheck);
                isProblematicReposPresent = true;
            }
        }
    }

    // End repo sanity checks
    if (isProblematicReposPresent){
        printf("[VULNERABILITY] You have pirate repos installed in your Cydia.\n\n");
    } else {
        printf("[ i ] You do not seem to have problematic repos installed. GREAT!\n\n");
    }
}
int execprog(const char *prog, const char* args[]) {
    if (args == NULL) {
        args = (const char **)&(const char*[]){ prog, NULL };
    }
    
    printf("Spawning [ ");
    for (const char **arg = args; *arg != NULL; ++arg) {
        printf("'%s' ", *arg);
    }
    
    int rv;
    posix_spawn_file_actions_t child_fd_actions;
    if ((rv = posix_spawn_file_actions_init (&child_fd_actions))) {
        perror ("posix_spawn_file_actions_init");
        return rv;
    }
    
    if ((rv = posix_spawn_file_actions_adddup2 (&child_fd_actions, STDOUT_FILENO, STDERR_FILENO))) {
        perror ("posix_spawn_file_actions_adddup2");
        return rv;
    }
    
    pid_t pd;
    if ((rv = posix_spawn(&pd, prog, &child_fd_actions, NULL, (char**)args, NULL))) {
        printf("posix_spawn error: %d (%s)\n", rv, strerror(rv));
        return rv;
    }
    
    printf("process spawned with pid %d \n", pd);
    int status;
    waitpid(pd, &status, 0);
    return 0;
}

-(void) checkForOutdatedPackages{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        char command[100];
        strcpy(command, "apt-get upgrade -s | grep upgraded | cut -d ' ' -f 1 > /var/mobile/tbd.txt" );
        system(command);
        FILE * f = fopen("/var/mobile/tbd.txt", "r");
           if (f) {
               fprintf(stderr,"Successfully fetched the amount of outdated packages.\n");
                char tweaksToBeUpdated[100];
                int finalTweakNumber = 0;
                 fscanf (f, "%s", tweaksToBeUpdated);
                 while (!feof (f))
                   {
                     printf ("%s ", tweaksToBeUpdated);
                     fscanf (f, "%s", tweaksToBeUpdated);
                   }
                 fclose (f);
               
               int i;
               int j = 0;
                   for(i=0; tweaksToBeUpdated[i] ;i++){
                       if(tweaksToBeUpdated[i] >= '0' && tweaksToBeUpdated[i] <= '9'){
                           tweaksToBeUpdated[j] = tweaksToBeUpdated[i];
                           j++;
                       }
                   }
               tweaksToBeUpdated[j] = '\0';
               finalTweakNumber = atoi(tweaksToBeUpdated);
    
               if (finalTweakNumber == 0){
                   printf("[ i ] No outdated tweaks detected! Great! (Ignores the ones you specifically downgraded.)\n");
               } else {
                   printf("[ ! ] There are tweaks that need to be upgraded! It's recommended that you always get the latest version of the tweaks.\n");
                   NSString *message = [NSString stringWithFormat:@"You have %d outdated tweaks! Please update them.\n", finalTweakNumber];
                   [Vulnerabilities addObject:message];
                   [VulnerabilityDetails addObject:@"It's important to keep your tweaks up to date to ensure you get the latest bug fixes and security improvements for your tweaks. Many tweaks get fixed daily and updates are being pushed, especially for stability reasons. Navigate to your favorite Package Manager and update your tweaks."];
               }
           } else {
               printf("Could not parse amount of outdated packages...\n");
           }
    });
}

int checkActiveSSHConnection(){
    // Check if an active root connection is found
    UIColor *redColor = [UIColor redColor];
    int rootAccess = warnaxActiveSSHConnection("sshd: root@ttys");
    if (rootAccess == 0) {
        printf("An active ROOT SSH connection is going on right now. If it's not you, this is BAD.\n");
            [Vulnerabilities addObject:@"WARNING! Active root SSH Connection to this device."];
            [VulnerabilityDetails addObject:@"An active SSH connection is going on right now. If it's not you, this is BAD. It means that someone is right now connected via the network to this device and can exfiltrate files as they please. Change your root password and reboot your device. As ROOT, the attacker has even more power."];
            [VulnerabilitySeverity addObject: redColor];
        isSSHPasswordVulnerable = true;
            return 0; // ROOT
    }
    
    // Check if an active mobile connection is found
    int mobileAccess = warnaxActiveSSHConnection("sshd: mobile@ttys");
    if (mobileAccess == 0) {
        printf("An active SSH connection as MOBILE is going on right now. If it's not you, this is BAD.\n");
            [Vulnerabilities addObject:@"WARNING! Active mobile SSH Connection to this device."];
            [VulnerabilityDetails addObject:@"An active SSH connection is going on right now. If it's not you, this is BAD. It means that someone is right now connected via the network to this device and can exfiltrate files as they please. Change your root and mobile password and reboot your device."];
            [VulnerabilitySeverity addObject: redColor];
        isSSHPasswordVulnerable = true;
            return 1; // mobile
    }
    
    /*------------------------------------------------------------*/
    
    // Check if an attempted mobile connection is ongoing...
    int attemptedMobile = warnaxActiveSSHConnection("sshd: mobile");
    if (attemptedMobile == 0) {
        printf("An attempted SSH connection as MOBILE is going on right now. If it's not you, this is BAD.\n");
            [Vulnerabilities addObject:@"WARNING! Somebody is trying to connect via SSH as mobile."];
            [VulnerabilityDetails addObject:@"Somebody is on the login screen right now either typing or trying different passwords to login as mobile via SSH to your device. If this is not you, change your mobile and root password and reboot your device."];
            [VulnerabilitySeverity addObject: redColor];
        isSSHPasswordVulnerable = true;
            return 2; // attempted mobile
    }
    
    /*------------------------------------------------------------*/
    
    // Check if an attempted ROOT connection is ongoing...
    int attemptedROOT = warnaxActiveSSHConnection("sshd: root");
    if (attemptedROOT == 0) {
        printf("An attempted SSH connection as ROOT is going on right now. If it's not you, this is BAD.\n");
            [Vulnerabilities addObject:@"WARNING! Somebody is trying to connect via SSH as ROOT."];
            [VulnerabilityDetails addObject:@"Somebody is on the login screen right now either typing or trying different passwords to login as ROOT via SSH to your device. If this is not you, change your root password and reboot your device."];
            [VulnerabilitySeverity addObject: redColor];
        isSSHPasswordVulnerable = true;
            return 3; // mobile
    }
    return -1;
}
- (IBAction)changePasswordForSSH:(id)sender {
    NSString *valueToSave = @"0";
    [[NSUserDefaults standardUserDefaults] setObject:valueToSave forKey:@"ShouldReboot"];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString * storyboardName = @"Main";
        UIStoryboard *storyboard = [UIStoryboard storyboardWithName:storyboardName bundle: nil];
        UIViewController * vc = [storyboard instantiateViewControllerWithIdentifier:@"RootPasswd"];
        [self presentViewController:vc animated:YES completion:nil];
    });
}
- (IBAction)saveLogToFile:(id)sender {
    
    NSString *path = @"/var/mobile/iSecureOS";
    NSURL *url = [NSURL URLWithString:[path stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLHostAllowedCharacterSet]]];
    url = [url URLByAppendingPathComponent:@"ScanResult.json"];
    NSError *e = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:Vulnerabilities options:NSJSONWritingPrettyPrinted error:&e];

    if (jsonData) {
        [jsonData writeToFile:url.path atomically:YES];
    }
    
    if (e == nil){
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Scan report saved"
                                                                       message:@"The scan report was saved to /var/mobile/iSecureOS/ScanResult.json"
                                   preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction * action) {}];

        [alert addAction:defaultAction];
        [self presentViewController:alert animated:YES completion:nil];
    }
    
}
-(int) scanForMalwareAtPath{
    _currentFile.hidden = NO;
    UIColor *redColor = [UIColor redColor];
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSURL *directoryURL = [NSURL URLWithString: tweakInjectionPath];
        NSArray *keys = [NSArray arrayWithObject:NSURLIsDirectoryKey];

        NSDirectoryEnumerator *enumerator = [fileManager
            enumeratorAtURL:directoryURL
            includingPropertiesForKeys:keys
            options:0
            errorHandler:^BOOL(NSURL *url, NSError *error) {
                printf("Something went wrong and the path could not be accessed.\n");
                return NO;
        }];

        for (NSURL *url in enumerator) {
            NSError *error;
            NSNumber *isDirectory = nil;
            if (![url getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&error]) {
                printf("Could not scan path. It's a directoy.\n");
            }
            else if (![isDirectory boolValue]) {
                NSString *filetocheckpath = url.path;
                
                if (![filetocheckpath containsString:@".plist"]) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self.currentFile.text = filetocheckpath;
                        self.scannProgressbar.progress += 0.0001f;
                        
                    });
                    NSString *hashsignature = [AWFileHash md5HashOfFileAtPath:filetocheckpath];
                    if ([MalwareDefinitions containsObject:hashsignature]){
                        [detectedMalware addObject:url];
                        NSString *malwareMessageHeader = [NSString stringWithFormat:@"[Malware] File: %@]", filetocheckpath];
                        NSString *malwareMessage = [NSString stringWithFormat:@"The file: %@ is a known malware binary file in the Jailbreak community and it can be used to remotely control, damage or otherwise affect your device. It's recommended that you delete the file in cause, and remove any unsafe repos.", filetocheckpath];
                        NSLog(@"%@", malwareMessage);
                        [Vulnerabilities addObject: malwareMessageHeader];
                        [VulnerabilityDetails addObject: malwareMessage];
                        [VulnerabilitySeverity addObject: redColor];
                    }
                }
            }
        }
    return 0;
    
}

- (IBAction)dismissModal12:(id)sender {
    // Looks like iOS 12 lacks the modals I use that you can just drag down to close, thus making people get stuck on one window. This should fix that.
    
    [self dismissViewControllerAnimated:YES completion:nil];
}
@end
