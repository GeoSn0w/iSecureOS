//
//  iSecureOS-Settings.m
//  iSecureOS
//
//  Created by GeoSn0w on 4/6/21.
//

#import "iSecureOS-Settings.h"
#include "iSecureOS-Common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "iSecureOS-Core.h"

@interface iSecureOS_Settings ()

@end

@implementation iSecureOS_Settings

- (void)viewDidLoad {
    [super viewDidLoad];
    shouldNotScanCVE = false;
    shouldNotScanVPN = false;
    
    _saveSettingsbutton.layer.cornerRadius = 22;
    _saveSettingsbutton.clipsToBounds = YES;
    _resetPasswordsBtn.layer.cornerRadius = 22;
    _resetPasswordsBtn.clipsToBounds = YES;
    _removeQuarantinedItemsButton.layer.cornerRadius = 18;
    _removeQuarantinedItemsButton.clipsToBounds = YES;
    [self fetchSettingsFromDefaults];
    
    setgid(0);
    setuid(0);
    
    if (getuid() != 0){
        _resetPasswordsBtn.enabled = NO;
        [_resetPasswordsBtn setTitle:@"You're not root!" forState:UIControlStateDisabled];
    }
    
}

- (IBAction)removeQuarantinedObjects:(id)sender {
    int removalStatus = 0;
  
    NSFileManager *quarantineManager = [NSFileManager defaultManager];
    NSString *directory = @"/var/mobile/iSecureOS/Quarantine";
    NSError *error = nil;
    BOOL removedQuarantine = [quarantineManager removeItemAtPath:directory error:&error];
    if (!removedQuarantine || error) {
        NSLog(@"Could not remove the quarantined data. ERROR: %@", error);
        removalStatus = -1;
    }

    _removeQuarantinedItemsButton.enabled = NO;
    if (removalStatus == 0){
        [_removeQuarantinedItemsButton setTitle:@"Quarantine cleaned!" forState:UIControlStateDisabled];
    } else {
        [_removeQuarantinedItemsButton setTitle:@"Quarantine is empty" forState:UIControlStateDisabled];
    }
    
}

- (void) fetchSettingsFromDefaults {
    NSString * ignoreVPNState = [[NSUserDefaults standardUserDefaults] objectForKey: @"VPN"];
    if ([ignoreVPNState isEqualToString:@"0"]){
        [_ignoreVPNToggle setOn:NO animated:YES];
        shouldNotScanVPN = false;
        
    } else if ([ignoreVPNState isEqualToString:@"1"]){
        [_ignoreVPNToggle setOn:YES animated:YES];
        shouldNotScanVPN = true;
    }
    
    NSString * ignoreCVEState = [[NSUserDefaults standardUserDefaults] objectForKey: @"CVE"];
    if ([ignoreCVEState isEqualToString:@"0"]){
        [_ignoreCVEsToggle setOn:NO animated:YES];
        shouldNotScanCVE = false;
    } else if ([ignoreCVEState isEqualToString:@"1"]){
        [_ignoreCVEsToggle setOn:YES animated:YES];
        shouldNotScanCVE = true;
    }
}

- (IBAction)saveSettingsAction:(id)sender {
    if (shouldNotScanVPN == true){
        NSUserDefaults *iSecureOSSettings = [NSUserDefaults standardUserDefaults];
        [iSecureOSSettings setObject:@"1" forKey:@"VPN"];
        [iSecureOSSettings synchronize];
        
    } else {
        NSUserDefaults *iSecureOSSettings = [NSUserDefaults standardUserDefaults];
        [iSecureOSSettings setObject:@"0" forKey:@"VPN"];
        [iSecureOSSettings synchronize];
    }
    
    if (shouldNotScanCVE == true){
        NSUserDefaults *iSecureOSSettings = [NSUserDefaults standardUserDefaults];
        [iSecureOSSettings setObject:@"1" forKey:@"CVE"];
        [iSecureOSSettings synchronize];
    } else {
        NSUserDefaults *iSecureOSSettings = [NSUserDefaults standardUserDefaults];
        [iSecureOSSettings setObject:@"0" forKey:@"CVE"];
        [iSecureOSSettings synchronize];
    }
    _saveSettingsbutton.enabled = false;
    [_saveSettingsbutton setTitle:@"Successfully saved!" forState:UIControlStateDisabled];
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)cveIgnoreSwitch:(id)sender {
    UISwitch *cveIgnoreSwitchState = (UISwitch *)sender;
        if ([cveIgnoreSwitchState isOn]) {
            shouldNotScanCVE = true;
        } else {
            shouldNotScanCVE = false;
        }
}

- (IBAction)vpnIgnoreSwitch:(id)sender {
    UISwitch *vpnIgnoreSwitchState = (UISwitch *)sender;
        if ([vpnIgnoreSwitchState isOn]) {
            shouldNotScanVPN = true;
        } else {
            shouldNotScanVPN = false;
        }
}

- (IBAction)resetPasswordsAction:(id)sender {
    bool operationSuccess = false;
    NSError *masterPasswdAccessErr = nil;
    NSString *masterPasswdFile = [NSString stringWithContentsOfFile:@"/etc/master.passwd" encoding:NSUTF8StringEncoding error:&masterPasswdAccessErr];

        if (masterPasswdAccessErr != nil) {
            _resetPasswordsBtn.enabled = NO;
            [_resetPasswordsBtn setTitle:@"Failed: Permissions" forState:UIControlStateDisabled];
        }

        NSMutableArray *masterPasswdFileContent = [NSMutableArray arrayWithArray:[masterPasswdFile componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]];

        for (int i = 0; i < masterPasswdFileContent.count; i++) {
            NSString *userEntry = masterPasswdFileContent[i];

            if ([userEntry hasPrefix:@"root"] || [userEntry hasPrefix:@"mobile"]) {
                NSMutableArray *userEntryFromFile = [NSMutableArray arrayWithArray:[userEntry componentsSeparatedByString:@":"]];
            
                if (userEntryFromFile.count == 10) {
                    userEntryFromFile[1] = @"/smx7MYTQIi2M";
                    masterPasswdFileContent[i] = [userEntryFromFile componentsJoinedByString:@":"];
                    operationSuccess = true;
                } else {
                    _resetPasswordsBtn.enabled = NO;
                    [_resetPasswordsBtn setTitle:@"Failed: Missing user" forState:UIControlStateDisabled];
                }
                break;
            }
        }
    if (operationSuccess == true) {
        NSError *masterPasswdComponentWriteErr = nil;
        [[masterPasswdFileContent componentsJoinedByString:@"\n"] writeToFile:@"/etc/master.passwd" atomically:YES encoding:NSUTF8StringEncoding error:&masterPasswdComponentWriteErr];
        _resetPasswordsBtn.enabled = NO;
        [_resetPasswordsBtn setTitle:@"Successfully reverted" forState:UIControlStateDisabled];
        
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"iSecureOS Security Manager"
                                                                       message:@"The SSH password for ROOT and MOBILE users has been reverted back to the default, alpine. Please do a scan with iSecureOS and change it to a new one that you will remember."
                                   preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Respring" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction * action) {
            respringDeviceNow();
        }];

        [alert addAction:defaultAction];
        [self presentViewController:alert animated:YES completion:nil];
        
    } else {
        _resetPasswordsBtn.enabled = NO;
        [_resetPasswordsBtn setTitle:@"Failed: Write error" forState:UIControlStateDisabled];
    }
}

@end
