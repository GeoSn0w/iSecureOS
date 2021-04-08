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

@interface iSecureOS_Settings ()

@end

@implementation iSecureOS_Settings

- (void)viewDidLoad {
    [super viewDidLoad];
    shouldNotScanCVE = false;
    shouldNotScanVPN = false;
    
    _saveSettingsbutton.layer.cornerRadius = 22;
    _saveSettingsbutton.clipsToBounds = YES;
    _removeQuarantinedItemsButton.layer.cornerRadius = 18;
    _removeQuarantinedItemsButton.clipsToBounds = YES;
    [self fetchSettingsFromDefaults];
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
        [[NSUserDefaults standardUserDefaults] setObject:@"1" forKey:@"VPN"];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"0" forKey:@"VPN"];
    }
    
    if (shouldNotScanCVE == true){
        [[NSUserDefaults standardUserDefaults] setObject:@"1" forKey:@"CVE"];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"0" forKey:@"CVE"];
    }
    [[NSUserDefaults standardUserDefaults] synchronize];
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

@end
