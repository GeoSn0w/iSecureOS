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

int removeQuarantineAtPath(const char path[]);

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
  
    if (removeQuarantineAtPath("/var/iSecureOS/Quarantine") != 0){
        NSLog(@"Could not remove the quarantined data.");
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

int removeQuarantineAtPath(const char path[]) {
    char *malwarePathFull;
    size_t lengthOfPath;
    DIR *malwareQuarantineDir;
    struct stat stat_path, stat_entry;
    struct dirent *directoryEntry;
    stat(path, &stat_path);

    if (S_ISDIR(stat_path.st_mode) == 0) {
        fprintf(stderr, "%s: %s\n", "this is not a folder.", path);
        exit(-1);
    }

    if ((malwareQuarantineDir = opendir(path)) == NULL) {
        fprintf(stderr, "%s: %s\n", "Could not open Quarantine folder.", path);
        exit(-1);
    }

    lengthOfPath = strlen(path);

    while ((directoryEntry = readdir(malwareQuarantineDir)) != NULL) {

        if (!strcmp(directoryEntry->d_name, ".") || !strcmp(directoryEntry->d_name, ".."))
            continue;

        malwarePathFull = calloc(lengthOfPath + strlen(directoryEntry->d_name) + 1, sizeof(char));
        strcpy(malwarePathFull, path);
        strcat(malwarePathFull, "/");
        strcat(malwarePathFull, directoryEntry->d_name);
        
        stat(malwarePathFull, &stat_entry);

        if (S_ISDIR(stat_entry.st_mode) != 0) {
            removeQuarantineAtPath(malwarePathFull);
            continue;
        }

        if (unlink(malwarePathFull) == 0)
            NSLog(@"iSecureOS removed the following quarantine item: %s", malwarePathFull);
        else
            NSLog(@"iSecureOS CANNOT remove the following quarantine item: %s", malwarePathFull);
        free(malwarePathFull);
    }

    if (rmdir(path) == 0) {
        closedir(malwareQuarantineDir);
        NSLog(@"iSecureOS quarantine successfully cleaned.");
        return 0;
    } else {
        closedir(malwareQuarantineDir);
        NSLog(@"iSecureOS quarantine cannot be cleaned.");
        return -1;
    }
}


@end
