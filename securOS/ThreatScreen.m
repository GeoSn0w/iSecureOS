//
//  ThreatScreen.m
//  iSecureOS
//
//  Created by GeoSn0w on 3/21/21.
//

#import "ThreatScreen.h"
#import <AudioToolbox/AudioServices.h>

@interface ThreatScreen ()

@end

@implementation ThreatScreen
SystemSoundID audioEffect;
- (void)viewDidLoad {
    [super viewDidLoad];
    _changeRootAndMobilePass.layer.cornerRadius = 18;
    _changeRootAndMobilePass.clipsToBounds = YES;
    
    NSString *message;
    NSString *ThreatLevelFromPrefs = [[NSUserDefaults standardUserDefaults]
        stringForKey:@"ThreatLevel"];
    
    int threatLevel = [ThreatLevelFromPrefs intValue];
    
    switch (threatLevel) {
        case 0:
            message = @"An active SSH connection has been detected on this device. This means that someone is currently on your device via the network. If it's you, connected from your PC, then that is okay. However, if this is not you, it's crucial to change your SSH password and reboot the device now.";
            break;
            
        case 1:
            message = @"An active SSH connection has been detected on this device as user MOBILE. This means that someone is currently on your device via the network. If it's you, connected from your PC, then that is okay. However, if this is not you, it's crucial to change your SSH password and reboot the device now.";
        case 2:
            message = @"An attempted SSH connection has been detected on this device as user MOBILE. This means that someone is currently trying to login via the network to your device, possibly trying various passwords. They did not manage to connect just yet, however, if this is not you, it's crucial to change your SSH password and reboot the device now.";
        case 3:
            message = @"An attempted SSH connection has been detected on this device as user ROOT. This means that someone is currently trying to login via the network to your device, possibly trying various passwords. They did not manage to connect just yet, however, if this is not you, it's crucial to change your SSH password and reboot the device now.";
    }
    
    _ThreatMessage.text = message;
    
    NSString *path  = [[NSBundle mainBundle] pathForResource:@"threat-detection" ofType:@"mp3"];
    NSURL *pathURL = [NSURL fileURLWithPath : path];

    AudioServicesCreateSystemSoundID((__bridge CFURLRef) pathURL, &audioEffect);
    AudioServicesPlaySystemSound(audioEffect);
    AudioServicesAddSystemSoundCompletion(audioEffect, nil, nil, playSoundFinished, (void*) CFBridgingRetain(self));
    
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"ThreatLevel"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

void playSoundFinished (SystemSoundID sound, void *data) {
    AudioServicesDisposeSystemSoundID(audioEffect); // We cleanup after iSecureOS' sound effect.
}
- (IBAction)changePasswordThreat:(id)sender {
    NSString *valueToSave = @"1";
    [[NSUserDefaults standardUserDefaults] setObject:valueToSave forKey:@"ShouldReboot"];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString * storyboardName = @"Main";
        UIStoryboard *storyboard = [UIStoryboard storyboardWithName:storyboardName bundle: nil];
        UIViewController * vc = [storyboard instantiateViewControllerWithIdentifier:@"RootPasswd"];
        [self presentViewController:vc animated:YES completion:nil];
    });
}
- (IBAction)thatwasMeDismiss:(id)sender {
    [self dismissViewControllerAnimated:YES completion:nil];
}

@end
