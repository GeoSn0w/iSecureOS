//
//  iSecureOS-ROOT.m
//  iSecureOS
//
//  Created by GeoSn0w on 3/21/21.
//

#import "iSecureOS-ROOT.h"
#include "iSecureOS-Security.h"
#include "SystemReboot.h"

@interface iSecureOS_ROOT ()

@end

@implementation iSecureOS_ROOT

int shouldReboot;
- (void)viewDidLoad {
    [super viewDidLoad];
    UITapGestureRecognizer *gestureRecognizer = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(dismissKeyboard)];
    [self.view addGestureRecognizer:gestureRecognizer];
        gestureRecognizer.cancelsTouchesInView = NO;
    _changePassword.layer.cornerRadius = 22;
    _changePassword.clipsToBounds = YES;
    NSString *ThreatShouldRebootAfterSSHPwd = [[NSUserDefaults standardUserDefaults]
        stringForKey:@"ShouldReboot"];
    
    shouldReboot = [ThreatShouldRebootAfterSSHPwd intValue];
}
- (IBAction)changePassword:(id)sender {
    if (_updatedPasswd.text && _updatedPasswdRecheck.text.length < 1){
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Oooops..."
                                   message:@"The password cannot be empty (unless you wanna brick the jailbreak, that is...)"
                                   preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction * action) {}];

        [alert addAction:defaultAction];
        [self presentViewController:alert animated:YES completion:nil];
        
    } else {
        if (_updatedPasswd.text && _updatedPasswd.text.length < 6){
            UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Ooops..."
                                       message:@"The password must be at least 6 characters long. Please try again."
                                       preferredStyle:UIAlertControllerStyleAlert];

            UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction * action) {}];

            [alert addAction:defaultAction];
            [self presentViewController:alert animated:YES completion:nil];
        } else {
            if ([_updatedPasswd.text isEqualToString: _updatedPasswdRecheck.text]) {
                NSString *newPassword = _updatedPasswd.text;
                const char *passwordForFunc = [newPassword UTF8String];
                    if (hashPasswordAndPrepare(passwordForFunc) == 0 && shouldReboot != 1){
                        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"ROOT Password Updated!"
                                                   message:@"Successfully updated the ROOT password to your own. Your device is already more secure now because any attempt of stray SSH via the network would require your password, rather than the default alpine. Congrats!"
                                                   preferredStyle:UIAlertControllerStyleAlert];

                        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Thank you!" style:UIAlertActionStyleDefault
                                                       handler:^(UIAlertAction * action) {}];

                        [alert addAction:defaultAction];
                        [self presentViewController:alert animated:YES completion:nil];
                    } else if (hashPasswordAndPrepare(passwordForFunc) == 0 && shouldReboot == 1){
                        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"ROOT Password Updated!"
                                                   message:@"Successfully updated the ROOT password to your own. Since this was prompted by a threat level, you need to reboot to disconnect the attacker. After closing this dialog, your device will reboot in NON-Jailbroken mode. Just re-jailbreak and keep an eye on your network."
                                                   preferredStyle:UIAlertControllerStyleAlert];

                        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Reboot Device" style:UIAlertActionStyleDefault
                                                       handler:^(UIAlertAction * action) {
                            reboot(RB_QUICK);
                        }];

                        [alert addAction:defaultAction];
                        [self presentViewController:alert animated:YES completion:nil];
                    } else if (hashPasswordAndPrepare(passwordForFunc) == -1) {
                        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Could not update ROOT Password"
                                                   message:@"It looks like, for some reason, iSecureOS doesn't run as ROOT or doesn't have access to the master.passwd file."
                                                   preferredStyle:UIAlertControllerStyleAlert];

                        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                                       handler:^(UIAlertAction * action) {}];

                        [alert addAction:defaultAction];
                        [self presentViewController:alert animated:YES completion:nil];
                    } else if (hashPasswordAndPrepare(passwordForFunc) == -2) {
                        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Could not update ROOT user Password"
                                                   message:@"While iSecureOS could successfully access the master.passwd file, the system has blocked the attempt to write to it. This is likely a permissions issue."
                                                   preferredStyle:UIAlertControllerStyleAlert];

                        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                                       handler:^(UIAlertAction * action) {}];

                        [alert addAction:defaultAction];
                        [self presentViewController:alert animated:YES completion:nil];
                    }
                } else {
                    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Ooops..."
                                               message:@"Sorry, but the passwords you entered do not match. Please type the same password in both fields. Also, make sure you can remember it later."
                                               preferredStyle:UIAlertControllerStyleAlert];

                    UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Let me try again." style:UIAlertActionStyleDefault
                                                   handler:^(UIAlertAction * action) {}];

                    [alert addAction:defaultAction];
                    [self presentViewController:alert animated:YES completion:nil];
                }
        }
    }
}

- (void) dismissKeyboard {
     [self.view endEditing:YES];
}

@end
