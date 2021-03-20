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

#define vm_address_t mach_vm_address_t
#define tfp0 pwnage.kernel_port
#define slide pwnage.kernel_slide
#define kbase pwnage.kernel_base

#define kalloc Kernel_alloc
#define kfree Kernel_free


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

NSMutableArray * Vulnerabilities;
NSMutableArray * VulnerabilityDetails;
NSMutableArray * VulnerabilitySeverity;
NSString *selectedVulnerabilityForDetails;
NSTimer * uiProgressTime;
float duration;

char *mostLikelyJailbreak;

@implementation securiOS_Logging

- (void)viewDidLoad {
    [super viewDidLoad];
    UITapGestureRecognizer *gestureRecognizer = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(dismissKeyboard)];
        [self.view addGestureRecognizer:gestureRecognizer];
        gestureRecognizer.cancelsTouchesInView = NO;
    _viewVulnerabilities.layer.cornerRadius = 22;
    _viewVulnerabilities.clipsToBounds = YES;
    _viewScanLog.layer.cornerRadius = 19;
    _viewScanLog.clipsToBounds = YES;
    [self redirectSTD:STDOUT_FILENO];
    [self initsecuriOS];
}
-(void)updateProgress {
    duration += 0.1;
    _scannProgressbar.progress = (duration/5.0);

    if (_scannProgressbar.progress == 1)
    {
        [uiProgressTime invalidate];
        uiProgressTime = nil;
        _viewVulnerabilities.hidden = NO;
        _viewScanLog.hidden = NO;
        _scanningLabel.text = @"Finished scanning.";
    }
}

- (void)dismissKeyboard {
     [self.view endEditing:YES];
}
- (IBAction)changeRootPassword:(id)sender {
    if (_passwordField.text && _passwordField.text.length < 1){
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Oooops..."
                                   message:@"The password cannot be empty (unless you wanna brick the jailbreak, that is...)"
                                   preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction * action) {}];

        [alert addAction:defaultAction];
        [self presentViewController:alert animated:YES completion:nil];
    } else {
        if (_passwordField.text && _passwordField.text.length < 6){
            UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Ooops..."
                                       message:@"The password must be at least 6 characters long. Please try again."
                                       preferredStyle:UIAlertControllerStyleAlert];

            UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction * action) {}];

            [alert addAction:defaultAction];
            [self presentViewController:alert animated:YES completion:nil];
        } else {
            if ([_passwordField.text isEqualToString: _passwordVerificationField.text]) {
                NSString *newPassword = _passwordField.text;
                const char *passwordForFunc = [newPassword UTF8String];
                    if (hashPasswordAndPrepare(passwordForFunc) == 0){
                        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"ROOT Password Updated!"
                                                   message:@"Successfully updated the ROOT password to your own. Your device is already more secure now because any attempt of stray SSH via the network would require your password, rather than the default alpine. Congrats!"
                                                   preferredStyle:UIAlertControllerStyleAlert];

                        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Thank you!" style:UIAlertActionStyleDefault
                                                       handler:^(UIAlertAction * action) {}];

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
                        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Could not update ROOT Password"
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

-(NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section{
    return [Vulnerabilities count];
}

-(UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"secuiOSTableCell"];
    cell.textLabel.text = [Vulnerabilities objectAtIndex:(indexPath.row)];
    cell.detailTextLabel.text = [VulnerabilityDetails objectAtIndex:(indexPath.row)];
    [[cell textLabel] setNumberOfLines:0];
    [[cell textLabel] setLineBreakMode:NSLineBreakByWordWrapping];
    [[cell textLabel] setFont:[UIFont systemFontOfSize: 14.0]];
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
    [self presentViewController:alert animated:YES completion:nil];

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
    
    self.securiOSLoggingWindow.text = [NSString stringWithFormat:@"%@\n%@",self.securiOSLoggingWindow.text, str];
    NSRange lastLine = NSMakeRange(self.securiOSLoggingWindow.text.length - 1, 1);
    [self.securiOSLoggingWindow scrollRangeToVisible:lastLine];
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
- (void) initsecuriOS {
        Vulnerabilities = [[NSMutableArray alloc] init];
        VulnerabilityDetails = [[NSMutableArray alloc] init];
        VulnerabilitySeverity = [[NSMutableArray alloc] init];
        kern_return_t oskernfail = KERN_SUCCESS;
        printf("iSecureOS v1.0 by GeoSn0w (@FCE365)\n");
        printf("Initializing securiOS...\n", NULL);
        printf("Performing jailbreak probing...\n", NULL);
    _scannProgressbar.progress  += 1;
        int jailbreakProbing = performJailbreakProbingAtPath();
        switch (jailbreakProbing) {
            case 0:
                oskernfail = get_kernelport(&pwnage);
                printf("[ i ] Testing to see if tfp0 / hsp4 is exported...\n");
                if(oskernfail) {
                    printf("[ ! ] Failed to get kernel taskport: %s. Good.\n", mach_error_string(oskernfail));
                } else {
                    printf("[VULNERABILITY] Kernel Task Port IS Exported. Disable it after running securiOS.\n\n");
                    printf("[ i ] Kernel Task Port is 0x%x\n", tfp0);
                }
                
                performSuspectRepoScanning();
                checkForUnsafeTweaks();
                [self checkForOutdatedPackages];
                [self checkPasswordDefaulting];
                break;
            case 1:
                printf("This device appears to be jailbroken, but it's not in the jailbroken state. Please enable the jailbreak first, and then run iSecureOS.\n");
                [Vulnerabilities addObject:@"Could not probe!"];
                [VulnerabilityDetails addObject:@"The device is not in jailbroken state. Can't probe."];
                [_securiOSTableView reloadData];
                break;
            case 2:
                printf("This device is not jailbroken. iSecureOS can only perform a very small amount of checks.");
                [Vulnerabilities addObject:@"Could not probe!"];
                [VulnerabilityDetails addObject:@"The device is not jailbroken. Cannot assess vulnerabilities."];
                break;
                
            default:
                printf("This device is not jailbroken. iSecureOS can only perform a very small amount of checks.");
                [Vulnerabilities addObject:@"Could not probe!"];
                [VulnerabilityDetails addObject:@"The device is not jailbroken. Cannot assess vulnerabilities."];
                break;
        }
        [self checkPasscodeProtectionStatus];
        uiProgressTime = [NSTimer scheduledTimerWithTimeInterval:0.1 target:self selector:@selector(updateProgress) userInfo:nil repeats:YES];
}

- (void) checkPasscodeProtectionStatus{
    if ([self extractPasscodeStatusWithKeychain] == 0){
        printf("[ ! ] Could not detect if the device has a passcode!\n\n");
        [Vulnerabilities addObject:@"Cannot detect if passcode is set."];
        [VulnerabilityDetails addObject:@"This device may not have a Passcode set. Data may be accessible to anybody with physical access."];
    } else if ([self extractPasscodeStatusWithKeychain] == 1){
        printf("[ i ] Passcode is active on the device. Great!\n\n");
    } else if ([self extractPasscodeStatusWithKeychain] == 2){
        printf("[VULNERABILITY] Passcode is NOT enabled on this device. That's BAD.\n\n");
        [Vulnerabilities addObject:@"Passcode not set!"];
        [VulnerabilityDetails addObject:@"This device does not have a Passcode set. Data is accessible to anybody with physical access."];
    }
    return;
}

void printUnsafeRepoWarning(char *problematicRepo){
    printf("[VULNERABILITY] %s is a problematic piracy repo which can contain malware, outdated tweaks or otherwise modified tweaks. You should remove it, and everything installed from it.\n\n", problematicRepo);
    return;
}

void printUnsafeTweakWarning(char *problematicTweak){
    printf("[VULNERABILITY] %s is a problematic tweak which can contain malware. Tweaks used to pirate Cydia tweaks, like CyDown, create botnets on your device to attempt to grab tweaks and share them with pirates from your UDID. In the case of LocaliAPStore, many applications detect this and may refuze to work and may ban you.\n\n", problematicTweak);
    return;
}
- (int) checkPasswordDefaulting {
      FILE *filepointer;
      char *searchString="root:/smx7MYTQIi2M";
      filepointer = fopen("/etc/passwd", "r");
      char buf[100];
      while((fgets(buf, 100, filepointer)!=NULL)) {
        if(strstr(buf, searchString)!=NULL) {
            printf("[VULNERABILITY] Your SSH password is the default, alpine! You should change it.\n\n");
            [Vulnerabilities addObject:@"Default SSH password detected."];
            [VulnerabilityDetails addObject:@"This device has the default alpine password for remote SSH access. You must change it."];
            fclose(filepointer);
            return -1;
            break;
        }
      }
      fclose(filepointer);
      printf("[ i ] Your SSH password does not seem to be the default, great!\n");
      return (0);
}

int potentiallyMalwareRepoCheck(char *repoToCheck) {
      FILE *filepointer;
      filepointer = fopen("/etc/apt/sources.list.d/cydia.list", "r");
      char buf[100];
      while((fgets(buf, 100, filepointer)!=NULL)) {
        if(strstr(buf, repoToCheck)!=NULL) {
            NSString * actual_vulnerability = [NSString stringWithCString:repoToCheck encoding:NSASCIIStringEncoding];
            [Vulnerabilities addObject:[actual_vulnerability stringByAppendingString:@" is an unsafe pirate repo."]];
            [VulnerabilityDetails addObject:@"Pirate repos contain old, outdated and even modified or weaponized tweaks."];
            fclose(filepointer);
            return 0;
            break;
        }
      }
      fclose(filepointer);
      return 1;
}

bool file_exists (char *filename) {
  struct stat   buffer;
  return (stat (filename, &buffer) == 0);
}

int performJailbreakProbingAtPath(){
    int result = 2;
    printf("Attempting to detect if the device is jailbroken...\n");
    FILE * f = fopen("/var/mobile/iSecureOS", "w");
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
    } else if (file_exists("/.bit_of_fun")){
        
    }
    
    return result;
}
int checkForUnsafeTweaks(){
    if(file_exists("/Library/MobileSubstrate/DynamicLibraries/CyDown.dylib" )) {
        printUnsafeTweakWarning("CyDown");
        [Vulnerabilities addObject:@"CyDown is an unsafe pirate tweak / Botnet."];
        [VulnerabilityDetails addObject:@"This is a pirate tweak used to get paid tweaks for free. There are reports in the community from developers (LaughingQuoll et al.), that the tweak acts as a botnet and uses your device / UDID to grab tweaks from Packix and other legitimate repos in your name, and then share them with pirates. It's advised to uninstall it for your safety."];
    }
    if(file_exists("/Library/MobileSubstrate/DynamicLibraries/LocalIAPStore.dylib") || file_exists("/Library/MobileSubstrate/DynamicLibraries/LocalIAPStore13.dylib")) {
        printUnsafeTweakWarning("LocaliAPStore");
        [Vulnerabilities addObject:@"LocaliAPStore is an unsafe pirate tweak that can get you banned."];
        [VulnerabilityDetails addObject:@"LocaliAPStore is a pirate repo that makes some applications believe you made a real in-app purchase / microtransaction. Many applications are nowadays immune to it, but may ban you because you have it installed."];
    }
    return 0;
}
void performSuspectRepoScanning(){
    // Performing repo sanity checks. This will check if the user has installed any problematic repos.
    if (potentiallyMalwareRepoCheck("cydia.kiiimo.org") == 0){
        printUnsafeRepoWarning("cydia.kiiimo.org");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("repo.hackyouriphone.org") == 0){
        printUnsafeRepoWarning("repo.hackyouriphone.org");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("repo.xarold.com")){
        printUnsafeRepoWarning("repo.xarold.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("repo.biteyourapple.net") == 0){
        printUnsafeRepoWarning("repo.biteyourapple.net");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("sinfuliphonerepo.com") == 0){
        printUnsafeRepoWarning("sinfuliphonerepo.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("cydia.iphonecake.com") == 0){
        printUnsafeRepoWarning("cydia.iphonecake.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("repo.insanelyi.com") == 0){
        printUnsafeRepoWarning("repo.insanelyi.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("idwaneo.org") == 0){
        printUnsafeRepoWarning("idwaneo.org");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("ihackstore.com") == 0){
        printUnsafeRepoWarning("ihackstore.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("ihacksrepo.com") == 0){
        printUnsafeRepoWarning("ihacksrepo.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("xsellize.com") == 0){
        printUnsafeRepoWarning("xsellize.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("pulandres") == 0){
        printUnsafeRepoWarning("Pulandres");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("idevicehacked.com") == 0){
        printUnsafeRepoWarning("idevicehacked.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("repo.appvv.com") == 0){
        printUnsafeRepoWarning("repo.appvv.com");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("julioverne.github.io") == 0){
        printUnsafeRepoWarning("julioverne.github.io");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("mainrepo.org") == 0){
        printUnsafeRepoWarning("mainrepo.org");
        isProblematicReposPresent = true;
    }
    if (potentiallyMalwareRepoCheck("rejail.ru") == 0){
        printUnsafeRepoWarning("rejail.ru");
        isProblematicReposPresent = true;
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
                 int tweaksToBeUpdated = 0;
                 fscanf (f, "%d", &tweaksToBeUpdated);
                 while (!feof (f))
                   {
                     printf ("%d ", tweaksToBeUpdated);
                     fscanf (f, "%d", &tweaksToBeUpdated);
                   }
                 fclose (f);
               if (tweaksToBeUpdated == 0){
                   printf("[ i ] No outdated tweaks detected! Great! (Ignores the ones you specifically downgraded.)\n");
               } else {
                   printf("[ ! ] There are tweaks that need to be upgraded! It's recommended that you always get the latest version of the tweaks.\n");
                   NSString *message = [NSString stringWithFormat:@"You have %d outdated tweaks! Please update them.\n", tweaksToBeUpdated];
                   [Vulnerabilities addObject:message];
                   [VulnerabilityDetails addObject:@"It's important to keep your tweaks up to date to ensure you get the latest bug fixes and security improvements for your tweaks. Many tweaks get fixed daily and updates are being pushed, especially for stability reasons. Navigate to your favorite Package Manager and update your tweaks.\n"];
               }
           } else {
               printf("Could not parse amount of outdated packages...\n");
           }
    });
}

- (IBAction)secureThisDevice:(id)sender {
}
@end
