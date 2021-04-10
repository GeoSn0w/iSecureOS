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
#include <CommonCrypto/CommonDigest.h>
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

#define vm_address_t mach_vm_address_t
#define tfp0 pwnage.kernel_port
#define slide pwnage.kernel_slide
#define kbase pwnage.kernel_base

int vulnerabilityCount = 0;
bool isPasscodeVulnerable = false;
bool isSSHPasswordVulnerable = false;
bool isProblematicReposPresent = false;
char *mostLikelyJailbreak;

// For Signatures
NSMutableArray * SecurityRiskRepos;
NSMutableArray *detectedMalware;

// For results
NSMutableArray * Vulnerabilities;
NSMutableArray * VulnerabilityDetails;
NSMutableArray * VulnerabilitySeverity;
NSMutableArray * MalwareDefinitions;
NSString *selectedVulnerabilityForDetails;
NSString *tweakInjectionPath;
UIColor *redColor;
UIColor *yellowColor;
UIColor *orangeColor;
UIColor *greenColor;

typedef struct kernel_data_t {
    mach_port_t kernel_port;
    mach_vm_address_t kernel_base;
    mach_vm_offset_t kernel_slide;
} kernel_data_t;

@interface securiOS_Logging () <UITableViewDelegate, UITableViewDataSource>

@end

@implementation securiOS_Logging

BOOL shouldScan = true;

- (void)viewDidLoad {
    [super viewDidLoad];
    if (@available(iOS 13.0, *)) {
            self.overrideUserInterfaceStyle = UIUserInterfaceStyleLight;
    }
    
    if (SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"13.0")){
        // iOS 12 lacks the modals you can close by draging down. We add a manual back button.
        _backButton12.hidden = NO;
    }
    
    printf("iSecureOS v1.17 by GeoSn0w (@FCE365)\n");
    printf("Initializing iSecureOS...\n", NULL);
    UITapGestureRecognizer *gestureRecognizer = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(dismissKeyboard)];
    [self.view addGestureRecognizer:gestureRecognizer];
        gestureRecognizer.cancelsTouchesInView = NO;
    
    // Beginning of UI Button Rounding
    _viewVulnerabilities.layer.cornerRadius = 22;
    _viewVulnerabilities.clipsToBounds = YES;
    _changeRootPassword.layer.cornerRadius = 19;
    _changeRootPassword.clipsToBounds = YES;
    // End of UI Rounding
    
    redColor = [UIColor redColor];
    yellowColor = [UIColor yellowColor];
    orangeColor = [UIColor orangeColor];
    greenColor = [UIColor greenColor];
    
    if (shouldScan == true){
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            dispatch_async(dispatch_get_main_queue(), ^{
                self.scanningLabel.text = @"Downloading definitons";
            });
            if ([self updateSignaturesDB] == 0){
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    fetchUserSettings();
                    [self iSecureOSInitMain];
                });
            } else {
                NSLog(@"Could not obtain and populate the signatures for iSecureOS.");
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.scanningLabel.text = @"Fatal error: Signatures.";
                });
            }
        });
    }
}

void fetchUserSettings() {
    NSString * ignoreVPNState = [[NSUserDefaults standardUserDefaults] objectForKey: @"VPN"];
    if ([ignoreVPNState isEqualToString:@"0"]){
        shouldNotScanVPN = false;
    } else if ([ignoreVPNState isEqualToString:@"1"]){
        shouldNotScanVPN = true;
    }
    
    NSString * ignoreCVEState = [[NSUserDefaults standardUserDefaults] objectForKey: @"CVE"];
    if ([ignoreCVEState isEqualToString:@"0"]){
        shouldNotScanCVE = false;
    } else if ([ignoreCVEState isEqualToString:@"1"]){
        shouldNotScanCVE = true;
    }
    return;
}

int populateDefinitionsToArrays() {
    int retvalRepo = populateVulnerableReposFromSignatures();
    int retvalMalware = populateMalwareDefinitionsFromSignatures();
    
    if (retvalRepo == 0 && retvalMalware == 0){
        NSLog(@"Successfully populated iSecureOS definitions. We're good.");
        return 0;
    } else {
        NSLog(@"Failed to populate iSecureOS definitions. App cannot continue.");
        return -1;
    }
}

- (int) updateSignaturesDB {
    int updateDefRetval = initializeDefinitionsAtPath();
    
    if (updateDefRetval != 0){
        NSLog(@"Failed to initialize iSecureOS Definitions.");
        self.scanningLabel.text = @"Failed to download signatures.";
        return -1;
    }
    
    int populateDefRetval = populateDefinitionsToArrays();
    
    if (populateDefRetval != 0){
        NSLog(@"Failed to populate iSecureOS Definitions.");
        self.scanningLabel.text = @"Could not load signatures.";
        return -2;
    }
    
    return 0;
}

- (void) dismissKeyboard {
     [self.view endEditing:YES];
}

int populateVulnerableReposFromSignatures() {
    SecurityRiskRepos = [[NSMutableArray alloc] init];
    NSString *repoDefinitionsPath = @"/var/mobile/iSecureOS/repo-signatures";
    NSError *repoFileErr;
    NSString *fileContentsUrls = [NSString stringWithContentsOfFile:repoDefinitionsPath encoding:NSUTF8StringEncoding error: &repoFileErr];
    SecurityRiskRepos = [[fileContentsUrls componentsSeparatedByString:@"\n"] mutableCopy];
    
    if (repoFileErr == nil) {
        printf("Successfully loaded Repo Signatures into iSecureOS\n");
        return 0;
    } else {
        printf("Failed to get the online version of the signatures. Will default to offline.\n");
        SecurityRiskRepos = [[iSecureOSDefaultingRepos componentsSeparatedByString:@","] mutableCopy];
        return 0;
    }
}

int populateMalwareDefinitionsFromSignatures() {
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

- (void) performCleanupSegue {
    shouldScan = false;
    
    _viewVulnerabilities.hidden = NO;
    if (isSSHPasswordVulnerable){
        _changeRootPassword.hidden = NO;
    }
    _scanningLabel.text = @"Finished scanning.";
    
    // Save the last scan report.
    NSString *path = @"/var/mobile/iSecureOS";
    NSURL *url = [NSURL URLWithString:[path stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLHostAllowedCharacterSet]]];
    url = [url URLByAppendingPathComponent:@"ScanResult.json"];
    NSError *e = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:Vulnerabilities options:NSJSONWritingPrettyPrinted error:&e];

    if (jsonData) {
        [jsonData writeToFile:url.path atomically:YES];
    }
    
    // Clean any temporary files used during scanning.
    remove("/var/mobile/iSecureOS/repo-signatures");
    remove("/var/mobile/iSecureOS/definitions.sec");
    remove("/Applications/iSecureOS.app/repo-signatures");
    
    return;
}

- (NSInteger) tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section{
    return [Vulnerabilities count];
}

- (UITableViewCell *) tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"secuiOSTableCell"];
    cell.textLabel.text = [Vulnerabilities objectAtIndex:(indexPath.row)];
    cell.detailTextLabel.text = [VulnerabilityDetails objectAtIndex:(indexPath.row)];
    [[cell imageView] setTintColor: [VulnerabilitySeverity objectAtIndex:(indexPath.row)]];
    [[cell textLabel] setNumberOfLines:0];
    [[cell textLabel] setLineBreakMode:NSLineBreakByWordWrapping];
    [[cell textLabel] setFont:[UIFont systemFontOfSize: 13.0]];
    
    return cell;
}

- (void) tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath{
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

- (void) updateUIProgressBar: (float) progress {
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIView animateWithDuration:1.5 animations:^{
            [self.scannProgressbar setProgress:progress animated:YES];
        }];
    });
    return;
}

- (void) iSecureOSInitMain {
    Vulnerabilities = [[NSMutableArray alloc] init];
    VulnerabilityDetails = [[NSMutableArray alloc] init];
    VulnerabilitySeverity = [[NSMutableArray alloc] init];
    
    kern_return_t kernelPortResult = KERN_SUCCESS;
    printf("Performing jailbreak probing...\n", NULL);
    
    [self updateUIProgressBar: 0.1];
    
    performJailbreakProbingAtPath();
    
    [self updateUIProgressBar: 0.5];

    kernelPortResult = get_kernelport(&pwnage);
        printf("[ i ] Testing to see if tfp0 / hsp4 is exported...\n");
            
    if (kernelPortResult) {
        printf("[ ! ] Failed to get kernel taskport: %s. Good.\n", mach_error_string(kernelPortResult));
    } else {
        printf("[VULNERABILITY] Kernel Task Port IS Exported. Disable it after running securiOS.\n\n");
        printf("[ i ] Kernel Task Port is 0x%x\n", tfp0);
    }
                
    [self updateUIProgressBar: 0.15];
    performSuspectRepoScanning();
    checkForUnsafeTweaks();

    tweakInjectionPath = @"/Library/MobileSubstrate/DynamicLibraries";
    [self scanForMalwareAtPath];
    [self updateUIProgressBar: 0.20];
        
    tweakInjectionPath = @"/usr/lib/TweakInject";
    [self scanForMalwareAtPath];
    [self updateUIProgressBar: 0.30];
    
    if (shouldPerformInDepthScan == true){
        dispatch_async(dispatch_get_main_queue(), ^{
            self.scanningLabel.text = @"Now Deep-scanning...";
        });
            
        tweakInjectionPath = @"/usr/bin/";
        [self scanForMalwareAtPath];
        [self updateUIProgressBar: 0.40];
            
        tweakInjectionPath = @"/usr/libexec/";
        [self scanForMalwareAtPath];
            
        tweakInjectionPath = @"/usr/sbin/";
        [self scanForMalwareAtPath];
            
        tweakInjectionPath = @"/usr/lib/";
        [self scanForMalwareAtPath];
        [self updateUIProgressBar: 0.50];
                    
        tweakInjectionPath = @"/bin/";
        [self scanForMalwareAtPath];
            
        tweakInjectionPath = @"/sbin/";
        [self scanForMalwareAtPath];
    }

    [self checkPasswordDefaulting];
    [self checkPasscodeProtectionStatus];

    [self updateUIProgressBar: 0.70];
    [self performLocationCheck];
    
    [self updateUIProgressBar: 0.75];
    if (shouldNotScanVPN != true){
        [self checkIfVPNIsActive];
    }
    
    sharedThreatLevel = checkActiveSSHConnection();
    if (sharedThreatLevel == 0 || sharedThreatLevel == 1){
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString * storyboardName = @"Main";
            UIStoryboard *storyboard = [UIStoryboard storyboardWithName:storyboardName bundle: nil];
            UIViewController * vc = [storyboard instantiateViewControllerWithIdentifier:@"ThreatMenu"];
            [self presentViewController:vc animated:YES completion:nil];
        });
    }
    
    if (shouldNotScanCVE != true){
        getCVEsForVersion();
    }
    [self updateUIProgressBar: 0.90];
    
    if ([Vulnerabilities count] == 0) {
        [Vulnerabilities addObject:@"There's nothing wrong! Yay!"];
        [VulnerabilityDetails addObject:@"The scan hasn't found anything suspicious, and according to the filters set in the app, you don't seem to have major vulnerabilities. Keep up!"];
        [VulnerabilitySeverity addObject: greenColor];
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIView animateWithDuration:1.5 animations:^{
            [self performCleanupSegue];
            self.currentFile.hidden = YES;
        }];
    });
    
    [self updateUIProgressBar: 1.0];
    
    return;
}

- (void) performLocationCheck {
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

- (void) checkIfVPNIsActive {
    int retval = performVPNCheck();
    switch (retval) {
        case 0:
            printf("Detected an enabled VPN. Great!");
            break;
        case -1:
            printf("There doesn't seem to be a VPN active on this device right now. You should consider a quality one, or build one yourself. These greatly improve the security of your device.");
            [Vulnerabilities addObject:@"You're not using a VPN"];
            [VulnerabilityDetails addObject:@"There doesn't seem to be a VPN active on this device right now. You should consider a quality one, or build one yourself. These greatly improve the security of your device. Be sure to get a quality, no LOGS VPN with preferably a transparent user data collection policies. Not all VPN providers are honest and you may end up worse than without one. Avoid free VPNs at all costs, as if the VPN is free, your data is usually the product being sold. Do your research first and don't just download whatever is on top on App Store."];
            [VulnerabilitySeverity addObject:yellowColor];
        default:
            break;
    }
}

// Passcode / FaceID / TouchID

- (void) checkPasscodeProtectionStatus {
    securiOS_Device_Security passcodeRetval = [self extractPasscodeStatusWithKeychain];
    
    switch (passcodeRetval) {
        case 1:
            printf("[ i ] Passcode is active on the device. Great!\n\n");
            break;
        case 2:
            printf("[VULNERABILITY] Passcode is NOT enabled on this device. That's BAD.\n\n");
            [Vulnerabilities addObject:@"Passcode not set!"];
            [VulnerabilityDetails addObject:@"This device does not have a Passcode set. Data is accessible to anybody with physical access."];
            [VulnerabilitySeverity addObject:orangeColor];
            break;
    }
    
    return;
}

void printUnsafeRepoWarning (const char *problematicRepo) {
    printf("[VULNERABILITY] %s is a problematic piracy repo which can contain malware, outdated tweaks or otherwise modified tweaks. You should remove it, and everything installed from it.\n\n", problematicRepo);
    return;
}

void printUnsafeTweakWarning (const char *problematicTweak) {
    printf("[VULNERABILITY] %s is a problematic tweak which can contain malware. Tweaks used to pirate Cydia tweaks, like CyDown, create botnets on your device to attempt to grab tweaks and share them with pirates from your UDID. In the case of LocaliAPStore, many applications detect this and may refuze to work and may ban you.\n\n", problematicTweak);
    return;
}

- (int) checkPasswordDefaulting {
    // Change our own permissions to be able to access /etc/master.passwd which is ROOT owned.
    setuid(0);
    setgid(0);
    
    if (getuid() != 0){
        printf("[ ! ] Could not assess the ROOT password. You are not root.\n");
        return -1;
    }
    
    FILE *filepointer;
    char *searchString="root:/smx7MYTQIi2M";
    filepointer = fopen("/etc/master.passwd", "r");
    char buf[100];
    
    while ((fgets(buf, 100, filepointer)!= NULL)) {
      if (strstr(buf, searchString)!= NULL) {
          printf("[VULNERABILITY] Your SSH password is the default, alpine! You should change it.\n\n");
          [Vulnerabilities addObject:@"Default SSH password detected."];
          [VulnerabilityDetails addObject:@"This device has the default alpine password for remote SSH access. You must change it."];
          [VulnerabilitySeverity addObject: redColor];
          isSSHPasswordVulnerable = true;
          fclose(filepointer);
          return -1;
      }
    }
    fclose(filepointer);
    printf("[ i ] Your SSH password does not seem to be the default, great!\n");
    
    return (0);
}

/*
 checkRepoInPackageManagerDB(...) takes a final int packageManager argument.
 It's:
 1 = Cydia
 2 = Sileo
 3 = Installer
 4 = Zebra
 Depending on which package manager you specify, the vulnerability message changes to tell the user in which package
 manager they have the bad repo.
 */

int checkRepoInPackageManagerDB(const char *whereToCheck, const char *repoToCheck, int packageManager) {
    FILE *filepointer;
    filepointer = fopen(whereToCheck, "r");
    char buf[100];
        
    if (filepointer) {
        while ((fgets(buf, 100, filepointer)!= NULL)) {
            if (strstr(buf, repoToCheck)!= NULL) {
                NSString * actual_vulnerability = [NSString stringWithCString:repoToCheck encoding:NSASCIIStringEncoding];
                NSString * packageManagerString = @"";
                        
                switch (packageManager) {
                    case 1:
                        packageManagerString = @" is an unsafe pirate repo. [In Cydia]";
                        break;
                    case 2:
                        packageManagerString = @" is an unsafe pirate repo. [In Sileo]";
                        break;
                    case 3:
                        packageManagerString = @" is an unsafe pirate repo. [In Installer]";
                        break;
                    case 4:
                        packageManagerString = @" is an unsafe pirate repo. [In Zebra]";
                        break;
                    }
                [Vulnerabilities addObject:[actual_vulnerability stringByAppendingString:packageManagerString]];
                [VulnerabilityDetails addObject:@"Pirate repos contain old, outdated and even modified or weaponized tweaks."];
                [VulnerabilitySeverity addObject:redColor];
            }
        }
        fclose(filepointer);
    }
    return 0;
}

int potentiallyMalwareRepoCheck (const char *repoToCheck) {
    checkRepoInPackageManagerDB("/etc/apt/sources.list.d/cydia.list", repoToCheck, 1);
    checkRepoInPackageManagerDB("/etc/apt/sources.list.d/sileo.sources", repoToCheck, 2);
    checkRepoInPackageManagerDB("/var/mobile/Library/Application Support/Installer/APT/sources.list", repoToCheck, 3);
    checkRepoInPackageManagerDB("/var/mobile/Library/Application Support/xyz.willy.Zebra/sources.list", repoToCheck, 4);
    return 0;
}

bool file_exists (char *filename) {
    struct stat  buffer;
    return (stat (filename, &buffer) == 0);
}

int performJailbreakProbingAtPath() {
    printf("Attempting to detect if the device is jailbroken...\n");
    FILE * filepath = fopen("/var/mobile/iSecureOS-Sandbox", "w");
    
    if (!filepath) {
        fclose(filepath);
        fprintf(stderr,"Random processes are running sandboxed. Will attempt to check further.\n");
        return -2;
    }
    
    printf("Detected sandbox escape. This device is likely jailbroken.\n");
    fclose(filepath);
    return 0;
}

int checkForUnsafeTweaks() {
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
void performSuspectRepoScanning() {
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

void respringDeviceNow() {
    const char * arguments = "backboardd";
    execprog("killall", &arguments);
    return;
}

int checkActiveSSHConnection() {
    // Check if an active root connection is found
    int rootAccess = warnaxActiveSSHConnection("sshd: root@ttys");
    
    if (rootAccess == 0) {
            [Vulnerabilities addObject:@"WARNING! Active root SSH Connection to this device."];
            [VulnerabilityDetails addObject:@"An active SSH connection is going on right now. If it's not you, this is BAD. It means that someone is right now connected via the network to this device and can exfiltrate files as they please. Change your root password and reboot your device. As ROOT, the attacker has even more power."];
            [VulnerabilitySeverity addObject: redColor];
        isSSHPasswordVulnerable = true;
            return 0; // ROOT
    }
    
    // Check if an active mobile connection is found
    int mobileAccess = warnaxActiveSSHConnection("sshd: mobile@ttys");
    
    if (mobileAccess == 0) {
            [Vulnerabilities addObject:@"WARNING! Active mobile SSH Connection to this device."];
            [VulnerabilityDetails addObject:@"An active SSH connection is going on right now. If it's not you, this is BAD. It means that someone is right now connected via the network to this device and can exfiltrate files as they please. Change your root and mobile password and reboot your device."];
            [VulnerabilitySeverity addObject: redColor];
        isSSHPasswordVulnerable = true;
            return 1; // mobile
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
    NSError *JsonWriteErr = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:Vulnerabilities options:NSJSONWritingPrettyPrinted error:&JsonWriteErr];

    if (jsonData) {
        [jsonData writeToFile:url.path atomically:YES];
    }
    
    if (JsonWriteErr == nil){
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Scan report saved"
                                                                       message:@"The scan report was saved to /var/mobile/iSecureOS/ScanResult.json"
                                   preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction * action) {}];

        [alert addAction:defaultAction];
        [self presentViewController:alert animated:YES completion:nil];
    }
    
}

- (int) scanForMalwareAtPath {
    _currentFile.hidden = NO;
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
    
            if ([self filePathSanityCheck: filetocheckpath] != -1) {
                    
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.currentFile.text = filetocheckpath;
                    self.scannProgressbar.progress += 0.0001f;
                });
                    
                NSData *data = [NSData dataWithContentsOfFile:filetocheckpath];
                uint8_t digest[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
                             
                NSMutableString* shaoutput = [NSMutableString  stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
                             
                for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
                    [shaoutput appendFormat:@"%02x", digest[i]];
                }
                
                NSString *hashsignature = shaoutput;
                if ([MalwareDefinitions containsObject:hashsignature]) {
                    int quarantineResult = [self quarantineMalwareAtPath: filetocheckpath];
            
                    if (quarantineResult == 0){
                        NSString *malwareMessageHeader = [NSString stringWithFormat:@"[Malware] File: %@ [QUARANTINED]", filetocheckpath];
                        NSString *malwareMessage = [NSString stringWithFormat:@"The file: %@ is a known malware binary file in the Jailbreak community and it can be used to remotely control, damage or otherwise affect your device. The file has automatically been quarantined for you and it's no longer executable. It's recommended that you remove any unsafe repos.", filetocheckpath];
                        [Vulnerabilities addObject: malwareMessageHeader];
                        [VulnerabilityDetails addObject: malwareMessage];
                        [VulnerabilitySeverity addObject: redColor];
                    } else {
                        NSString *malwareMessageHeader = [NSString stringWithFormat:@"[Malware] File: %@ [QUARANTINED]", filetocheckpath];
                        NSString *malwareMessage = [NSString stringWithFormat:@"The file: %@ is a known malware binary file in the Jailbreak community and it can be used to remotely control, damage or otherwise affect your device. \n\n We could not quarantine the file automatically. \n\nIt's recommended that you delete the file in cause, and remove any unsafe repos. A ROOT FS restore may also be indicated.", filetocheckpath];
                        [Vulnerabilities addObject: malwareMessageHeader];
                        [VulnerabilityDetails addObject: malwareMessage];
                        [VulnerabilitySeverity addObject: redColor];
                    }
                }
            }
        }
    }
    return 0;
}


- (int) quarantineMalwareAtPath: (NSString *) pathOfMalware {
    // Replace the Mach-O header with 0x69 0x53 0x51 0x41 (iSQA) (iSecureOS Quarantine).
    // This way the system can't open the binary by mistake (unrecognized file type).
    // It's still recommended that the file is deleted permanently, but if the user wants to keep it, this is safer.
    // New magic should look like 0x69, 0x53, 0x51, 0x51, 0x41
    
    // Set up the quarantine directory
    DIR* quarantineDirectory = opendir("/var/mobile/iSecureOS/Quarantine");
    if (quarantineDirectory) {
        closedir(quarantineDirectory);
    } else if (ENOENT == errno) {
        mkdir("/var/mobile/iSecureOS/Quarantine", 0666); // Create the quarantine with Read-Write, but no Execute perms.
    } else {
        NSLog(@"Cannot check Quarantine directory. Aborting...");
        return -1;
    }
    
    // Replace the Magic number of the file with ours. The system won't be able to recognize it's an executable.
    // Normal Magic is 0xFEEDFACF || 0xFEEDFACE || 0xCAFEBABE || 0xCFFAEDFE || 0xCEFAEDFE
    
    const char *malwarePath = [pathOfMalware UTF8String];
    
    FILE *malwareFilePath = fopen(malwarePath, "r+b" );
    fseek(malwareFilePath, 0, SEEK_SET);
    unsigned char newMagic[] = {0x69, 0x53, 0x51, 0x41};
    fwrite(&newMagic, sizeof(char), sizeof(newMagic), malwareFilePath);
    fclose(malwareFilePath);

    chmod(malwarePath, 0666); // Change the malware permission to be Readable, Writable, but not Executable.
    
    NSFileManager *fsManager = [NSFileManager defaultManager];
    NSString *malwareFileName = [[[NSFileManager defaultManager] displayNameAtPath:pathOfMalware] stringByResolvingSymlinksInPath];
    NSURL *malwareFileToMove = [NSURL fileURLWithPath:pathOfMalware];
    NSString *malwareNewName = [NSString stringWithFormat:@"%@.quarantine", malwareFileName];
    NSString *newmalwarepath = [NSString stringWithFormat:@"/var/mobile/iSecureOS/Quarantine/%@", malwareNewName];
    NSURL *quarantinePath = [NSURL fileURLWithPath:newmalwarepath];
    NSError *QuarantineMoveError;
    
    NSError *error;
    if ([[NSFileManager defaultManager] isDeletableFileAtPath: quarantinePath.path]) {
        BOOL success = [[NSFileManager defaultManager] removeItemAtPath: quarantinePath.path error:&error];
        if (!success) {
            NSLog(@"Error removing file at path: %@", error.localizedDescription);
        }
    }
    
    [fsManager moveItemAtURL: malwareFileToMove toURL: quarantinePath error: &QuarantineMoveError];
    
    if (QuarantineMoveError != nil){
        NSLog(@"An error has occured while moving the file to quarantine. Error: %@", QuarantineMoveError);
        return -1;
    }
    
    NSLog(@"Successfully quarantined %@", pathOfMalware);
    return 0;
}

- (IBAction)dismissModal12:(id)sender {
    // Looks like iOS 12 lacks the modals I use that you can just drag down to close,
    // thus making people get stuck on one window. This should fix that.
    
    [self dismissViewControllerAnimated:YES completion:nil];
}

int getCVEsForVersion() {
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
    return 0;
}

- (void) redirectNotificationHandle: (NSNotification *)nf {
    NSData *data = [[nf userInfo] objectForKey:NSFileHandleNotificationDataItem];
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    self.logmeeh.text = [NSString stringWithFormat:@"%@\n%@",self.logmeeh.text, str];
    NSRange lastLine = NSMakeRange(self.logmeeh.text.length - 1, 1);
    [self.logmeeh scrollRangeToVisible:lastLine];
    [[nf object] readInBackgroundAndNotify];
}

- (void) redirectSTD: (int)fd {
    setvbuf(stdout, nil, _IONBF, 0);
    NSPipe * pipe = [NSPipe pipe] ;
    NSFileHandle *pipeReadHandle = [pipe fileHandleForReading] ;
    dup2([[pipe fileHandleForWriting] fileDescriptor], fd) ;
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                               selector:@selector(redirectNotificationHandle:)
                                               name:NSFileHandleReadCompletionNotification
                                               object:pipeReadHandle];
    [pipeReadHandle readInBackgroundAndNotify];
}

- (int) filePathSanityCheck: (NSString*) filetocheckpath {
    if (![filetocheckpath containsString:@".plist"] &&
        ![filetocheckpath containsString:@".png"] &&
        ![filetocheckpath containsString:@".strings"] &&
        ![filetocheckpath containsString:@".jpg"] &&
        ![filetocheckpath containsString:@".db"] &&
        ![filetocheckpath containsString:@".gif"] &&
        ![filetocheckpath containsString:@".wav"] &&
        ![filetocheckpath containsString:@".txt"] &&
        ![filetocheckpath containsString:@".mp3"] &&
        ![filetocheckpath containsString:@".xml"] &&
        ![filetocheckpath containsString:@".json"] &&
        ![filetocheckpath containsString:@".jpeg"] &&
        ![filetocheckpath containsString:@".tiff"]) {
        return 0;
    } else {
        return -1;
    }
}
@end
