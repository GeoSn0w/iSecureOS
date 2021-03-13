//
//  securiOS-Logging.m
//  securiOS
//
//  Created by GeoSn0w on 3/9/21.
//

#import "securiOS-Logging.h"
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

#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/cdefs.h>
#include <sys/queue.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/lock.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <mach-o/loader.h>
#include <mach/mach.h>

#include <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

#define vm_address_t mach_vm_address_t
#define tfp0 escalation.kernel_port
#define slide escalation.kernel_slide
#define kbase escalation.kernel_base

#define kalloc Kernel_alloc
#define kfree Kernel_free


//***********************************************
int vulnerabilityCount = 0;
bool isPasscodeVulnerable = false;
bool isSSHPasswordVulnerable = false;
bool isProblematicReposPresent = false;
//***********************************************


typedef struct escalation_data
{
    mach_port_t kernel_port;
    mach_vm_address_t kernel_base;
    mach_vm_offset_t kernel_slide;
} escalation_data_t;

@interface securiOS_Logging ()

@end

@implementation securiOS_Logging

- (void)viewDidLoad {
    [super viewDidLoad];
    _dismissLoggingButton.layer.cornerRadius = 22;
    _dismissLoggingButton.clipsToBounds = YES;
    [self redirectSTD:STDOUT_FILENO];
    [self initsecuriOS];
}
- (IBAction)dismissLoggingScreen:(id)sender {
    
}
escalation_data_t escalation = {};
kern_return_t get_kernelport(escalation_data_t* data)
{
    
    if(!data)
    {
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
    kern_return_t err = KERN_SUCCESS;
        printf("securiOS v1.0 by GeoSn0w (@FCE365)\n");
        printf("Initializing securiOS...\n", NULL);
        err = get_kernelport(&escalation);
        printf("[ i ] Testing to see if tfp0 / hsp4 is exported...\n");
        printf("[ i ] Kernel Task Port is 0x%x\n", tfp0);
        if(err) {
            printf("[ ! ] Failed to get kernel taskport: %s.\n", mach_error_string(err));
        } else {
            printf("[VULNERABILITY] Kernel Task Port IS Exported. Disable it after running securiOS.\n\n");
        }
        [self checkPasscodeProtectionStatus];
        [self checkPasswordDefaulting];
        // Performing repo sanity checks. This will check if the user has installed any problematic repos.
        if (potentiallyMalwareRepoCheck("cydia.kiiimo.org") == 0){
            printf("[VULNERABILITY] cydia.kiiimo.org is a problematic piracy repo which can contain malware, outdated tweaks or otherwise modified tweaks. You should remove it, and everything installed from it.\n\n");
        }
        if (potentiallyMalwareRepoCheck("repo.hackyouriphone.org") == 0){
            printf("[VULNERABILITY] repo.hackyouriphone.org is a problematic piracy repo which can contain malware, outdated tweaks or otherwise modified tweaks. You should remove it, and everything installed from it.\n\n");
        }
        // End repo sanity checks
        if (isProblematicReposPresent){
            printf("[VULNERABILITY] You have pirate repos installed in your Cydia.\n\n");
        } else {
            printf("[ i ] You do not seem to have problematic repos installed. GREAT!\n\n");
        }
}

- (void) checkPasscodeProtectionStatus{
    if ([self extractPasscodeStatusWithKeychain] == 0){
        printf("[ ! ] Could not detect if the device has a passcode!\n\n");
        vulnerabilityCount++;
        isPasscodeVulnerable = true;
    } else if ([self extractPasscodeStatusWithKeychain] == 1){
        printf("[ i ] Passcode is active on the device. Great!\n\n");
    } else if ([self extractPasscodeStatusWithKeychain] == 2){
        printf("[VULNERABILITY] Passcode is NOT enabled on this device. That's BAD.\n\n");
        vulnerabilityCount++;
        isPasscodeVulnerable = true;
    }
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
            vulnerabilityCount++;
            isSSHPasswordVulnerable = true;
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
            vulnerabilityCount++;
            isProblematicReposPresent = true;
            fclose(filepointer);
            return 0;
            break;
        }
      }
      fclose(filepointer);
      return -1;
}
@end
