//
//  iSecureOS-Security.m
//  iSecureOS
//
//  Created by GeoSn0w on 3/20/21.
//

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <unistd.h>
#include "iSecureOS-Security.h"
#include <spawn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int failReason = 0;
char *password_staging;

int hashPasswordAndPrepare(const char *newPassword){
    setuid(0);
    setgid(0);
    NSString *passwordFromUser = [NSString stringWithUTF8String:newPassword];
    NSArray<NSString *> *characterSet =
            @[@"a", @"b", @"c", @"d", @"e", @"f", @"g", @"h", @"i", @"j", @"k", @"l", @"m", @"n", @"o", @"p", @"q", @"r", @"s", @"t", @"u", @"v", @"w", @"x", @"y", @"z", @"A", @"B", @"C", @"D", @"E", @"F", @"G", @"H", @"I", @"J", @"K", @"L", @"M", @"N", @"O", @"P", @"Q", @"R", @"S", @"T", @"U", @"V", @"W", @"X", @"Y", @"Z", @"0", @"1", @"2", @"3", @"4", @"5", @"6", @"7", @"8", @"9", @".", @"/"];
    NSString *salt_prefix = characterSet[arc4random() % characterSet.count];
    NSString *salt_suffix = characterSet[arc4random() % characterSet.count];
    NSString *ReadySalt = [NSString stringWithFormat:@"%@%@", salt_prefix, salt_suffix];
    password_staging = crypt([passwordFromUser  UTF8String], [ReadySalt UTF8String]);
    printf("New password hash: %s\n", password_staging);
    if (appendChangesToFileSystem() == 0){
        switch (failReason) {
            case 0:
                printf("Successfully appended new ROOT Password!\n");
                return 0;
                break;
            case 1:
                printf("Could not append new password because the master file is not accessible.\n");
                return -1;
                break;
            case 2:
                printf("Could not append new password because the master file cannot be written to.\n");
                return -2;
                break;
        }
    }
    return -1;
}
int setFail(int why);
int appendChangesToFileSystem(){
    //Get the obligatory root, master.passwd isn't even visible to mobile...
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *masterPath = @"/etc/master.passwd";
        NSError *masterContentError;
        NSString *originalMaster = [NSString stringWithContentsOfFile:masterPath encoding:NSUTF8StringEncoding error:&masterContentError];
            if (!originalMaster) {
                NSLog(@"%@", [masterContentError localizedDescription]);
                setFail(1);
            } else {
                NSString *newpass = [NSString stringWithUTF8String:password_staging];
                // Only replace the password if the has matches that of "alpine".
                NSString *replacedString = [originalMaster stringByReplacingOccurrencesOfString:@"/smx7MYTQIi2M"
                                                               withString:newpass];

                NSString *stringFilepath = @"/etc/master.passwd";
                NSError *masterWriteError;
                [replacedString writeToFile:stringFilepath atomically:YES encoding:NSWindowsCP1250StringEncoding error:&masterWriteError];
                if (masterWriteError != nil){
                    NSLog(@"%@", masterWriteError);
                    setFail(2);
                } else {
                    setFail(0);
                }
            }
    });
    return 0;
}
int setFail(int why){
    switch (why){
        case 1:
            failReason = 1;
            break;
        case 2:
            failReason = 2;
        case 0:
            failReason = 0;
            break;
    }
    return 0;
}

bool check_file_presence (char *filename) {
  struct stat   buffer;
  return (stat (filename, &buffer) == 0);
}

int warnaxActiveSSHConnection(char *ActiveSSHSignature) {
    if (check_file_presence("/usr/sbin/sshd") == true){
        int whatTheHellsGoingOnUpInHere = 99;
        char command[100];
        strcpy(command, "ps -ax | grep sshd: | grep -v 'grep sshd' > /var/mobile/iSecureOS/ps" );
        //system(command); <-- Uncomment this if you wanna compile the app, after you modify Xcode's header.
        
          FILE * filePointer = fopen("/var/mobile/iSecureOS/ps", "r");
          char buf[150];
              while((fgets(buf, 150, filePointer)!= NULL)) {
                    if(strstr(buf, ActiveSSHSignature)!= NULL) {
                          whatTheHellsGoingOnUpInHere = 0;  //Someone is SSH as ROOT. Fuck...
                          break;
                    }
              }
            fclose(filePointer);
            if (remove("/var/mobile/iSecureOS/ps") != 0){
                printf("What... Could not delete the temporary file.\n");
            }
            if (whatTheHellsGoingOnUpInHere == 0) {
                return 0;
            } else if (whatTheHellsGoingOnUpInHere == 99) {
                return 1;
            }
    } else {
        printf("OpenSSH not installed, no point to check.");
        return 1;
    }
    return -2;
}

int printFailReason(char * reason){
    printf("[!] Error: %s\n", reason);
    return 0;
}
