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
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
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
                NSLog(@"%@", masterWriteError);
                if (masterWriteError != nil){
                    setFail(2);
                }
            }
    });
    return -1;
}
int setFail(int why){
    NSLog(@"Got a fail!\n");
    switch (why){
        case 1:
            failReason = 1;
            break;
        case 2:
            failReason = 2;
        default:
            failReason = 0;
            break;
    }
    return 0;
}

int checkHostsFileForModifications(){
    if (getuid() != 0){
        setuid(0); // root
        setgid(0); // wheel
    }
    NSString *string= [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil];
    NSArray *array = [string componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    NSLog(@"%@",array);
                        
    
    return 0;
}
