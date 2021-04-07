//
//  iSecureOS-Signatures.m
//  iSecureOS
//
//  Created by GeoSn0w on 3/20/21.
//

#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include "iSecureOS-Common.h"

#define CURRENT_VERSION 1.16

bool checkForAppUpdate() {
    NSString *appVersionPlist = @"https://geosn0w.github.io/iSecureOS-Definitions/Isabella/SystemVersion.plist";
    NSURL  *appVersionURL = [NSURL URLWithString: appVersionPlist];
    NSError *AppVersionError = nil;
    NSMutableDictionary *propertyListDict = [[NSMutableDictionary alloc] initWithContentsOfURL: appVersionURL error: &AppVersionError];
    if (AppVersionError != nil){
        NSLog(@"iSecureOS could not check for version status. Will assume no new version is available for now, but will trip the CANT_CHK_VER fuse.");
        CANT_CHK_VER = true;
        return false;
    }
    double NewestVersion = [[propertyListDict objectForKey:@"CurrentVersion"] floatValue];
    NSLog(@"%f", NewestVersion);
    return (fabs(CURRENT_VERSION - NewestVersion) < 0.01);
}

int performRepoSignatureUpdate() {
        NSString *stringURL = @"https://geosn0w.github.io/iSecureOS/Signatures/repo-signatures";
        NSURL  *url = [NSURL URLWithString:stringURL];
        NSData *urlData = [NSData dataWithContentsOfURL:url];
        
        if (urlData) {
            NSFileManager *fileManager= [NSFileManager defaultManager];
            NSError *error = nil;
            if(![fileManager createDirectoryAtPath:@"/var/mobile/iSecureOS" withIntermediateDirectories:YES attributes:nil error:&error]) {
                NSLog(@"Failed to create directory \"%@\". Error: %@", @"/var/mobile/iSecureOS", error);
            }
          NSString  *filePath = @"/var/mobile/iSecureOS/repo-signatures";
          [urlData writeToFile:filePath atomically:YES];
            NSLog(@"Successfully downloaded new signatures for iSecureOS.");
            return 0;
        } else {
            NSLog(@"Could not access signatures list online.");
            return -1;
        }
    
    return 2;
}

int performMalwareSignatureUpdate() {
        NSString *stringURL = @"https://geosn0w.github.io/iSecureOS/Signatures/definitions.hash";
        NSURL  *url = [NSURL URLWithString:stringURL];
        NSData *urlData = [NSData dataWithContentsOfURL:url];
    
        if (urlData){
            NSFileManager *fileManager= [NSFileManager defaultManager];
            NSError *error = nil;
            if(![fileManager createDirectoryAtPath:@"/var/mobile/iSecureOS" withIntermediateDirectories:YES attributes:nil error:&error]) {
                NSLog(@"Failed to create directory \"%@\". Error: %@", @"/var/mobile/iSecureOS", error);
            }
          NSString  *filePath = @"/var/mobile/iSecureOS/definitions.sec";
          [urlData writeToFile:filePath atomically:YES];
            NSLog(@"Successfully downloaded new malware signatures for iSecureOS.\n");
            return 0;
        } else {
            NSLog(@"Could not access malware signatures list online.\n");
            return -1;
        }
    
    return 2;
}

/*
 Returns 0 if everything is good.
 Returns -1 if Repo signatures couldn't be downloaded.
 Returns -2 if malware hashes could not be downloaded.
 Both should be considered fatal errors and the user should be notified on the main iSecureOS UI.
 */

int initializeDefinitionsAtPath() {
    int repoDefResponse = performRepoSignatureUpdate();
    int malwareDefResponse = performMalwareSignatureUpdate();
    
    switch (repoDefResponse) {
        case 0:
            switch (malwareDefResponse) {
                case 0:
                    NSLog(@"All good, both malware and repo definitions have been successfully obtained.");
                    return 0;
                case -1:
                    NSLog(@"Fatal Error: Could not fetch malware hashes from the server.");
                    return 0;
            }
        case -1:
            NSLog(@"Fatal Error: Could not fetch repo signatures from the server.");
            return -1;
    }
    return 2;
}
