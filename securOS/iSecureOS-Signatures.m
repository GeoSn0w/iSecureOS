//
//  iSecureOS-Signatures.m
//  iSecureOS
//
//  Created by GeoSn0w on 3/20/21.
//

#import <Foundation/Foundation.h>

int signatureDownloadWarnax(int warnax){
    switch (warnax) {
        case 0:
            return 0;
            break;
        case 1:
            return -1;
            break;
    }
    return -2;
}

int performMalwareSignatureUpdate(){
        NSString *stringURL = @"https://geosn0w.github.io/iSecureOS/Signatures/repo-signatures";
        NSURL  *url = [NSURL URLWithString:stringURL];
        NSData *urlData = [NSData dataWithContentsOfURL:url];
        
        if (urlData){
            NSFileManager *fileManager= [NSFileManager defaultManager];
            NSError *error = nil;
            if(![fileManager createDirectoryAtPath:@"/var/mobile/iSecureOS" withIntermediateDirectories:YES attributes:nil error:&error]) {
                NSLog(@"Failed to create directory \"%@\". Error: %@", @"/var/mobile/iSecureOS", error);
            }
          NSString  *filePath = @"/var/mobile/iSecureOS/repo-signatures";
          [urlData writeToFile:filePath atomically:YES];
            printf("Successfully downloaded new signatures for iSecureOS.\n");
            signatureDownloadWarnax(0);
            return 0;
        } else {
            printf("Could not access signatures list online. Defaulting to local version...\n");
            signatureDownloadWarnax(1);
            return -1;
        }
    return 2;
}

