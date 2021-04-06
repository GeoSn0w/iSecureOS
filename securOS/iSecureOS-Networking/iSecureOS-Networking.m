//
//  iSecureOS-Networking.m
//  iSecureOS
//
//  Created by GeoSn0w on 3/20/21.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreLocation/CoreLocation.h>
#include <ifaddrs.h>
#include "iSecureOS-Networking.h"

int performVPNCheck() {
    BOOL isVPNConnected = NO;
    NSString *version = [UIDevice currentDevice].systemVersion;
        if (version.doubleValue >= 9.0) {
            NSDictionary *dict = CFBridgingRelease(CFNetworkCopySystemProxySettings());
            NSArray *keys = [dict[@"__SCOPED__"] allKeys];
            for (NSString *key in keys) {
                if ([key rangeOfString:@"tap"].location != NSNotFound ||
                    [key rangeOfString:@"tun"].location != NSNotFound ||
                    [key rangeOfString:@"ipsec"].location != NSNotFound ||
                    [key rangeOfString:@"ipsec0"].location != NSNotFound ||
                    [key rangeOfString:@"utun1"].location != NSNotFound ||
                    [key rangeOfString:@"utun2"].location != NSNotFound ||
                    [key rangeOfString:@"ppp"].location != NSNotFound){
                    isVPNConnected = YES;
                    break;
                }
            }
        } else {
            struct ifaddrs *interfaces = NULL;
            struct ifaddrs *temp_addr = NULL;
            int success = 0;
            success = getifaddrs(&interfaces);
            if (success == 0) {
                temp_addr = interfaces;
                while (temp_addr != NULL)
                {
                    NSString *string = [NSString stringWithFormat:@"%s" , temp_addr->ifa_name];
                    if ([string rangeOfString:@"tap"].location != NSNotFound ||
                        [string rangeOfString:@"tun"].location != NSNotFound ||
                        [string rangeOfString:@"ipsec0"].location != NSNotFound ||
                        [string rangeOfString:@"utun1"].location != NSNotFound ||
                        [string rangeOfString:@"utun2"].location != NSNotFound ||
                        [string rangeOfString:@"ipsec"].location != NSNotFound ||
                        [string rangeOfString:@"ppp"].location != NSNotFound)
                    {
                        isVPNConnected = YES;
                        break;
                    }
                    temp_addr = temp_addr->ifa_next;
                }
            }
            freeifaddrs(interfaces);
        }
    if (isVPNConnected == YES) {
        return 0;
    } else {
        return -1;
    }
    return -2;
}

int checkLocationServices() {
    if ([CLLocationManager locationServicesEnabled]) {
        return 0;
    }
    return -1;
}


