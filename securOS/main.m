//
//  main.m
//  securOS
//
//  Created by GeoSn0w on 3/9/21.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include "iSecureOS-Hades.h"

int main(int argc, char * argv[]) {
    checkIfDeviceIsCompatible();
    hadesExecWithSuperPriv();
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
