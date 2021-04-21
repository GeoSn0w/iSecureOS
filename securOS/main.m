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
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
