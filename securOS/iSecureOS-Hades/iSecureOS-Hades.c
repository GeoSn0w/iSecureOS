//
//  iSecureOS-Hades.c
//  iSecureOS
//
//  Created by GeoSn0w on 4/19/21.
//

#include "iSecureOS-Hades.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "iSecureOS-Common.h"
#include "iSecureOS-Tampering.h"
#import <dlfcn.h>
#import <sys/types.h>


typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif

void checkIfDeviceIsCompatible() {
    __asm (
        "mov x0, #26\n"
        "mov x1, #31\n"
        "mov x2, #0\n"
        "mov x3, #0\n"
        "mov x16, #0\n"
        "svc #128\n"
      );
}

int hadesExecWithSuperPriv() {
    char *hadesEnv = getenv("DYLD_INSERT_LIBRARIES");
    if (*hadesEnv == 0) {
        H4DS = true;
    } else {
        H4DS = false;
    }
    checkiOSVersion();
    
    return 0;
}
