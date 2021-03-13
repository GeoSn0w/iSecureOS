//
//  securiOS_Tampering.m
//  securiOS
//
//  Created by GeoSn0w on 3/12/21.
//  Thanks: avltree9798 for their isJailbroken Open Source snippets.

#import <Foundation/Foundation.h>
#import "securiOS-Tampering.h"
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <TargetConditionals.h>

#define A(c)            (c) - 0x19

const char* checklibPresence(const char* X, const char* Y)
{
    if (*Y == '\0')
        return X;

    for (int i = 0; i < strlen(X); i++)
    {
        if (*(X + i) == *Y)
        {
            char* ptr = checklibPresence(X + i + 1, Y + 1);
            return (ptr) ? ptr - 1 : NULL;
        }
    }

    return NULL;
}

char* string_dec_clr(char* str){
    do { char *p = str;  while (*p) *p++ += 0x19; } while (0);
    return str;
}

char* decryptString(char* str){
    str = string_dec_clr(str);
    str[strlen(str)]='\0';
    return str;
}

BOOL checkTampering(){
    int i=0;
    while(true){
        const char *libInjectedName = _dyld_get_image_name(i++);
        if(libInjectedName==NULL){
            break;
        }
        if (libInjectedName != NULL) {
            char libsubstitute[] = {A('l'),A('i'),A('b'),A('s'),A('u'),A('b'),A('s'),A('t'),A('i'),A('t'),A('u'),A('t'),A('e'),A('.'),A('d'),A('y'),A('l'),A('i'),A('b'),0
            };
            char tweakinject[] = {A('R'),A('w'),A('e'),A('a'),A('k'),A('I'),A('n'),A('j'),A('e'),A('c'),A('t'),A('.'),A('d'),A('y'),A('l'),A('i'),A('b'),0
            };
            
            char cyinjectHide[] = {
                A('c'),
                A('y'),
                A('i'),
                A('n'),
                A('j'),
                A('e'),
                A('c'),
                A('t'),
                0
            };
            char libcycriptHide[] = {
                A('l'),
                A('i'),
                A('b'),
                A('c'),
                A('y'),
                A('c'),
                A('r'),
                A('i'),
                A('p'),
                A('t'),
                0
            };
            
            char libfridaHide[] = {
                A('F'),
                A('r'),
                A('i'),
                A('d'),
                A('a'),
                A('G'),
                A('a'),
                A('d'),
                A('g'),
                A('e'),
                A('t'),
                0
            };
            char zzzzLibertyDylibHide[] = {
                A('z'),
                A('z'),
                A('z'),
                A('z'),
                A('L'),
                A('i'),
                A('b'),
                A('e'),
                A('r'),
                A('t'),
                A('y'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            char sslkillswitch2dylib[] = {
                A('S'),
                A('S'),
                A('L'),
                A('K'),
                A('i'),
                A('l'),
                A('l'),
                A('S'),
                A('w'),
                A('i'),
                A('t'),
                A('c'),
                A('h'),
                A('2'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char zeroshadowdylib[] = {
                A('0'),
                A('S'),
                A('h'),
                A('a'),
                A('d'),
                A('o'),
                A('w'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char mobilesubstratedylib[] = {
                A('M'),
                A('o'),
                A('b'),
                A('i'),
                A('l'),
                A('e'),
                A('S'),
                A('u'),
                A('b'),
                A('s'),
                A('t'),
                A('r'),
                A('a'),
                A('t'),
                A('e'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            
            char libsparkapplistdylib[] = {A('l'),A('i'),A('b'),A('s'),A('p'),A('a'),A('r'),A('k'),A('a'),A('p'),A('p'),A('l'),A('i'),A('s'),A('t'),A('.'),A('d'),A('y'),A('l'),A('i'),A('b'),0
            };
            
            char SubstrateInserterdylib[] = {
                A('S'),A('u'),A('b'),A('s'),A('t'),A('r'),A('a'),A('t'),A('e'),A('I'),A('n'),A('s'),A('e'),A('r'),A('t'),A('e'),A('r'),A('.'),A('d'),A('y'),A('l'),A('i'),A('b'),0
            };
            
            char zzzzzzUnSubdylib[] = {
                A('z'), A('z'), A('z'),A('z'),A('z'),A('z'),A('U'),A('n'),A('S'),A('u'),A('b'),A('.'),A('d'),A('y'),A('l'),A('i'),A('b'),0
                
            };
            
            char kor[] = {A('.'),A('.'),A('.'),A('!'),A('@'),A('#'),0
            };
            char cephei[] = {
                A('/'),A('u'),A('s'),A('r'),A('/'),A('l'),A('i'),A('b'),A('/'),A('C'),A('e'),A('p'),A('h'),A('e'),A('i'),A('.'),A('f'),A('r'),A('a'),A('m'),A('e'),A('w'),A('o'),A('r'),A('k'),A('/'),A('C'),A('e'),A('p'),A('h'),A('e'),A('i'),
                0
            };
            
            if (checklibPresence(libInjectedName, decryptString(libsubstitute)) != NULL){
                printf("[ ! ] Substitute injection detected! (libsubstitute.dylib)\n\n");
                return YES;
            }
            
            if (checklibPresence(libInjectedName, decryptString(tweakinject)) != NULL){
                printf("[ ! ] TweakInject injection detected! (TweakInject.dylib), probably Electra.\n\n");
                return YES;
            }
            
            if (checklibPresence(libInjectedName, decryptString(cephei)) != NULL){
                printf("[ ! ] CEPHEI injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(kor)) != NULL){
                printf("[ ! ] KOR injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(mobilesubstratedylib)) != NULL){
                printf("[ ! ] mobilesubstrate injection detected!\n\n");
                return YES;
            }
            if(checklibPresence(libInjectedName, decryptString(libsparkapplistdylib)) != NULL){
                printf("[ ! ] libsparkapplist injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(cyinjectHide)) != NULL){
                printf("[ ! ] cyinjectHide injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(libcycriptHide)) != NULL){
                printf("[ ! ] libcycriptHide injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(libfridaHide)) != NULL){
                printf("[ ! ] libfridaHide injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(zzzzLibertyDylibHide)) != NULL){
                printf("[ ! ] zzzzLibertyDylibHide injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(sslkillswitch2dylib)) != NULL){
                printf("[ ! ] sslkillswitch2dylib injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(zeroshadowdylib)) != NULL){
                printf("[ ! ] zeroshadowdylib injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(SubstrateInserterdylib)) != NULL){
                printf("[ ! ] SubstrateInserter injection detected!\n\n");
                return YES;
            }
            if (checklibPresence(libInjectedName, decryptString(zzzzzzUnSubdylib)) != NULL){
                printf("[ ! ] zzzzzzUnSubdylib injection detected!\n\n");
                return YES;
            }
        }
    }
    return NO;
}
