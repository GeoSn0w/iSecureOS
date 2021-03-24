//
//  iSecureOS-Security.h
//  iSecureOS
//
//  Created by GeoSn0w on 3/20/21.
//

#ifndef iSecureOS_Security_h
#define iSecureOS_Security_h
int hashPasswordAndPrepare(const char *newPassword);
int appendChangesToFileSystem(void);
int warnaxActiveSSHConnection(char *ActiveSSHSignature);
#endif /* iSecureOS_Security_h */
