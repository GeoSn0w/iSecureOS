//
//  iSecureOS-Main.h
//  securOS
//
//  Created by GeoSn0w on 3/9/21.
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v)     ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

@interface ViewController : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *secureOS_Load_Btn;
@property (weak, nonatomic) IBOutlet UILabel *currentStatus;
@property (weak, nonatomic) IBOutlet UIImageView *shieldStatus;
@property (weak, nonatomic) IBOutlet UISwitch *shouldScanDeep;

@end

