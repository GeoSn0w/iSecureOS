//
//  iSecureOS-Settings.h
//  iSecureOS
//
//  Created by GeoSn0w on 4/6/21.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface iSecureOS_Settings : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *removeQuarantinedItemsButton;
@property (weak, nonatomic) IBOutlet UIButton *saveSettingsbutton;
@property (weak, nonatomic) IBOutlet UISwitch *ignoreCVEsToggle;
@property (weak, nonatomic) IBOutlet UISwitch *ignoreVPNToggle;
@end

NS_ASSUME_NONNULL_END
