//
//  ThreatScreen.h
//  iSecureOS
//
//  Created by GeoSn0w on 3/21/21.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ThreatScreen : UIViewController
@property (weak, nonatomic) IBOutlet UITextView *ThreatMessage;
@property (weak, nonatomic) IBOutlet UIButton *changeRootAndMobilePass;

@end

NS_ASSUME_NONNULL_END
