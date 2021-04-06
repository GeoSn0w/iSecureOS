//
//  iSecureOS-Main.h
//  securOS
//
//  Created by GeoSn0w on 3/9/21.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *secureOS_Load_Btn;
@property (weak, nonatomic) IBOutlet UILabel *currentStatus;
@property (weak, nonatomic) IBOutlet UIImageView *shieldStatus;
@property (weak, nonatomic) IBOutlet UISwitch *shouldScanDeep;


@end

