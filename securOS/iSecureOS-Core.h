//
//  securiOS-Logging.h
//  securiOS
//
//  Created by GeoSn0w on 3/9/21.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface securiOS_Logging : UIViewController
@property (weak, nonatomic) IBOutlet UITextView *securiOSLoggingWindow;
@property (weak, nonatomic) IBOutlet UITableView *securiOSTableView;
@property (weak, nonatomic) IBOutlet UIButton *secureThisDevice;
@property (weak, nonatomic) IBOutlet UITextField *passwordField;
@property (weak, nonatomic) IBOutlet UITextField *passwordVerificationField;
@property (weak, nonatomic) IBOutlet UIImageView *scanningImage;
@property (weak, nonatomic) IBOutlet UIButton *viewVulnerabilities;
@property (weak, nonatomic) IBOutlet UIButton *viewScanLog;
@property (weak, nonatomic) IBOutlet UIProgressView *scannProgressbar;
@property (weak, nonatomic) IBOutlet UILabel *scanningLabel;


@end
NS_ASSUME_NONNULL_END
