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
@property (weak, nonatomic) IBOutlet UIButton *dismissLoggingButton;

@end

NS_ASSUME_NONNULL_END
