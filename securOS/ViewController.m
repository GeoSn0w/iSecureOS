//
//  ViewController.m
//  securiOS
//
//  Created by GeoSn0w on 3/9/21.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSDate *lastScan = [[NSUserDefaults standardUserDefaults] objectForKey:@"LastScan"];
    if (lastScan == nil) {
        _currentStatus.text = @"You have never scanned.";
        _shieldStatus.image = [UIImage imageNamed: @"shielderr.png"];
    } else {
        NSDate *currDate = [NSDate date];
        NSDateFormatter *dateFormatter = [[NSDateFormatter alloc]init];
        [dateFormatter setDateFormat:@"dd-MM-YY"];
        NSCalendar *calendar = [NSCalendar currentCalendar];

        [calendar rangeOfUnit:NSCalendarUnitDay startDate:&lastScan
            interval:NULL forDate:lastScan];
        [calendar rangeOfUnit:NSCalendarUnitDay startDate:&currDate
            interval:NULL forDate:currDate];

        NSDateComponents *difference = [calendar components:NSCalendarUnitDay
            fromDate:lastScan toDate:currDate options:0];
        NSInteger diff = [difference day];
        
        if (diff < 5){
            _currentStatus.text = @"You have scanned recently.";
            _shieldStatus.image = [UIImage imageNamed: @"shield.png"];
        } else {
            _currentStatus.text = @"You haven't scanned in a while.";
            _shieldStatus.image = [UIImage imageNamed: @"shielderr.png"];
        }
    }
     
    _secureOS_Load_Btn.layer.cornerRadius = 22;
    _secureOS_Load_Btn.clipsToBounds = YES;
    
    /*
    if (getuid() != 0){
        _secureOS_Load_Btn.enabled = NO;
        [_secureOS_Load_Btn setTitle:@"Not running as ROOT" forState:UIControlStateDisabled];
    }
     */
}

@end
