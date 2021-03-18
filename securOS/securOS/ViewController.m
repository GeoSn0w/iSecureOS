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
    _secureOS_Load_Btn.layer.cornerRadius = 22;
    _secureOS_Load_Btn.clipsToBounds = YES;
    _settingsbutton.layer.cornerRadius = 22;
    _settingsbutton.clipsToBounds = YES;
}

- (IBAction)beginSecureOS:(id)sender {
    
}

@end
