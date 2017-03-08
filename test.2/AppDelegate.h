//
//  AppDelegate.h
//  test.2
//
//  Created by Andrew Tomenko on 3/6/17.
//  Copyright © 2017 Andrew Tomenko. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>

@property (weak) IBOutlet NSTextField *inputText;
@property (weak) IBOutlet NSTextField *initializationVector;
- (IBAction)onButtonClicl:(id)sender;

@property (unsafe_unretained) IBOutlet NSTextView *outputTextView;

@end

