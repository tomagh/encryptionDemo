//
//  AppDelegate.m
//  test.2
//
//  Created by Andrew Tomenko on 3/6/17.
//  Copyright © 2017 Andrew Tomenko. All rights reserved.
//

#import "AppDelegate.h"
#import "SecurityExtensions.h"
#import <SecurityFoundation/SecurityFoundation.h>

@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

- (NSString*) base64StringFromData:(NSData*)input
{
	NSData* output = nil;
	SecTransformRef transform = SecEncodeTransformCreate(kSecBase64Encoding, NULL);
	if (transform != NULL)
	{
		if (SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef)input, NULL))
		{
			output = (__bridge NSData*)SecTransformExecute(transform, NULL);
		}
		CFRelease(transform);
	}

	return [[NSString alloc] initWithData:output encoding:NSASCIIStringEncoding];
}

- (void) appendText:(NSString*)text
{
	[self.outputTextView setString:[self.outputTextView.string stringByAppendingString:text]];
}

- (IBAction)onButtonClicl:(id)sender
{
	/* Take input data */
	char* zeroBytes = malloc(16);
	memset(zeroBytes, 0, 16);
	NSMutableData* inputData = [[self.inputText.stringValue dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
	[inputData appendBytes:zeroBytes length:16 - inputData.length % 16];

	[self appendText:[NSString stringWithFormat:@"Input data in binary format:\n%@\n\n", inputData.description]];
	
	/* Take IV */
	NSMutableData* initializationVectorData = [[self.initializationVector.stringValue dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
	if (initializationVectorData.length < 16)
		[initializationVectorData appendBytes:zeroBytes length:16 - initializationVectorData.length];
	else if (initializationVectorData.length > 16)
		[initializationVectorData replaceBytesInRange:NSMakeRange(16, initializationVectorData.length - 16) withBytes:NULL length:0];
	[self appendText:[NSString stringWithFormat:@"AES initialization vector in binary format:\n%@\n\n", initializationVectorData.description]];
	
	/* Encrypt */
	NSData* aesKey = nil;
	NSData* encryptedAESKey = nil;
	NSData* publicRSAKey = nil;
	NSData* privateRSAKey = nil;
	NSData* encryptedData = [SecurityExtensions encryptData:inputData withEASInitVector:initializationVectorData AESKey:&aesKey encryptedAESKey:&encryptedAESKey publicRSAKey:&publicRSAKey privateRSAKey:&privateRSAKey];

	[self appendText:[NSString stringWithFormat:@"Random AES symmetric key:\n%@\n\n", aesKey.description]];
	[self appendText:[NSString stringWithFormat:@"Input data encrypted with AES key:\n%@\n\n", encryptedData.description]];
	[self appendText:[NSString stringWithFormat:@"Random RSA public key:\n%@\n\n", [self base64StringFromData:publicRSAKey]]];
	[self appendText:[NSString stringWithFormat:@"AES key encrypted with RSA public key (PKCS#1 padding):\n%@\n\n", encryptedAESKey.description]];
	[self appendText:[NSString stringWithFormat:@"RSA private key:\n%@\n\n", [self base64StringFromData:privateRSAKey]]];
	
	/* Decrypt */
	NSData* decryptedData = [SecurityExtensions decryptData:encryptedData usingEncryptedAESKey:encryptedAESKey andPrivateRSAKey:privateRSAKey initVector:initializationVectorData];
	[self appendText:[NSString stringWithFormat:@"Data decrypted with AES key that is decrypted with private RSA key:\n%@\n\n", decryptedData.description]];
	[self appendText:[NSString stringWithFormat:@"Data decrypted as text:\n%@\n\n", [NSString stringWithUTF8String:decryptedData.bytes]]];
}

@end
