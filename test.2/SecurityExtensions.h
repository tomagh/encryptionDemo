//
//  SecurityExtensions.h
//  test.2
//
//  Created by Andrew Tomenko on 3/6/17.
//  Copyright © 2017 Andrew Tomenko. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SecurityExtensions : NSObject

+ (NSData*) encryptData:(NSData*)inputData
	  withEASInitVector:(NSData*)initVector
				 AESKey:(NSData**)AESKey
		encryptedAESKey:(NSData**)encryptedAESKey
		   publicRSAKey:(NSData**)publicRSAKey
		  privateRSAKey:(NSData**)privateRSAKey;
+ (NSData*) decryptData:(NSData*)encryptedData usingEncryptedAESKey:(NSData*)encryptedAESKey andPrivateRSAKey:(NSData*)privateKeyData initVector:(NSData*)initVector;

@end
