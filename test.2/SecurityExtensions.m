//
//  SecurityExtensions.m
//  test.2
//
//  Created by Andrew Tomenko on 3/6/17.
//  Copyright © 2017 Andrew Tomenko. All rights reserved.
//

#import "SecurityExtensions.h"

@implementation SecurityExtensions

+ (NSData*)exportSecKey:(SecKeyRef)cryptoKey
{
	// Create and populate the parameters object with a basic set of values
	SecItemImportExportKeyParameters params;
	memset(&params, 0, sizeof(SecItemImportExportKeyParameters));
	
	// Set the keyUsage and keyAttributes in the params object
	params.keyUsage = (__bridge CFArrayRef)@[(__bridge NSString*)kSecAttrCanEncrypt, (__bridge NSString*)kSecAttrCanDecrypt]; // TODO: check retain count
	params.keyAttributes = (__bridge CFArrayRef)@[];
	
	// Export the CFData Key
	CFDataRef keyData = NULL;
	OSStatus oserr = SecItemExport(cryptoKey, kSecFormatUnknown, 0, &params, &keyData);
	if (oserr) {
		NSLog(@"SecItemExport failed (oserr= %d)\n", oserr);
	}
	
	return (__bridge NSData*)keyData; // TODO: check retain count
}

+ (NSData*) encryptDataAES: (NSData*) sourceData usingKey:(SecKeyRef)cryptokey withInitializationVector:(NSData*)initiavlizationVector
{
	NSData* result = nil;
	CFErrorRef error = NULL;
	SecTransformRef encrypt = SecEncryptTransformCreate(cryptokey, &error);
	if (error == NULL)
	{
		SecTransformSetAttribute(encrypt, kSecTransformInputAttributeName, (__bridge CFDataRef)sourceData, &error);
		SecTransformSetAttribute(encrypt, kSecEncryptionMode, kSecModeCBCKey, &error);

		if (initiavlizationVector != nil)
		{
			SecTransformSetAttribute(encrypt, kSecIVKey, (__bridge CFDataRef)initiavlizationVector, &error);
		}
		
		if (error == NULL)
		{
			result = (__bridge_transfer NSData*)SecTransformExecute(encrypt, &error); // TODO: check retain count
		}
	}
	
	if (encrypt != NULL) CFRelease(encrypt);
	if (error != NULL)
	{
		CFShow(error);
		CFRelease(error);
	}
	
	return result;
}

+ (NSData*) encryptDataRSA: (NSData*) sourceData usingKey:(SecKeyRef)cryptokey
{
	NSData* result = nil;
	CFErrorRef error = NULL;
	SecTransformRef encrypt = SecEncryptTransformCreate(cryptokey, &error);
	if (error == NULL)
	{
		SecTransformSetAttribute(encrypt, kSecTransformInputAttributeName, (__bridge CFDataRef)sourceData, &error);
		SecTransformSetAttribute(encrypt, kSecEncryptionMode, kSecModeECBKey, &error);
		
		// For an RSA key the transform does PKCS#1 padding by default.  Weirdly, if we explicitly
		// set the padding to kSecPaddingPKCS1Key then the transform fails <rdar://problem/13661366>>.
		// Thus, if the client has requested PKCS#1, we leave paddingStr set to NULL, which prevents
		// us explicitly setting the padding to anything, which avoids the error while giving us
		// PKCS#1 padding.
		// SecTransformSetAttribute(encrypt, kSecPaddingKey, kSecPaddingPKCS1Key, &error);
		//		SecTransformSetAttribute(encrypt, kSecIVKey, NULL, &error);
		
		if (error == NULL)
		{
			result = (__bridge_transfer NSData*)SecTransformExecute(encrypt, &error); // TODO: check retain count
		}
	}
	
	if (encrypt != NULL) CFRelease(encrypt);
	if (error != NULL)
	{
		CFShow(error);
		CFRelease(error);
	}
	
	return result;
}

+ (NSData*) decryptData: (NSData*) sourceData usingKey:(SecKeyRef)cryptokey initVector:(NSData*)initVector
{
	NSData* result = nil;
	CFErrorRef error = NULL;
	SecTransformRef decrypt = SecDecryptTransformCreate(cryptokey, &error);
	if (error == NULL)
	{
		SecTransformSetAttribute(decrypt, kSecTransformInputAttributeName, (__bridge CFDataRef)sourceData, &error);
		SecTransformSetAttribute(decrypt, kSecEncryptionMode, kSecModeCBCKey, &error);
		if (initVector != nil)
		{
			SecTransformSetAttribute(decrypt, kSecIVKey, (__bridge CFDataRef)initVector, &error);
		}
//		SecTransformSetAttribute(decrypt, kSecPaddingKey, kSecPaddingNoneKey, &error);
		if (error == NULL)
		{
			result = (__bridge_transfer NSData*)SecTransformExecute(decrypt, &error); // TODO: check retain count
		}
	}
	
	if (decrypt != NULL) CFRelease(decrypt);
	if (error != NULL)
	{
		CFShow(error);
		CFRelease(error);
	}
	
	return result;
}


+ (NSData*) encryptData:(NSData*)inputData
	  withEASInitVector:(NSData*)initVector
				 AESKey:(NSData**)AESKeyData
		encryptedAESKey:(NSData**)encryptedAESKey
		   publicRSAKey:(NSData**)publicRSAKey
		  privateRSAKey:(NSData**)privateRSAKey;
{
	CFErrorRef error = NULL;
	NSData* result = nil;
	
	/* Generate random AES key */
	NSDictionary* ASEKeysParameters = @{(__bridge NSString*)kSecAttrKeyType: (__bridge NSString*)kSecAttrKeyTypeAES,
										(__bridge NSString*)kSecAttrKeySizeInBits: @(256)};
	SecKeyRef AESKey = SecKeyGenerateSymmetric((__bridge CFDictionaryRef)ASEKeysParameters, &error);
	
	/* Generate random RSA keys */
	SecKeyRef RSAPublicKey = NULL;
	SecKeyRef RSAPrivateKey = NULL;
	NSDictionary* RSAKeysParameters = @{(__bridge NSString*)kSecAttrKeyType: (__bridge NSString*)kSecAttrKeyTypeRSA,
										(__bridge NSString*)kSecAttrKeyClass: (__bridge NSString*)kSecAttrKeyClassPrivate,
										(__bridge NSString*)kSecAttrKeyClass: (__bridge NSString*)kSecAttrKeyClassPublic,
										(__bridge NSString*)kSecAttrKeySizeInBits: @(2048)};
	SecKeyGeneratePair((__bridge CFDictionaryRef)RSAKeysParameters, &RSAPublicKey, &RSAPrivateKey);

	
	if (error == NULL)
	{
		result = [SecurityExtensions encryptDataAES:inputData usingKey:AESKey withInitializationVector:initVector];
		*AESKeyData = [SecurityExtensions exportSecKey:AESKey];
		*encryptedAESKey = [SecurityExtensions encryptDataRSA:*AESKeyData usingKey:RSAPublicKey];
		*publicRSAKey = [SecurityExtensions exportSecKey: RSAPublicKey];
		*privateRSAKey = [SecurityExtensions exportSecKey: RSAPrivateKey];
	}
	
	if (error != NULL)
	{
		CFShow(error);
		CFRelease(error);
	}
	if (AESKey != NULL) CFRelease(AESKey);
	if (RSAPublicKey != NULL) CFRelease(RSAPublicKey);
	if (RSAPrivateKey != NULL) CFRelease(RSAPrivateKey);
	
	return result;
}

+ (NSData*) decryptData:(NSData*)encryptedData usingEncryptedAESKey:(NSData*)encryptedAESKey andPrivateRSAKey:(NSData*)privateKeyData initVector:(NSData*)initVector
{
	CFErrorRef error = NULL;
	NSData* result = nil;

	NSDictionary* ASEKeysParameters = @{(__bridge NSString*)kSecAttrKeyType: (__bridge NSString*)kSecAttrKeyTypeAES,
										(__bridge NSString*)kSecAttrKeySizeInBits: @(256)};
	
	NSDictionary* RSAKeysParameters = @{(__bridge NSString*)kSecAttrKeyType: (__bridge NSString*)kSecAttrKeyTypeRSA,
										(__bridge NSString*)kSecAttrKeyClass: (__bridge NSString*)kSecAttrKeyClassPrivate,
										(__bridge NSString*)kSecAttrKeySizeInBits: @(2048)};

	SecKeyRef privateRSAKey = SecKeyCreateFromData((__bridge CFDictionaryRef)RSAKeysParameters, (__bridge CFDataRef)privateKeyData, &error);
	NSData* decryptedAESKeyData = [SecurityExtensions decryptData:encryptedAESKey usingKey:privateRSAKey initVector:initVector];
	SecKeyRef AESKey = SecKeyCreateFromData((__bridge CFDictionaryRef)ASEKeysParameters, (__bridge CFDataRef)decryptedAESKeyData, &error);
	result = [SecurityExtensions decryptData:encryptedData usingKey:AESKey initVector:initVector];
	
	if (privateRSAKey != NULL) CFRelease(privateRSAKey);
	if (AESKey != NULL) CFRelease(AESKey);
	if (error != NULL)
	{
		CFShow(error);
		CFRelease(error);
	}
	
	return result;
}

@end
