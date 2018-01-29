//
//  JHRSAEncoder.m
//  JHKit
//
//  Created by HaoCold on 2018/1/26.
//  Copyright © 2018年 HaoCold. All rights reserved.
//

#import "JHRSAEncoder.h"
#import "rsa.h"
#import "pem.h"
#import "err.h"

#if 1
#define JHRSALog(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define JHRSALog(...)
#endif

#define PADDING RSA_PKCS1_PADDING

@implementation JHRSAEncoder

#pragma mark - public

/// encode with public key
+ (NSString *)jh_encodeString:(NSString *)string withPublicKey:(NSString *)pemName{
    return [self jh_encodeString:string withKey:pemName type:0];
}

/// encode with private key
+ (NSString *)jh_encodeString:(NSString *)string withPrivateKey:(NSString *)pemName{
    return [self jh_encodeString:string withKey:pemName type:1];
}

/// decode with public key
+ (NSString *)jh_decodeString:(NSString *)string withPublicKey:(NSString *)pemName{
    return [self jh_decodeString:string withKey:pemName type:0];
}

/// decode with private key
+ (NSString *)jh_decodeString:(NSString *)string withPrivateKey:(NSString *)pemName{
    return [self jh_decodeString:string withKey:pemName type:1];
}

#pragma mark - private

/// type: 0 - public, 1 - private
+ (NSString *)jh_encodeString:(NSString *)string withKey:(NSString *)keyName type:(int)type
{
    RSA *rsa = [self jh_rsaForKeyName:keyName check:string type:type];
    if (rsa == NULL) {
        JHRSALog(@"read RSA Key failed.");
        return NULL;
    }

    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char input[data.length+1];
    bzero(input,data.length+1);
    [data getBytes:input length:data.length+1];
    
    int length = RSA_size(rsa);
    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
        length -= 11;
    }
    
    char *encodeData = (char *)malloc(length);
    bzero(encodeData, length);
    
    int status;
    if (type == 0) {
        status = RSA_public_encrypt((int)[string length], (unsigned char *)input, (unsigned char *)encodeData, rsa, PADDING);
    }else{
        status = RSA_private_encrypt((int)[string length], (unsigned char *)input, (unsigned char *)encodeData, rsa, PADDING);
    }
    
    NSString *outputString = @"";
    if (status > 0) {
        NSData *data = [NSData dataWithBytes:encodeData length:status];
        outputString = [data base64EncodedStringWithOptions:0];
    }
    free(encodeData);
    encodeData = NULL;
    
    return outputString;
}

/// type: 0 - public, 1 - private
+ (NSString *)jh_decodeString:(NSString *)string withKey:(NSString *)keyName type:(int)type
{
    RSA *rsa = [self jh_rsaForKeyName:keyName check:string type:type];
    if (rsa == NULL) {
        JHRSALog(@"read RSA Key failed.");
        return NULL;
    }
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:0];
    
    int length = RSA_size(rsa);
    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
        length -= 11;
    }
    
    char *decodeData = (char *)malloc(length);
    bzero(decodeData, length);
    
    int status;
    if (type == 0) {
        status = RSA_public_decrypt((int)[data length], (unsigned char *)[data bytes], (unsigned char *)decodeData, rsa, PADDING);
    }else{
        status = RSA_private_decrypt((int)[data length], (unsigned char *)[data bytes], (unsigned char *)decodeData, rsa, PADDING);
    }
    
    NSString *outputString = @"";
    if (status > 0) {
        outputString = [[NSMutableString alloc] initWithBytes:decodeData length:strlen(decodeData) encoding:NSASCIIStringEncoding];
        // NSLog(@"length:%@",@(strlen(decodeData)));
        // NSLog(@"outputString:%@",outputString);
        if (outputString.length > 117) {
            outputString = [outputString substringToIndex:117];
            // NSLog(@"outputString:%@",outputString);
        }
    }
    free(decodeData);
    decodeData = NULL;
    
    return outputString;
}

+ (RSA *)jh_rsaForKeyName:(NSString *)keyName check:(NSString *)string type:(int)type
{
    if (![string isKindOfClass:[NSString class]]) {
        JHRSALog(@"string is not a kind of NSString.");
        return NULL;
    }
    if ([string length] == 0) {
        JHRSALog(@"string length is 0.");
        return NULL;
    }
    
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:keyName ofType:@"pem"];
    FILE *file = fopen([keyPath UTF8String], "rb");
    if (file == NULL) {
        JHRSALog(@"read pem file failed.");
        return NULL;
    }
    
    RSA *rsa = NULL;
    if (type == 0) {
        rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
    }else{
        rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
    }
    fclose(file);
    return rsa;
}

@end


@implementation JHRSAEncoder (MaxmumLength)

#pragma mark - public
+ (NSString *)jh_encodeMAXString:(NSString *)string withPublicKey:(NSString *)pemName{
    return [self jh_encodeMAXString:string withKey:pemName type:0];
}

+ (NSString *)jh_encodeMAXString:(NSString *)string withPrivateKey:(NSString *)pemName{
    return [self jh_encodeMAXString:string withKey:pemName type:1];
}

+ (NSString *)jh_decodeMAXString:(NSString *)string withPublicKey:(NSString *)pemName{
    return [self jh_decodeMAXString:string withKey:pemName type:0];
}

+ (NSString *)jh_decodeMAXString:(NSString *)string withPrivateKey:(NSString *)pemName{
    return [self jh_decodeMAXString:string withKey:pemName type:1];
}

#pragma mark - private

/// type: 0 - public, 1 - private
+ (NSString *)jh_encodeMAXString:(NSString *)string withKey:(NSString *)pemName type:(int)type
{
    if (![string isKindOfClass:[NSString class]] || string.length == 0) {
        return @"";
    }
    
    if (string.length < 117) {
        if (type == 0) {
            return [self jh_encodeString:string withPublicKey:pemName];
        }else{
            return [self jh_encodeString:string withPrivateKey:pemName];
        }
    }
    
    BOOL flag = NO;
    NSString *outputString = @"";
    NSMutableArray *marr = @[].mutableCopy;
    for (int i = 0; i < string.length; i+=117) {
        NSUInteger length = (string.length - i) > 117 ? 117 : string.length - i;
        NSString *subString = [string substringWithRange:NSMakeRange(i, length)];
        NSString *encodeString = nil;
        if (type == 0) {
            encodeString = [self jh_encodeString:subString withPublicKey:pemName];
        }else{
            encodeString = [self jh_encodeString:subString withPrivateKey:pemName];
        }
        
        if (encodeString == nil) {
            flag = YES;
            break;
        }
        [marr addObject:encodeString];
    }
    
    if (flag) {
        return outputString;
    }
    outputString = [marr componentsJoinedByString:@""];
    
    return outputString;
}

+ (NSString *)jh_decodeMAXString:(NSString *)string withKey:(NSString *)pemName type:(int)type
{
    if (![string isKindOfClass:[NSString class]] || string.length == 0) {
        return @"";
    }
    
    if (string.length < 172) {
        if (type == 0) {
            return [self jh_decodeString:string withPublicKey:pemName];
        }else{
            return [self jh_decodeString:string withPrivateKey:pemName];
        }
    }
    
    BOOL flag = NO;
    NSString *outputString = @"";
    NSMutableArray *marr = @[].mutableCopy;
    for (int i = 0; i < string.length; i+=172) {
        NSUInteger length = (string.length - i) > 172 ? 172 : string.length - i;
        NSString *subString = [string substringWithRange:NSMakeRange(i, length)];
        NSString *decodeString = nil;
        if (type == 0) {
            decodeString = [self jh_decodeString:subString withPublicKey:pemName];
        }else{
            decodeString = [self jh_decodeString:subString withPrivateKey:pemName];
        }
        
        if (decodeString == nil) {
            flag = YES;
            break;
        }
        [marr addObject:decodeString];
    }
    
    if (flag) {
        return outputString;
    }
    outputString = [marr componentsJoinedByString:@""];
    
    return outputString;
}

@end
