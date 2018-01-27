//
//  JHRSAEncoder.h
//  JHKit
//
//  Created by HaoCold on 2018/1/26.
//  Copyright © 2018年 HaoCold. All rights reserved.
//

/**<
 JHRSAEncoder 文件夹的路径添加到 Header Search Path 内
 */

#import <Foundation/Foundation.h>

@interface JHRSAEncoder : NSObject

#pragma mark --- encode
/// encode with public key. string MAX length is 117.
+ (NSString *)jh_encodeString:(NSString *)string withPublicKey:(NSString *)pemName;
/// encode with private key. string MAX length is 117.
+ (NSString *)jh_encodeString:(NSString *)string withPrivateKey:(NSString *)pemName;

#pragma mark --- decode
/// decode with public key. string MAX length is 117.
+ (NSString *)jh_decodeString:(NSString *)string withPublicKey:(NSString *)pemName;
/// decode with private key. string MAX length is 117.
+ (NSString *)jh_decodeString:(NSString *)string withPrivateKey:(NSString *)pemName;

@end

@interface JHRSAEncoder (MaxmumLength)

#pragma mark --- encode
/// encode with public key.
+ (NSString *)jh_encodeMAXString:(NSString *)string withPublicKey:(NSString *)pemName;
/// encode with private key.
+ (NSString *)jh_encodeMAXString:(NSString *)string withPrivateKey:(NSString *)pemName;

#pragma mark --- decode
/// decode with public key.
+ (NSString *)jh_decodeMAXString:(NSString *)string withPublicKey:(NSString *)pemName;
/// decode with private key.
+ (NSString *)jh_decodeMAXString:(NSString *)string withPrivateKey:(NSString *)pemName;

@end
