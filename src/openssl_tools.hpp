//
//  p12_password_check.hpp
//  feather
//
//  Created by HAHALOSAH on 8/6/24.
//

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif
bool p12_password_check(NSString * _Nonnull file, NSString * _Nonnull pass);
// 0 成功，1 密码错误，2 格式无效，3 缺少私钥，4 不支持或无法解析。
NSData * _Nullable p12_certificate_data(NSData * _Nonnull data, NSString * _Nonnull pass,
                                        NSInteger * _Nonnull errorCode);
void password_check_fix_WHAT_THE_FUCK(NSString * _Nonnull path);
void password_check_fix_WHAT_THE_FUCK_free(NSString * _Nonnull path);
#ifdef __cplusplus
}
#endif
