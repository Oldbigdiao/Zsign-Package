//
//  p12_password_check.cpp
//  feather
//
//  Created by HAHALOSAH on 8/6/24.
//

#include "openssl_tools.hpp"
#include "common.h"

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/pkcs12.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <string>
#include <memory>

using namespace std;

NSData *p12_certificate_data(NSData *data, NSString *pass, NSInteger *errorCode) {
    *errorCode = 4;
    if (data.length == 0) {
        *errorCode = 2;
        return nil;
    }
    // 与签名引擎共用 OpenSSL，兼容新版 AES 和旧版 RC2/3DES P12。
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        OSSL_PROVIDER_load(NULL, "default");
        OSSL_PROVIDER_load(NULL, "legacy");
    });
    ERR_clear_error();
    const unsigned char *cursor = static_cast<const unsigned char *>(data.bytes);
    const unsigned char *end = cursor + data.length;
    unique_ptr<PKCS12, decltype(&PKCS12_free)> p12(
        d2i_PKCS12(NULL, &cursor, data.length), PKCS12_free);
    if (!p12 || cursor != end) {
        *errorCode = 2;
        return nil;
    }
    const char *password = pass.UTF8String;
    if (PKCS12_mac_present(p12.get())) {
        int verified = PKCS12_verify_mac(p12.get(), password, -1);
        if (!verified && pass.length == 0) {
            ERR_clear_error();
            verified = PKCS12_verify_mac(p12.get(), NULL, 0);
            if (verified) password = NULL;
        }
        if (!verified) {
            // MAC 不匹配与算法不可用分开报告，避免把格式问题归咎于密码。
            *errorCode = ERR_peek_error() == 0 ? 1 : 4;
            return nil;
        }
    }
    ERR_clear_error();
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    int parsed = PKCS12_parse(p12.get(), password, &key, &cert, NULL);
    unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ownedKey(key, EVP_PKEY_free);
    unique_ptr<X509, decltype(&X509_free)> ownedCert(cert, X509_free);
    if (!parsed) return nil;
    if (!key) {
        *errorCode = 3;
        return nil;
    }
    if (!cert || X509_check_private_key(cert, key) != 1) return nil;
    int length = i2d_X509(cert, NULL);
    if (length <= 0) return nil;
    NSMutableData *result = [NSMutableData dataWithLength:length];
    unsigned char *output = static_cast<unsigned char *>(result.mutableBytes);
    if (i2d_X509(cert, &output) != length) return nil;
    *errorCode = 0;
    return result;
}

bool p12_password_check(NSString *file, NSString *pass) {
	const std::string strFile = [file cStringUsingEncoding:NSUTF8StringEncoding];
	const std::string strPass = [pass cStringUsingEncoding:NSUTF8StringEncoding];
	
	BIO *bio = BIO_new_file(strFile.c_str(), "rb");
	if (!bio) {
		NSLog(@"Failed to open .p12 file");
		return false;
	}
	
	OSSL_PROVIDER_load(NULL, "legacy");
	
	PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
	BIO_free(bio);
	
	if (!p12) {
		NSLog(@"Failed to parse PKCS12");
		return false;
	}
	
	if( PKCS12_verify_mac(p12, NULL, 0) ) {
		return true;
	} else if( PKCS12_verify_mac(p12, strPass.c_str(), -1) ) {
		return true;
	} else {
		return false;
	}
	
	PKCS12_free(p12);
	return false;
}

// This is fucking bullshit IMO.
//
// In total, I probably wasted a total of 1.5 hours on this
// Feel free to increment the counter until someone finds a proper fix
//
// hours_wasted = 1.5
//
// TODO: FIX
void password_check_fix_WHAT_THE_FUCK(NSString *path) {
	string strProvisionFile = [path cStringUsingEncoding:NSUTF8StringEncoding];
	string strProvisionData;
	ZFile::ReadFile(strProvisionFile.c_str(), strProvisionData);
	
	BIO *in = BIO_new(BIO_s_mem());
	OPENSSL_assert((size_t)BIO_write(in, strProvisionData.data(), (int)strProvisionData.size()) == strProvisionData.size());
	d2i_CMS_bio(in, NULL);
}

void password_check_fix_WHAT_THE_FUCK_free(NSString *path) {
	string strProvisionFile = [path cStringUsingEncoding:NSUTF8StringEncoding];
	string strProvisionData;
	ZFile::ReadFile(strProvisionFile.c_str(), strProvisionData);
	
	BIO *in = BIO_new(BIO_s_mem());
	if (!in) return;
	
	if ((size_t)BIO_write(in, strProvisionData.data(), (int)strProvisionData.size()) != strProvisionData.size()) {
		BIO_free(in);
		return;
	}
	
	CMS_ContentInfo *cms = d2i_CMS_bio(in, NULL);
	if (cms) CMS_ContentInfo_free(cms);
	// free my boy
	BIO_free(in);
}
