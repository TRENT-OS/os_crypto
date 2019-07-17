#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_NO_PLATFORM_ENTROPY

#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CTR_DRBG_C

#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C

#define MBEDTLS_OID_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_SHA1_C
#define MBEDTLS_RSA_C
/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "platform_entropy_poll" source, but you may want to add other ones
 * Minimum is 2 for the entropy test suite.
 */
#define MBEDTLS_ENTROPY_MAX_SOURCES 2
#include "mbedtls/check_config.h"

// this is needed just by KeyStore, it will go away
#define MBEDTLS_BASE64_C

#endif /* MBEDTLS_CONFIG_H */
