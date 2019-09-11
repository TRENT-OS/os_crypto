/* Copyright (C) 2019); Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoDigest_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCryptoDigest
 *
 */

#pragma once

#include "LibDebug/Debug.h"

#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

#define SeosCryptoDigest_SIZE_MD5     16
#define SeosCryptoDigest_SIZE_SHA256  32

#define SeosCryptoDigest_MAX_DIGEST_SIZE SeosCryptoDigest_SIZE_SHA256

typedef enum
{
    // be aware!! At the moment those enums are matching those of
    // mbedtls_md_type_t for convenience reasons. Do not change values unless
    // you know what you are doing.
    SeosCryptoDigest_Algorithm_NONE,
    SeosCryptoDigest_Algorithm_MD2,
    SeosCryptoDigest_Algorithm_MD4,
    SeosCryptoDigest_Algorithm_MD5,
    SeosCryptoDigest_Algorithm_SHA1,
    SeosCryptoDigest_Algorithm_SHA224,
    SeosCryptoDigest_Algorithm_SHA256,
    SeosCryptoDigest_Algorithm_SHA384,
    SeosCryptoDigest_Algorithm_SHA512,
    SeosCryptoDigest_Algorithm_RIPEMD160
}
SeosCryptoDigest_Algorithm;

typedef struct
{
    union
    {
        mbedtls_md5_context     md5;
        mbedtls_sha256_context  sha256;
    }
    agorithmCtx;

    SeosCryptoDigest_Algorithm algorithm;
    char digest[SeosCryptoDigest_MAX_DIGEST_SIZE];
} SeosCryptoDigest;

Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_NONE     ==
                    (int) MBEDTLS_MD_NONE);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_MD2      ==
                    (int) MBEDTLS_MD_MD2);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_MD4      ==
                    (int) MBEDTLS_MD_MD4);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_MD5      ==
                    (int) MBEDTLS_MD_MD5);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_SHA1     ==
                    (int) MBEDTLS_MD_SHA1);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_SHA224   ==
                    (int) MBEDTLS_MD_SHA224);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_SHA256   ==
                    (int) MBEDTLS_MD_SHA256);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_SHA384   ==
                    (int) MBEDTLS_MD_SHA384);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_SHA512   ==
                    (int) MBEDTLS_MD_SHA512);
Debug_STATIC_ASSERT(SeosCryptoDigest_Algorithm_RIPEMD160 ==
                    (int) MBEDTLS_MD_RIPEMD160);
/** @} */
