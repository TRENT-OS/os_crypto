/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoCipher_Impl.h
 *
 * @brief Cipher data structures and constants
 *
 */

#pragma once

#include "SeosCryptoKey_Impl.h"

#include "mbedtls/rsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include <stdbool.h>

#define SeosCryptoCipher_Size_AES_BLOCK         16
#define SeosCryptoCipher_Size_AES_CBC_IV        16
#define SeosCryptoCipher_Size_AES_GCM_IV        12
#define SeosCryptoCipher_Size_AES_GCM_TAG_MIN   4
#define SeosCryptoCipher_Size_AES_GCM_TAG_MAX   SeosCryptoCipher_Size_AES_BLOCK

typedef enum
{
    SeosCryptoCipher_Algorithm_NONE = 0,
    SeosCryptoCipher_Algorithm_AES_ECB_ENC,
    SeosCryptoCipher_Algorithm_AES_ECB_DEC,
    SeosCryptoCipher_Algorithm_AES_CBC_ENC,
    SeosCryptoCipher_Algorithm_AES_CBC_DEC,
    SeosCryptoCipher_Algorithm_AES_GCM_ENC,
    SeosCryptoCipher_Algorithm_AES_GCM_DEC,
    SeosCryptoCipher_Algorithm_RSA_PKCS1_ENC,
    SeosCryptoCipher_Algorithm_RSA_PKCS1_DEC
}
SeosCryptoCipher_Algorithm;

typedef struct
{
    union
    {
        mbedtls_aes_context     aes;
        mbedtls_rsa_context     rsa;
        mbedtls_gcm_context     gcm;
    }
    mbedtls;

    SeosCryptoCipher_Algorithm  algorithm;
    const SeosCryptoKey*        key;
    unsigned char               iv[SeosCryptoCipher_Size_AES_BLOCK];
    size_t                      ivLen;
    size_t                      inputLen;
    bool                        started;
    bool                        processed;
    bool                        finalized;
}
SeosCryptoCipher;

/** @} */
