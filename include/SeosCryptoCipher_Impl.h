/* Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoCipher_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCryptoCipher
 *
 */

#pragma once

#include "SeosCryptoKey_Impl.h"

#include "mbedtls/rsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#define SeosCryptoCipher_OUTPUT_BUFFER_SIZE     PAGE_SIZE
#define SeosCryptoCipher_AES_BLOCK_SIZE         16
#define SeosCryptoCipher_AES_CBC_IV_SIZE        16
#define SeosCryptoCipher_AES_GCM_IV_SIZE        12
#define SeosCryptoCipher_AES_GCM_TAG_SIZE       16

typedef enum
{
    SeosCryptoCipher_Algorithm_NONE,
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
    algorithmCtx;

    SeosCryptoCipher_Algorithm  algorithm;
    SeosCryptoKey const*        key;
    unsigned char               iv[SeosCryptoCipher_AES_BLOCK_SIZE];
    size_t                      ivLen;
    size_t                      inputLen;
    char                        outputBuf[SeosCryptoCipher_OUTPUT_BUFFER_SIZE];
    bool                        started;
    bool                        updated;
    bool                        finalized;
}
SeosCryptoCipher;

/** @} */
