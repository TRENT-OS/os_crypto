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

#include "mbedtls/rsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include "SeosCryptoKey.h"

struct SeosCryptoCipher
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
    SeosCryptoRng*              rng;
    void*                       iv;
    size_t                      ivLen;
    size_t                      inputLen;
    char                        outputBuf[SeosCryptoCipher_OUTPUT_BUFFER_SIZE];
    char                        tagBuf[SeosCryptoCipher_TAG_BUFFER_SIZE];
};

/** @} */
