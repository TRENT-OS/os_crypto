/* Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoSignature_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCryptoSignature
 *
 */

#pragma once

#include "SeosCryptoKey_Impl.h"

#include "mbedtls/rsa.h"

#include <limits.h>

typedef enum
{
    SeosCryptoSignature_Algorithm_NONE,
    SeosCryptoSignature_Algorithm_RSA_PKCS1
}
SeosCryptoSignature_Algorithm;

typedef struct
{
    union
    {
        mbedtls_rsa_context     rsa;
    }
    mbedtls;

    SeosCryptoSignature_Algorithm   algorithm;
    SeosCryptoKey*                  prvKey;
    SeosCryptoKey*                  pubKey;
    unsigned char                   outBuf[PAGE_SIZE];
}
SeosCryptoSignature;

/** @} */
