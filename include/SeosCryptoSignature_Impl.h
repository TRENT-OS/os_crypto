/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoSignature_Impl.h
 *
 * @brief Signature data structures and constants
 *
 */

#pragma once

#include "SeosCryptoKey_Impl.h"

#include "mbedtls/rsa.h"

#include <limits.h>

typedef enum
{
    SeosCryptoSignature_Algorithm_NONE = 0,
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
    const SeosCryptoKey*            prvKey;
    const SeosCryptoKey*            pubKey;
}
SeosCryptoSignature;

/** @} */
