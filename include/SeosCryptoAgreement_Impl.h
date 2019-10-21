/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoAgreement_Impl.h
 *
 * @brief Agreement data structures and constants
 *
 */

#pragma once

#include "SeosCryptoKey_Impl.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"

typedef enum
{
    SeosCryptoAgreement_Algorithm_NONE = 0,
    SeosCryptoAgreement_Algorithm_DH,
    SeosCryptoAgreement_Algorithm_ECDH
}
SeosCryptoAgreement_Algorithm;

typedef struct
{
    union
    {
        mbedtls_dhm_context     dh;
        mbedtls_ecdh_context    ecdh;
    }
    mbedtls;

    SeosCryptoAgreement_Algorithm   algorithm;
    const SeosCryptoKey*            prvKey;
}
SeosCryptoAgreement;

/** @} */
