/* Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoAgreement_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCryptoAgreement
 *
 */

#pragma once

#include "SeosCryptoKey_Impl.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"

typedef enum
{
    SeosCryptoAgreement_Algorithm_NONE,
    SeosCryptoAgreement_Algorithm_DH,
    SeosCryptoAgreement_Algorithm_ECDH
}
SeosCryptoAgreement_Algorithm;

typedef struct
{
    SeosCryptoAgreement_Algorithm algorithm;
    union
    {
        mbedtls_dhm_context     dh;
        mbedtls_ecdh_context    ecdh;
    }
    mbedtls;

    const SeosCryptoKey*        prvKey;
}
SeosCryptoAgreement;

/** @} */
