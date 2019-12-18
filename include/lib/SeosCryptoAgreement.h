/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoAgreement.h
 *
 * @brief Agreement functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"

#include <stddef.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoAgreement
{
    union
    {
        mbedtls_dhm_context dh;
        mbedtls_ecdh_context ecdh;
    }
    mbedtls;
    SeosCryptoApi_Agreement_Alg algorithm;
    const SeosCryptoKey* prvKey;
};

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoAgreement_init(SeosCryptoAgreement*              self,
                         const SeosCryptoApi_MemIf*        memIf,
                         const SeosCryptoApi_Agreement_Alg algorithm,
                         const SeosCryptoKey*              privateKey);

seos_err_t
SeosCryptoAgreement_agree(SeosCryptoAgreement* self,
                          SeosCryptoRng*       rng,
                          const SeosCryptoKey* pubKey,
                          void*                shared,
                          size_t*              sharedSize);

seos_err_t
SeosCryptoAgreement_free(SeosCryptoAgreement*       self,
                         const SeosCryptoApi_MemIf* memIf);

/** @} */
