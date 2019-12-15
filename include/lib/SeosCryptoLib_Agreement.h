/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoLib_Agreement.h
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

struct SeosCryptoLib_Agreement
{
    union
    {
        mbedtls_dhm_context dh;
        mbedtls_ecdh_context ecdh;
    }
    mbedtls;
    SeosCryptoApi_Agreement_Alg algorithm;
    const SeosCryptoLib_Key* prvKey;
};

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoAgreement_init(
    SeosCryptoLib_Agreement*          self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          privateKey);

seos_err_t
SeosCryptoAgreement_agree(
    SeosCryptoLib_Agreement* self,
    SeosCryptoRng*           rng,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize);

seos_err_t
SeosCryptoAgreement_free(
    SeosCryptoLib_Agreement*   self,
    const SeosCryptoApi_MemIf* memIf);

/** @} */
