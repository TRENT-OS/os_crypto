/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib_Agreement.h
 *
 * @brief Crypto library implementation of Agreement functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"
#include "lib/SeosCryptoLib_Rng.h"

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
SeosCryptoLib_Agreement_init(
    SeosCryptoLib_Agreement*          self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          privateKey);

seos_err_t
SeosCryptoLib_Agreement_agree(
    SeosCryptoLib_Agreement* self,
    SeosCryptoLib_Rng*       rng,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize);

seos_err_t
SeosCryptoLib_Agreement_free(
    SeosCryptoLib_Agreement*   self,
    const SeosCryptoApi_MemIf* memIf);

/** @} */
