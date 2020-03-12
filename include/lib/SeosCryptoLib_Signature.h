/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib_Signature.h
 *
 * @brief Crypto library implementation of Signature functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "lib/SeosCryptoLib_Rng.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct SeosCryptoLib_Signature SeosCryptoLib_Signature;

// Exported functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_Signature_init(
    SeosCryptoLib_Signature**         self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey);

seos_err_t
SeosCryptoLib_Signature_free(
    SeosCryptoLib_Signature*   self,
    const SeosCryptoApi_MemIf* memIf);

seos_err_t
SeosCryptoLib_Signature_sign(
    SeosCryptoLib_Signature* self,
    SeosCryptoLib_Rng*       rng,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize);

seos_err_t
SeosCryptoLib_Signature_verify(
    SeosCryptoLib_Signature* self,
    SeosCryptoLib_Rng*       rng,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize);

/** @} */
