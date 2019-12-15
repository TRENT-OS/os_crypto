/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoLib_Signature.h
 *
 * @brief Signature functions and context
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "mbedtls/rsa.h"

#include "compiler.h"

#include <stdbool.h>
#include <stddef.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoLib_Signature
{
    union
    {
        mbedtls_rsa_context rsa;
    }
    mbedtls;
    SeosCryptoApi_Signature_Alg algorithm;
    SeosCryptoApi_Digest_Alg digest;
    const SeosCryptoLib_Key* prvKey;
    const SeosCryptoLib_Key* pubKey;
};

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoSignature_init(
    SeosCryptoLib_Signature*          self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey);

seos_err_t
SeosCryptoSignature_free(
    SeosCryptoLib_Signature*   self,
    const SeosCryptoApi_MemIf* memIf);

seos_err_t
SeosCryptoSignature_sign(
    SeosCryptoLib_Signature* self,
    SeosCryptoRng*           rng,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize);

seos_err_t
SeosCryptoSignature_verify(
    SeosCryptoLib_Signature* self,
    SeosCryptoRng*           rng,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize);

/** @} */
