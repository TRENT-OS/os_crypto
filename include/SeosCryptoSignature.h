/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoSignature.h
 *
 * @brief Signature functions and context
 *
 */

#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoSignature_Impl.h"
#include "SeosCryptoRng_Impl.h"
#include "SeosCryptoKey.h"

#include "SeosError.h"
#include "compiler.h"

seos_err_t
SeosCryptoSignature_init(SeosCryptoSignature*                   self,
                         const SeosCrypto_MemIf*                memIf,
                         const SeosCryptoSignature_Algorithm    algorithm,
                         const SeosCryptoDigest_Algorithm       digest,
                         const SeosCryptoKey*                   prvKey,
                         const SeosCryptoKey*                   pubKey);

seos_err_t
SeosCryptoSignature_free(SeosCryptoSignature*       self,
                         const SeosCrypto_MemIf*    memIf);

seos_err_t
SeosCryptoSignature_sign(SeosCryptoSignature*   self,
                         SeosCryptoRng*         rng,
                         const void*            hash,
                         const size_t           hashSize,
                         void*                  signature,
                         size_t*                signatureSize);

seos_err_t
SeosCryptoSignature_verify(SeosCryptoSignature* self,
                           SeosCryptoRng*       rng,
                           const void*          hash,
                           const size_t         hashSize,
                           const void*          signature,
                           const size_t         signatureSize);

/** @} */
