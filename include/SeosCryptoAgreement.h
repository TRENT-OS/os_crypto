/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoAgreement.h
 *
 * @brief KeyAgreement functions and context
 *
 */
#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoRng_Impl.h"
#include "SeosCryptoAgreement_Impl.h"

#include "compiler.h"
#include "seos_err.h"

/**
 * @brief Initializes a key agreement context
 *
 */
seos_err_t
SeosCryptoAgreement_init(SeosCryptoAgreement*                   self,
                         const SeosCrypto_MemIf*                memIf,
                         const SeosCryptoAgreement_Algorithm    algorithm,
                         const SeosCryptoKey_v5*                   privateKey);

/**
 * @brief Computes a shared secret
 *
 */
seos_err_t
SeosCryptoAgreement_agree(SeosCryptoAgreement*  self,
                          SeosCryptoRng*        rng,
                          const SeosCryptoKey_v5*  pubKey,
                          void*                 shared,
                          size_t*               sharedSize);

/**
 * @brief Closes a key agreement context.
 *
 */
seos_err_t
SeosCryptoAgreement_free(SeosCryptoAgreement*       self,
                         const SeosCrypto_MemIf*    memIf);

/** @} */
