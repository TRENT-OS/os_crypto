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
SeosCryptoAgreement_init(SeosCrypto_MemIf*                 memIf,
                         SeosCryptoAgreement*              self,
                         SeosCryptoAgreement_Algorithm     algorithm,
                         SeosCryptoKey*                    privateKey);

/**
 * @brief Computes a shared secret
 *
 */
seos_err_t
SeosCryptoAgreement_agree(SeosCryptoAgreement*  self,
                          SeosCryptoRng*        rng,
                          SeosCryptoKey*        pubKey,
                          void*                 shared,
                          size_t*               sharedSize);

/**
 * @brief Closes a key agreement context.
 *
 */
seos_err_t
SeosCryptoAgreement_free(SeosCrypto_MemIf*           memIf,
                         SeosCryptoAgreement*        self);

/** @} */
