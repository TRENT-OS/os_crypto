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
 * @brief initializes a key agreement context
 *
 * @param self (required) pointer to context to initialize
 * @param algorithm the key agreement algorithm
 * @param privateKey (required) our private key
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 *
 */
seos_err_t
SeosCryptoAgreement_init(SeosCrypto_MemIf*                 memIf,
                         SeosCryptoAgreement*              self,
                         SeosCryptoAgreement_Algorithm     algorithm,
                         SeosCryptoKey*                    privateKey);

/**
 * @brief computes a shared secret
 *
 * @param self (required) pointer to context
 * @param rng (optional) seos RNG for protection against side channel attacks
 * @param publicKey (required) their public key
 * @param shared (required) buffer for resulting shared key
 * @param sharedSize size of buffer in bytes, will be set to actual length
  *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing
 * @retval SEOS_ERROR_ABORTED if calculation could not execute due to small buffers
 *  or other errors
 *
 */
seos_err_t
SeosCryptoAgreement_computeShared(SeosCryptoAgreement*  self,
                                  SeosCryptoRng*        rng,
                                  SeosCryptoKey*        pubKey,
                                  void**                shared,
                                  size_t*               sharedSize);

/**
 * @brief closes a key agreement context.
 *
 * @param self (required) pointer to context to free
 *
 */
seos_err_t
SeosCryptoAgreement_deInit(SeosCrypto_MemIf*           memIf,
                           SeosCryptoAgreement*        self);

/** @} */
