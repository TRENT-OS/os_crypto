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

#include "seos_err.h"
#include "compiler.h"

/**
 * @brief initializes a signature context
 *
 * @param self (required) pointer to context to initialize
 * @param algorithm the signature algorithm
 * @param key (required) the signature key
 * @param iv (optional) the initialization vector
 * @param ivLen the initialization vector length
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 *
 */
seos_err_t
SeosCryptoSignature_init(SeosCrypto_MemIf*              memIf,
                         SeosCryptoSignature*           self,
                         SeosCryptoSignature_Algorithm  algorithm,
                         SeosCryptoKey*                 prvKey,
                         SeosCryptoKey*                 pubKey);

/**
 * @brief closes a signature context.
 *
 * @param self (required) pointer to context to initialize
 *
 */
seos_err_t
SeosCryptoSignature_deInit(SeosCrypto_MemIf*            memIf,
                           SeosCryptoSignature*         self);

/**
 * @brief Sign a hash value
 *
 * @param self (required) pointer to context
 * @param rng (optional) seos RNG for protection against side channel attacks
 * @param hash (required) hash buffer
 * @param hashSize hash buffer size
 * @param signature (required) input/output parameter cointaining the pointer to
 *  the output buffer. If content is == NULL, then it is set to a local (to the
 *  context) buffer and the content of \p outputSize is set to the correct value
 *  of the amount of written data. Otherwise (!= NULL) the given buffer is used
 *  as output and the value in \p outputSize is used (in the meaning of capacity
 *  of the buffer) for boundary check before writing. If write is possible then
 *  the value of \p outputSize is set to the correct value of the amount of
 *  written data.
 * @param signatureSize (required) input/output parameter holding the
 *  capacity/size of \p output
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 * @retval SEOS_ERROR_ABORTED if the underlying implementation of the algorithm
 *  fails for any reason or the output buffer is not big enough
 *
 */
seos_err_t
SeosCryptoSignature_sign(SeosCryptoSignature*       self,
                         SeosCryptoRng*             rng,
                         const void*                hash,
                         size_t                     hashSize,
                         void**                     signature,
                         size_t*                    signatureSize);

/**
 * @brief verify a hash value
 *
 * @param self (required) pointer to context
 * @param rng (optional) seos RNG for protection against side channel attacks
 * @param hash (required) hash buffer
 * @param hashSize hash buffer size
 * @param signature (required) signature to be verified
 * @param signatureSize (required) size of signature
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_ABORTED if it does not match
 *
 */
seos_err_t
SeosCryptoSignature_verify(SeosCryptoSignature*         self,
                           SeosCryptoRng*               rng,
                           const void*                  hash,
                           size_t                       hashSize,
                           const void*                  signature,
                           size_t                       signatureSize);

///@}
