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

#include "SeosCrypto.h"
#include "SeosCryptoDigest.h"
#include "SeosCryptoRng.h"

#include <limits.h>

typedef enum
{
    SeosCryptoSignature_Algorithm_NONE,
    SeosCryptoSignature_Algorithm_RSA_PKCS1
}
SeosCryptoSignature_Algorithm;

#include "SeosCryptoSignature_Impl.h"
typedef struct SeosCryptoSignature SeosCryptoSignature;

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
SeosCryptoSignature_init(SeosCryptoSignature* self,
                         SeosCryptoSignature_Algorithm algorithm,
                         SeosCryptoKey const* key,
                         SeosCryptoRng* rng,
                         char* iv,
                         size_t ivLen);
/**
 * @brief closes a signature context.
 *
 * @param self (required) pointer to context to initialize
 *
 */
void
SeosCryptoSignature_deInit(SeosCryptoSignature* self);
/**
 * @brief TBD
 *
 * @param self (required) pointer to context
 * @param input (required) input buffer
 * @param inputSize input buffer size
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
SeosCryptoSignature_update(SeosCryptoSignature* self,
                           const char* input,
                           size_t inputSize);
/**
 * @brief TBD
 *
 * @param self (required) pointer to context
 * @param input (required) input buffer
 * @param inputSize input buffer size
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
SeosCryptoSignature_sign(SeosCryptoSignature* self,
                         SeosCryptoDigest_Algorithm digestAlgo, // can be none
                         const char* hash,
                         size_t hashSize,
                         char* signature,
                         size_t* signatureSize);
/**
 * @brief TBD
 *
 * @param self (required) pointer to context
 * TBD
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_GENERIC if it does not match
 *
 */
seos_err_t
SeosCryptoSignature_verify(SeosCryptoSignature* self,
                           SeosCryptoDigest_Algorithm digestAlgo, // can be none
                           const char* hash,
                           size_t hashSize,
                           const char* signature,
                           size_t signatureSize);
