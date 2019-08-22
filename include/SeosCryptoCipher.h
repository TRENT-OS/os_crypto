/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoCipher.h
 *
 * @brief Cipher functions and context
 *
 */
#pragma once

#include "SeosCryptoRng.h"

#include <limits.h>

#define SeosCryptoCipher_OUTPUT_BUFFER_SIZE     PAGE_SIZE
#define SeosCryptoCipher_TAG_BUFFER_SIZE        16
#define SeosCryptoCipher_AES_BLOCK_SIZE         16

typedef enum
{
    SeosCryptoCipher_Algorithm_NONE,
    SeosCryptoCipher_Algorithm_AES_EBC_ENC,
    SeosCryptoCipher_Algorithm_AES_EBC_DEC,
    SeosCryptoCipher_Algorithm_AES_CBC_ENC,
    SeosCryptoCipher_Algorithm_AES_CBC_DEC,
    SeosCryptoCipher_Algorithm_RSA_PKCS1_ENC,
    SeosCryptoCipher_Algorithm_RSA_PKCS1_DEC
}
SeosCryptoCipher_Algorithm;

#include "SeosCryptoCipher_Impl.h"
typedef struct SeosCryptoCipher SeosCryptoCipher;

/**
 * @brief initializes a cipher context
 *
 * @param self (required) pointer to context to initialize
 * @param algorithm the cipher algorithm
 * @param key (required) the cipher key
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
SeosCryptoCipher_init(SeosCryptoCipher*             self,
                      SeosCryptoCipher_Algorithm    algorithm,
                      SeosCryptoKey const*          key,
                      SeosCryptoRng*                rng,
                      void*                         iv,
                      size_t                        ivLen);
/**
 * @brief closes a cipher context.
 *
 * @param self (required) pointer to context to initialize
 *
 */
void
SeosCryptoCipher_deInit(SeosCryptoCipher* self);
/**
 * @brief update function for AEAD algorithms only
 *
 * @param self (required) pointer to context
 * @param input (required) input buffer
 * @param inputSize input buffer size
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 *
 */
seos_err_t
SeosCryptoCipher_updateAd(SeosCryptoCipher* self,
                          const char* input,
                          size_t inputSize);
/**
 * @brief perform cipher operation on a block
 *
 * @param self (required) pointer to context
 * @param input (required) input buffer
 * @param inputSize input buffer size
 * @param output (optional) input/output parameter cointaining the pointer to
 *  the output buffer. If content is == NULL, then it is set to a local (to the
 *  context) buffer and the content of \p outputSize is set to the correct value
 *  of the amount of written data. Otherwise (!= NULL) the given buffer is used
 *  as output and the value in \p outputSize is used (in the meaning of capacity
 *  of the buffer) for boundary check before writing. If write is possible then
 *  the value of \p outputSize is set to the correct value of the amount of
 *  written data.
 * @param outputSize (required) input/output parameter holding the capacity/size
 *  of \p output
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
SeosCryptoCipher_update(SeosCryptoCipher*   self,
                        const void*         input,
                        size_t              inputSize,
                        void**              output,
                        size_t*             outputSize);
/**
 * @brief perform operation on final block, applies padding automatically if
 *  requested
 *
 * @param self (required) pointer to context
 * @param input (required) input buffer
 * @param inputSize input buffer size
 * @param output (required) input/output parameter cointaining the pointer to
 *  the output buffer. If content is == NULL, then it is set to a local (to the
 *  context) buffer and the content of \p outputSize is set to the correct value
 *  of the amount of written data. Otherwise (!= NULL) the given buffer is used
 *  as output and the value in \p outputSize is used (in the meaning of capacity
 *  of the buffer) for boundary check before writing. If write is possible then
 *  the value of \p outputSize is set to the correct value of the amount of
 *  written data.
 * @param outputSize (required) input/output parameter holding the capacity/size
 *  of \p output
 * @param tag (optional) input/output parameter cointaining the pointer to
 *  the final tag buffer. It follows the same logic as output parameter.
 * @param tagSize (required) input/output parameter holding the capacity/size
 *  of \p tag
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
SeosCryptoCipher_finalize(SeosCryptoCipher* self,
                          const void*       input,
                          size_t            inputSize,
                          void**            output,
                          size_t*           outputSize,
                          void**            tag,
                          size_t*           tagSize);
/**
 * @brief checks the previously computed tag against the provided one
 *
 * @param self (required) pointer to context
 * @param tag (required) the tag buffer
 * @param tagSize the size of the tag buffer
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_GENERIC if it does not match
 *
 */
seos_err_t
SeosCryptoCipher_verifyTag(SeosCryptoCipher*    self,
                           char*                tag,
                           size_t               tagSize);
