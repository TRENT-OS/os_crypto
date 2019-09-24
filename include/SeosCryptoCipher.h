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

#include "SeosCrypto_Impl.h"
#include "SeosCryptoKey_Impl.h"
#include "SeosCryptoCipher_Impl.h"

#include "compiler.h"
#include "seos_err.h"

/**
 * @brief implements SeosCryptoApi_cipherInit()
 *
 */
seos_err_t
SeosCryptoCipher_init(SeosCrypto_MemIf*             memIf,
                      SeosCryptoCipher*             self,
                      SeosCryptoCipher_Algorithm    algorithm,
                      SeosCryptoKey const*          key,
                      const void*                   iv,
                      size_t                        ivLen);

/**
 * @brief closes a cipher context.
 *
 * @param self (required) pointer to context to initialize
 *
 */
seos_err_t
SeosCryptoCipher_deInit(SeosCrypto_MemIf*           memIf,
                        SeosCryptoCipher*           self);

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
SeosCryptoCipher_start(SeosCryptoCipher* self,
                       const void*       input,
                       size_t            inputSize);

/**
 * @brief implements SeosCryptoApi_cipherUpdate()
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
 * @param output (required) output parameter cointaining the pointer to
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
SeosCryptoCipher_finalize(SeosCryptoCipher* self,
                          void*             output,
                          size_t*           outputSize);

///@}
