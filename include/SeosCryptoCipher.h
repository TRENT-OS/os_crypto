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
 * @brief Initializes a cipher context
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
 */
seos_err_t
SeosCryptoCipher_free(SeosCrypto_MemIf*           memIf,
                      SeosCryptoCipher*           self);

/**
 * @brief Function for AEAD algorithms only to start computation
 *
 */
seos_err_t
SeosCryptoCipher_start(SeosCryptoCipher* self,
                       const void*       input,
                       size_t            inputSize);

/**
 * @brief Perform cipher operation on a block
 *
 */
seos_err_t
SeosCryptoCipher_update(SeosCryptoCipher*   self,
                        const void*         input,
                        size_t              inputSize,
                        void*               output,
                        size_t*             outputSize);

/**
 * @brief Perform operation on final block
 *
 */
seos_err_t
SeosCryptoCipher_finalize(SeosCryptoCipher* self,
                          void*             output,
                          size_t*           outputSize);

///@}
