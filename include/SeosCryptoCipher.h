/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoCipher.h
 *
 * @brief Cipher functions
 *
 */

#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoKey_Impl.h"
#include "SeosCryptoCipher_Impl.h"

#include "compiler.h"
#include "SeosError.h"

seos_err_t
SeosCryptoCipher_init(SeosCryptoCipher*                 self,
                      const SeosCrypto_MemIf*           memIf,
                      const SeosCryptoCipher_Algorithm  algorithm,
                      const SeosCryptoKey*              key,
                      const void*                       iv,
                      size_t                            ivLen);

seos_err_t
SeosCryptoCipher_free(SeosCryptoCipher*         self,
                      const SeosCrypto_MemIf*   memIf);

seos_err_t
SeosCryptoCipher_start(SeosCryptoCipher*    self,
                       const void*          input,
                       const size_t         inputSize);

seos_err_t
SeosCryptoCipher_process(SeosCryptoCipher*   self,
                         const void*         input,
                         const size_t        inputSize,
                         void*               output,
                         size_t*             outputSize);

seos_err_t
SeosCryptoCipher_finalize(SeosCryptoCipher* self,
                          void*             output,
                          size_t*           outputSize);

/** @} */
