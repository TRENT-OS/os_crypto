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

#include "SeosCryptoApi.h"

#include "mbedtls/rsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoCipher
{
    union
    {
        mbedtls_aes_context aes;
        mbedtls_rsa_context rsa;
        mbedtls_gcm_context gcm;
    }
    mbedtls;
    SeosCryptoApi_Cipher_Alg algorithm;
    const SeosCryptoKey* key;
    uint8_t iv[SeosCryptoApi_Cipher_SIZE_AES_BLOCK];
    size_t ivLen;
    size_t inputLen;
    bool started;
    bool processed;
    bool finalized;
};

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoCipher_init(SeosCryptoCipher*              self,
                      const SeosCryptoApi_MemIf*     memIf,
                      const SeosCryptoApi_Cipher_Alg algorithm,
                      const SeosCryptoKey*           key,
                      const void*                    iv,
                      size_t                         ivLen);

seos_err_t
SeosCryptoCipher_free(SeosCryptoCipher*          self,
                      const SeosCryptoApi_MemIf* memIf);

seos_err_t
SeosCryptoCipher_start(SeosCryptoCipher* self,
                       const void*       input,
                       const size_t      inputSize);

seos_err_t
SeosCryptoCipher_process(SeosCryptoCipher* self,
                         const void*       input,
                         const size_t      inputSize,
                         void*             output,
                         size_t*           outputSize);

seos_err_t
SeosCryptoCipher_finalize(SeosCryptoCipher* self,
                          void*             output,
                          size_t*           outputSize);

/** @} */
