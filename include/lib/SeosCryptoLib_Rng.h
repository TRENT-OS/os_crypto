/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib_Rng.h
 *
 * @brief Crypto library implementation of RNG functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "mbedtls/ctr_drbg.h"

#include "compiler.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct SeosCryptoLib_Rng SeosCryptoLib_Rng;

// Exported functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_Rng_init(
    SeosCryptoLib_Rng**                  self,
    const SeosCryptoApi_MemIf*           memIf,
    const SeosCryptoApi_Rng_EntropyFunc* entropyFunc,
    void*                                entropyCtx);

seos_err_t
SeosCryptoLib_Rng_getBytes(
    SeosCryptoLib_Rng*           self,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize);

seos_err_t
SeosCryptoLib_Rng_reSeed(
    SeosCryptoLib_Rng* self,
    const void*        seed,
    const size_t       seedSize);

seos_err_t
SeosCryptoLib_Rng_free(
    SeosCryptoLib_Rng*         self,
    const SeosCryptoApi_MemIf* memIf);

/**
 * @brief Get random bytes for mbedTLS wrapper
 *
 * @param self (required) pointer to context
 * @param buf (required) pointer to the destination buffer
 * @param bufSize size of the destination buffer
 *
 * @return an error code
 * @retval 0 if all right
 *
 */
INLINE int
SeosCryptoLib_Rng_getBytesMbedtls(
    void*          self,
    unsigned char* buf,
    size_t         bufSize)
{
    // Simple wrapper for mbedTLS, to allow the buffered use of the getRandomData()
    // function as is common, but also to directly pass a function to mbedTLS
    return SeosCryptoLib_Rng_getBytes(self, 0, buf,
                                      bufSize) == SEOS_SUCCESS ? 0 : 1;
}

/** @} */
