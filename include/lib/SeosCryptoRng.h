/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoRng.h
 *
 * @brief RNG functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "mbedtls/ctr_drbg.h"

#include "compiler.h"

#include <stddef.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoRng
{
    mbedtls_ctr_drbg_context drbg;
};

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoRng_init(
    SeosCryptoRng*                       self,
    const SeosCryptoApi_MemIf*           memIf,
    const SeosCryptoApi_Rng_EntropyFunc* entropyFunc,
    void*                                entropyCtx);

seos_err_t
SeosCryptoRng_getBytes(
    SeosCryptoRng*               self,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize);

seos_err_t
SeosCryptoRng_reSeed(
    SeosCryptoRng* self,
    const void*    seed,
    const size_t   seedLen);

seos_err_t
SeosCryptoRng_free(
    SeosCryptoRng*             self,
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
SeosCryptoRng_getBytesMbedtls(
    void*          self,
    unsigned char* buf,
    size_t         bufSize)
{
    // Simple wrapper for mbedTLS, to allow the buffered use of the getRandomData()
    // function as is common, but also to directly pass a function to mbedTLS
    return SeosCryptoRng_getBytes(self, 0, buf, bufSize) == SEOS_SUCCESS ? 0 : 1;
}

/** @} */
