/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoRng.h
 *
 * @brief SEOS Crypto Random Number generator context and functions
 *
 */
#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoRng_Impl.h"

#include "seos_err.h"
#include "compiler.h"

/**
 * @brief Initializes an rng context
 *
 */
seos_err_t
SeosCryptoRng_init(SeosCrypto_MemIf*        memIf,
                   SeosCryptoRng*           self,
                   SeosCrypto_EntropyFunc   entropyFunc,
                   void*                    entropyCtx);

/**
 * @brief Get random bytes
 *
 */
seos_err_t
SeosCryptoRng_getBytes(SeosCryptoRng*  self,
                       void*           buf,
                       size_t          bufSize);

/**
 * @brief Reseed the RNG with additional bytes
 *
 */
seos_err_t
SeosCryptoRng_reSeed(SeosCryptoRng*  self,
                     const void*     seed,
                     size_t          seedLen);

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
SeosCryptoRng_getBytesMbedtls(void*            self,
                              unsigned char*   buf,
                              size_t           bufSize)
{
    // Simple wrapper for mbedTLS, to allow the buffered use of the getRandomData()
    // function as is common, but also to directly pass a function to mbedTLS
    return SeosCryptoRng_getBytes(self, buf, bufSize) == SEOS_SUCCESS ? 0 : 1;
}

/**
 * @brief Deinitializes an rng context
 *
 */
seos_err_t
SeosCryptoRng_free(SeosCrypto_MemIf*           memIf,
                   SeosCryptoRng*              self);

/** @} */
