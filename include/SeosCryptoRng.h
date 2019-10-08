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
 * @param memIf (required) pointer to context to initialize
 * @param self (required) pointer to context to initialize
 * @param entropyFunc (required) entropy callback provided by platform
 * @param entropyCtx (optional) pointer passed to entropy function
   *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_ABORTED if drbg could not be seeded
 * @retval SEOS_ERROR_INVALID_PARAMETER if a parameter is invalid (e.g. NULL)
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
 * @param self (required) pointer to context
 * @param buf (required) pointer to the destination buffer
 * @param bufSize size of the destination buffer
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 *
 */
seos_err_t
SeosCryptoRng_getBytes(SeosCryptoRng*  self,
                       void*           buf,
                       size_t          bufSize);

/**
 * @brief Reseed the RNG with additional bytes
 *
 * @param self (required) pointer to context
 * @param seed (required) pointer to additional seed data
 * @param seedLen size seed
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
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
 * @param memIf (required) pointer to memory interface
 * @param self (required) pointer to context to initialize
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
  */
seos_err_t
SeosCryptoRng_deInit(SeosCrypto_MemIf*           memIf,
                     SeosCryptoRng*              self);

/** @} */
