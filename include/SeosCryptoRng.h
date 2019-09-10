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
 * @brief initializes an rng context
 *
 * @param self (required) pointer to context to initialize
 * @param imlp pointer to the implementation context that will be used by the
 * rngFunc
 * @param rngFunc function pointer to a SeosCryptoRng_ImplRngFunc
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 *
 */
seos_err_t
SeosCryptoRng_init(SeosCrypto_MemIf*        memIf,
                   SeosCryptoRng*           self,
                   SeosCrypto_EntropyFunc   entropyFunc,
                   void*                    entropyCtx);

/**
 * @brief get random bytes
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
                       void**          buf,
                       size_t          bufSize);

/**
 * @brief reseed the RNG with additional bytes
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
 * @brief get random bytes for mbedTLS wrapper
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
    void* p = buf;
    return SeosCryptoRng_getBytes(self, &p, bufSize) == SEOS_SUCCESS ? 0 : 1;
}

/**
 * @brief deinitializes an rng context
 *
 * @param self (required) pointer to context to initialize
 *
 */
void
SeosCryptoRng_deInit(SeosCrypto_MemIf*           memIf,
                     SeosCryptoRng*              self);

/** @} */
