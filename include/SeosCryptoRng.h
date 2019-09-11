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

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "LibDebug/Debug.h"

#include "seos_err.h"
#include "compiler.h"

typedef int (SeosCrypto_EntropyFunc)(void* ctx, unsigned char* buf, size_t len);


typedef struct
{
    mbedtls_ctr_drbg_context    drbg;
    unsigned char rnd[PAGE_SIZE];
}
SeosCryptoRng;

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
SeosCryptoRng_init(SeosCryptoRng*           self,
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
int
SeosCryptoRng_getBytes_mbedtls(SeosCryptoRng*  self,
                               unsigned char*  buf,
                               size_t          bufSize);

/**
 * @brief deinitializes an rng context
 *
 * @param self (required) pointer to context to initialize
 *
 */
void
SeosCryptoRng_deInit(SeosCryptoRng* self);

/** @} */
