/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file OS_CryptoLibRng_t.h
 *
 * @brief Crypto library implementation of RNG functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "mbedtls/ctr_drbg.h"

#include "compiler.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct OS_CryptoLibRng OS_CryptoLibRng_t;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibRng_init(
    OS_CryptoLibRng_t**              self,
    const OS_Crypto_Memory_t*        memIf,
    const OS_CryptoRng_Entropy_func* entropyFunc,
    void*                            entropyCtx);

seos_err_t
OS_CryptoLibRng_getBytes(
    OS_CryptoLibRng_t*        self,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize);

seos_err_t
OS_CryptoLibRng_reSeed(
    OS_CryptoLibRng_t* self,
    const void*        seed,
    const size_t       seedSize);

seos_err_t
OS_CryptoLibRng_free(
    OS_CryptoLibRng_t*        self,
    const OS_Crypto_Memory_t* memIf);

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
OS_CryptoLibRng_getBytesMbedtls(
    void*          self,
    unsigned char* buf,
    size_t         bufSize)
{
    // Simple wrapper for mbedTLS, to allow the buffered use of the getRandomData()
    // function as is common, but also to directly pass a function to mbedTLS
    return OS_CryptoLibRng_getBytes(self, 0, buf,
                                    bufSize) == SEOS_SUCCESS ? 0 : 1;
}

/** @} */
