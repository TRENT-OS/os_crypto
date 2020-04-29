/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibRng.h"

#include "mbedtls/ctr_drbg.h"

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct CryptoLibRng
{
    mbedtls_ctr_drbg_context drbg;
};

// Public Functions ------------------------------------------------------------

seos_err_t
CryptoLibRng_init(
    CryptoLibRng_t**                 self,
    const OS_CryptoRng_Entropy_func* entropyFunc,
    void*                            entropyCtx,
    const OS_Crypto_Memory_t*        memory)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    CryptoLibRng_t* rng;

    if (NULL == memory || NULL == self || NULL == entropyFunc)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((rng = memory->calloc(1, sizeof(CryptoLibRng_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = rng;

    memset(rng, 0, sizeof(CryptoLibRng_t));
    mbedtls_ctr_drbg_init(&rng->drbg);

    if (mbedtls_ctr_drbg_seed(&rng->drbg, entropyFunc, entropyCtx, NULL, 0) != 0)
    {
        err = SEOS_ERROR_ABORTED;
        goto err0;
    }

    // Force mbedTLS to reseed drbg frequently (e.g., after every time we have
    // obtained *some* amount of randomness from the DRBG)
    mbedtls_ctr_drbg_set_prediction_resistance(&rng->drbg, MBEDTLS_CTR_DRBG_PR_ON);

    return SEOS_SUCCESS;

err0:
    mbedtls_ctr_drbg_free(&rng->drbg);
    memory->free(rng);

    return err;
}

seos_err_t
CryptoLibRng_free(
    CryptoLibRng_t*           self,
    const OS_Crypto_Memory_t* memory)
{
    if (NULL == memory || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    mbedtls_ctr_drbg_free(&self->drbg);
    memory->free(self);

    return SEOS_SUCCESS;
}

seos_err_t
CryptoLibRng_getBytes(
    CryptoLibRng_t*           self,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize)
{
    if (NULL == self || NULL == buf || 0 == bufSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (flags != 0)
    {
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return (mbedtls_ctr_drbg_random(&self->drbg, buf, bufSize) != 0) ?
           SEOS_ERROR_ABORTED : SEOS_SUCCESS;
}

seos_err_t
CryptoLibRng_reSeed(
    CryptoLibRng_t* self,
    const void*     seed,
    const size_t    seedSize)
{
    if (NULL == seed || 0 == seedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    // Update RNG state with additional seed data
    if (mbedtls_ctr_drbg_update_ret(&self->drbg, seed, seedSize) != 0)
    {
        return SEOS_ERROR_ABORTED;
    }

    return SEOS_SUCCESS;
}

/** @} */
