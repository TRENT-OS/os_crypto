/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Rng.h"

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoLib_Rng
{
    mbedtls_ctr_drbg_context drbg;
};

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoLib_Rng_init(
    SeosCryptoLib_Rng**                  self,
    const SeosCryptoApi_MemIf*           memIf,
    const SeosCryptoApi_Rng_EntropyFunc* entropyFunc,
    void*                                entropyCtx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib_Rng* rng;

    if (NULL == memIf || NULL == self || NULL == entropyFunc)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((rng = memIf->malloc(sizeof(SeosCryptoLib_Rng))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = rng;

    memset(rng, 0, sizeof(SeosCryptoLib_Rng));
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
    memIf->free(rng);

    return err;
}

seos_err_t
SeosCryptoLib_Rng_free(
    SeosCryptoLib_Rng*         self,
    const SeosCryptoApi_MemIf* memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    mbedtls_ctr_drbg_free(&self->drbg);
    memIf->free(self);

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoLib_Rng_getBytes(
    SeosCryptoLib_Rng*           self,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize)
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
SeosCryptoLib_Rng_reSeed(
    SeosCryptoLib_Rng* self,
    const void*        seed,
    const size_t       seedSize)
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
