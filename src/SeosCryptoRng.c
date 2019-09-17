/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include <string.h>

#include "SeosCryptoRng.h"

seos_err_t
SeosCryptoRng_init(SeosCryptoRng*           self,
                   SeosCrypto_EntropyFunc   entropyFunc,
                   void*                    entropyCtx)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_SUCCESS;

    memset(self, 0, sizeof(*self));

    mbedtls_ctr_drbg_init(&self->drbg);
    if (mbedtls_ctr_drbg_seed(&self->drbg, entropyFunc, entropyCtx, NULL, 0) != 0)
    {
        retval = SEOS_ERROR_ABORTED;
        goto err0;
    }

    // Force mbedTLS to reseed drbg frequently (e.g., after every time we have
    // obtained *some* amount of randomness from the DRBG)
    mbedtls_ctr_drbg_set_prediction_resistance(&self->drbg, MBEDTLS_CTR_DRBG_PR_ON);

    return SEOS_SUCCESS;

err0:
    mbedtls_ctr_drbg_free(&self->drbg);
    return retval;
}

seos_err_t
SeosCryptoRng_getBytes(SeosCryptoRng*  self,
                       void**          buf,
                       size_t          bufSize)
{
    Debug_ASSERT_SELF(self);

    if (NULL == buf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if (NULL == *buf)
    {
        if (bufSize > PAGE_SIZE)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        *buf = self->rnd;
    }

    if (mbedtls_ctr_drbg_random(&self->drbg, *buf, bufSize) != 0)
    {
        return SEOS_ERROR_ABORTED;
    }

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoRng_reSeed(SeosCryptoRng*  self,
                     const void*     seed,
                     size_t          seedLen)
{
    if (NULL == seed || 0 == seedLen)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    // Update RNG state with additional seed data
    if (mbedtls_ctr_drbg_update_ret(&self->drbg, seed, seedLen) != 0)
    {
        return SEOS_ERROR_ABORTED;
    }

    return SEOS_SUCCESS;
}

void
SeosCryptoRng_deInit(SeosCryptoRng* self)
{
    Debug_ASSERT_SELF(self);

    mbedtls_ctr_drbg_free(&self->drbg);

    return;
}

/** @} */
