/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoRng.h"

#include "LibDebug/Debug.h"

#include <string.h>

seos_err_t
SeosCryptoRng_init(SeosCryptoRng*               self,
                   const SeosCrypto_MemIf*      memIf,
                   const SeosCrypto_EntropyFunc entropyFunc,
                   void*                        entropyCtx)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_SUCCESS;

    if (NULL == memIf || NULL == self || NULL == entropyFunc)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

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
SeosCryptoRng_getBytes(SeosCryptoRng*               self,
                       const SeosCryptoRng_Flags    flags,
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
SeosCryptoRng_reSeed(SeosCryptoRng* self,
                     const void*    seed,
                     const size_t   seedLen)
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

seos_err_t
SeosCryptoRng_free(SeosCryptoRng*           self,
                   const SeosCrypto_MemIf*  memIf)
{
    UNUSED_VAR(memIf);
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    mbedtls_ctr_drbg_free(&self->drbg);

    return SEOS_SUCCESS;
}

/** @} */
