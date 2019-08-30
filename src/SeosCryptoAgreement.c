/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoAgreement.h"
#include "LibDebug/Debug.h"

#include <string.h>

seos_err_t
SeosCryptoAgreement_init(SeosCryptoAgreement*            self,
                         SeosCryptoAgreement_Algorithm   algorithm,
                         SeosCryptoKey*                  privateKey,
                         SeosCryptoRng*                  rng)
{
    Debug_ASSERT_SELF(self);

    mbedtls_dhm_context* dh;
    seos_err_t retval;

    if (NULL == privateKey || NULL == rng)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = SEOS_SUCCESS;
    switch (algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        // Check we have all the parameter we expect from a PRIVATE key
        dh = (mbedtls_dhm_context*) privateKey->algoKeyCtx;
        if (    mbedtls_mpi_cmp_int(&dh->P, 0) == 0
                || mbedtls_mpi_cmp_int(&dh->G, 0) == 0
                || mbedtls_mpi_cmp_int(&dh->X, 0) == 0)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        mbedtls_dhm_init(&self->algCtx.dh);
        // We will use this later for key generation
        self->algCtx.dh.len = mbedtls_mpi_size(&dh->P);
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        // ToDo: Check params
        mbedtls_ecdh_init(&self->algCtx.ecdh);
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    self->algorithm = algorithm;
    self->rng = rng;
    self->privateKey = privateKey;

    return retval;
}

seos_err_t
SeosCryptoAgreement_computeShared(SeosCryptoAgreement*  self,
                                  SeosCryptoKey*        publicKey,
                                  unsigned char*        buf,
                                  size_t                bufSize,
                                  size_t*               outLen)
{
    Debug_ASSERT_SELF(self);

    mbedtls_dhm_context* privDh;
    mbedtls_dhm_context* pubDh;
    seos_err_t retval;

    if (NULL == publicKey)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        pubDh  = (mbedtls_dhm_context*) publicKey->algoKeyCtx;
        privDh = (mbedtls_dhm_context*) self->privateKey->algoKeyCtx;
        // Make sure our private key and the public key passed here share the same DH group parameters!
        if (    mbedtls_mpi_cmp_mpi(&pubDh->P, &privDh->P) != 0
                || mbedtls_mpi_cmp_mpi(&pubDh->G, &privDh->G) != 0
                || mbedtls_mpi_cmp_int(&pubDh->GY, 0) == 0)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }

        // Copy from keys into our own DH context
        mbedtls_mpi_copy(&self->algCtx.dh.P,  &privDh->P);
        mbedtls_mpi_copy(&self->algCtx.dh.G,  &privDh->G);
        mbedtls_mpi_copy(&self->algCtx.dh.GY, &pubDh->GY);
        mbedtls_mpi_copy(&self->algCtx.dh.X,  &privDh->X);
        // Compute the shared key
        if (mbedtls_dhm_calc_secret(&self->algCtx.dh,
                                    buf,
                                    bufSize,
                                    outLen,
                                    (int (*)(void*, unsigned char*, unsigned int)) self->rng->rngFunc,
                                    self->rng->implCtx) != 0)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
}

void
SeosCryptoAgreement_deInit(SeosCryptoAgreement* self)
{
    Debug_ASSERT_SELF(self);

    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        mbedtls_dhm_free(&self->algCtx.dh);
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        mbedtls_ecdh_free(&self->algCtx.ecdh);
        break;
    default:
        break;
    }
}