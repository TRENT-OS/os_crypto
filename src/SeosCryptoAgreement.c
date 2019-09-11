/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoAgreement.h"
#include "LibDebug/Debug.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"

#include <string.h>

seos_err_t
SeosCryptoAgreement_init(SeosCryptoAgreement*            self,
                         SeosCryptoAgreement_Algorithm   algorithm,
                         SeosCryptoKey*                  privateKey)
{
    seos_err_t retval;

    if (NULL == self || NULL == privateKey || privateKey->algorithm != algorithm)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = SEOS_SUCCESS;
    switch (algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
    {
        // Check we have all the parameter we expect from a PRIVATE key
        mbedtls_dhm_context* dh = (mbedtls_dhm_context*) privateKey->algoKeyCtx;
        if (mbedtls_mpi_cmp_int(&dh->P, 0) == 0
            || mbedtls_mpi_cmp_int(&dh->G, 0) == 0
            || mbedtls_mpi_cmp_int(&dh->X, 0) == 0)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        break;
    }
    case SeosCryptoAgreement_Algorithm_ECDH:
    {
        mbedtls_ecp_keypair* ecp = (mbedtls_ecp_keypair*) privateKey->algoKeyCtx;
        // Check we actually have a group set and the scalar parameter is
        // not empty (in this case, it could be a PUBLIC key)
        if (ecp->grp.id == MBEDTLS_ECP_DP_NONE
            || mbedtls_mpi_cmp_int(&ecp->d, 0) == 0)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        break;
    }
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    self->algorithm  = algorithm;
    self->privateKey = privateKey;

    return retval;
}

seos_err_t
SeosCryptoAgreement_computeShared(SeosCryptoAgreement*  self,
                                  SeosCryptoRng*        rng,
                                  SeosCryptoKey*        publicKey,
                                  unsigned char*        buf,
                                  size_t                bufSize,
                                  size_t*               outLen)
{
    seos_err_t retval;
    void* rngFunc;

    if (NULL == self || NULL == publicKey || NULL == buf
        || publicKey->algorithm != self->algorithm)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    rngFunc = (NULL != rng) ? SeosCryptoRng_getBytes_mbedtls : NULL;

    retval = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
    {
        mbedtls_dhm_context* pub  = (mbedtls_dhm_context*) publicKey->algoKeyCtx;
        mbedtls_dhm_context* priv = (mbedtls_dhm_context*) self->privateKey->algoKeyCtx;
        mbedtls_dhm_context dh;

        // Make sure our private key and the public key passed here share the same
        // DH group parameters! Also ensure we have the public value in the key.
        if (mbedtls_mpi_cmp_mpi(&pub->P, &priv->P) != 0
            || mbedtls_mpi_cmp_mpi(&pub->G, &priv->G) != 0
            || mbedtls_mpi_cmp_int(&pub->GY, 0) == 0)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }

        // Copy from keys into our own DH context so we can feed it to calc_secret,
        // which also does the blinding for us.
        mbedtls_dhm_init(&dh);
        if (mbedtls_mpi_copy(&dh.P,  &priv->P) != 0
            || mbedtls_mpi_copy(&dh.G,  &priv->G) != 0
            || mbedtls_mpi_copy(&dh.GY, &pub->GY) != 0
            || mbedtls_mpi_copy(&dh.X,  &priv->X) != 0
            || mbedtls_dhm_calc_secret(&dh, buf, bufSize, outLen, rngFunc, rng) != 0)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        mbedtls_dhm_free(&dh);
        break;
    }
    case SeosCryptoAgreement_Algorithm_ECDH:
    {
        mbedtls_ecp_keypair* pub  = (mbedtls_ecp_keypair*) publicKey->algoKeyCtx;
        mbedtls_ecp_keypair* priv = (mbedtls_ecp_keypair*) self->privateKey->algoKeyCtx;
        mbedtls_ecdh_context ecdh;

        // Make sure the public key is actually on the same curve we use for the
        // private key..
        if (mbedtls_ecp_check_pubkey(&priv->grp, &pub->Q) != 0)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }

        // Create our own, short lived context and work on that to compute the
        // shared key.
        mbedtls_ecdh_init(&ecdh);
        if (mbedtls_ecp_group_copy(&ecdh.grp, &priv->grp) != 0
            || mbedtls_ecp_copy(&ecdh.Qp, &pub->Q) != 0
            || mbedtls_mpi_copy(&ecdh.d, &priv->d) != 0
            || mbedtls_ecdh_calc_secret(&ecdh, outLen, buf, bufSize, rngFunc, rng) != 0)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        mbedtls_ecdh_free(&ecdh);
        break;
    }
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
}