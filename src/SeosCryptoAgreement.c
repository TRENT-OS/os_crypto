/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoAgreement.h"
#include "SeosCryptoRng.h"
#include "SeosCryptoKey.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

/*
 * Verify sanity of parameter with regards to P
 *
 * Parameter should be: 2 <= public_param <= P - 2
 *
 * This means that we need to return an error if
 *              public_param < 2 or public_param > P-2
 *
 * For more information on the attack, see:
 *  http://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf
 *  http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-2643
 */
static int dhm_check_range( const mbedtls_mpi* param, const mbedtls_mpi* P )
{
    mbedtls_mpi L, U;
    int ret = 0;

    mbedtls_mpi_init( &L );
    mbedtls_mpi_init( &U );

    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &L, 2 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &U, P, 2 ) );

    if ( mbedtls_mpi_cmp_mpi( param, &L ) < 0 ||
         mbedtls_mpi_cmp_mpi( param, &U ) > 0 )
    {
        ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }

cleanup:
    mbedtls_mpi_free( &L );
    mbedtls_mpi_free( &U );
    return ( ret );
}

static seos_err_t
initImpl(SeosCrypto_MemIf*               memIf,
         SeosCryptoAgreement*            self)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        mbedtls_dhm_init(&self->mbedtls.dh);
        retval = SEOS_SUCCESS;
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        mbedtls_ecdh_init(&self->mbedtls.ecdh);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
}

static void
deInitImpl(SeosCrypto_MemIf*               memIf,
           SeosCryptoAgreement*            self)
{
    UNUSED_VAR(memIf);

    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        mbedtls_dhm_free(&self->mbedtls.dh);
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        mbedtls_ecdh_free(&self->mbedtls.ecdh);
        break;
    default:
        break;
    }
}

static seos_err_t
setKeyImpl(SeosCryptoAgreement*            self)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->prvKey->type)
    {
    case SeosCryptoKey_Type_DH_PRV:
    {
        mbedtls_dhm_context* dh = &self->mbedtls.dh;
        SeosCryptoKey_DHPrv* dhKey;
        retval = (self->algorithm != SeosCryptoAgreement_Algorithm_DH)
                 || (dhKey = SeosCryptoKey_getDHPrv(self->prvKey)) == NULL
                 || mbedtls_mpi_read_binary(&dh->P, dhKey->pBytes, dhKey->pLen) != 0
                 || mbedtls_mpi_read_binary(&dh->G, dhKey->gBytes, dhKey->gLen) != 0
                 || mbedtls_mpi_read_binary(&dh->X, dhKey->xBytes, dhKey->xLen) != 0
                 || dhm_check_range(&dh->X, &dh->P) != 0 ?
                 SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
        break;
    }
    case SeosCryptoKey_Type_SECP256R1_PRV:
    {
        mbedtls_ecdh_context* ecdh = &self->mbedtls.ecdh;
        SeosCryptoKey_SECP256r1Prv* ecKey;
        retval = (self->algorithm != SeosCryptoAgreement_Algorithm_ECDH)
                 || (ecKey = SeosCryptoKey_getSECP256r1Prv(self->prvKey)) == NULL
                 || mbedtls_ecp_group_load(&ecdh->grp, MBEDTLS_ECP_DP_SECP256R1) != 0
                 || mbedtls_mpi_read_binary(&ecdh->d, ecKey->dBytes, ecKey->dLen) != 0 ?
                 SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
        break;
    }
    default:
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }

    return retval;
}

static seos_err_t
computeImpl(SeosCryptoAgreement*            self,
            SeosCryptoRng*                  rng,
            SeosCryptoKey*                  pubKey,
            unsigned char*                  buf,
            size_t*                         bufSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;
    size_t outLen = 0;

    switch (pubKey->type)
    {
    case SeosCryptoKey_Type_DH_PUB:
    {
        mbedtls_dhm_context* dh = &self->mbedtls.dh;
        SeosCryptoKey_DHPub* dhKey;
        retval = (self->algorithm != SeosCryptoAgreement_Algorithm_DH)
                 || (dhKey = SeosCryptoKey_getDHPub(pubKey)) == NULL
                 || mbedtls_mpi_read_binary(&dh->GY, dhKey->yBytes, dhKey->yLen) != 0
                 || dhm_check_range(&dh->GY, &dh->P) != 0
                 || mbedtls_dhm_calc_secret(dh, buf, *bufSize, &outLen, rngFunc, rng) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }
    case SeosCryptoKey_Type_SECP256R1_PUB:
    {
        mbedtls_ecdh_context* ecdh = &self->mbedtls.ecdh;
        SeosCryptoKey_SECP256r1Pub* ecKey;
        retval = (self->algorithm != SeosCryptoAgreement_Algorithm_ECDH)
                 || (ecKey = SeosCryptoKey_getSECP256r1Pub(pubKey)) == NULL
                 || mbedtls_mpi_read_binary(&ecdh->Qp.X, ecKey->qxBytes, ecKey->qxLen) != 0
                 || mbedtls_mpi_read_binary(&ecdh->Qp.Y, ecKey->qyBytes, ecKey->qyLen) != 0
                 || mbedtls_mpi_lset(&ecdh->Qp.Z, 1) != 0
                 || mbedtls_ecp_check_pubkey(&ecdh->grp, &ecdh->Qp) != 0
                 || mbedtls_ecdh_calc_secret(ecdh, &outLen, buf, *bufSize, rngFunc, rng) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }
    default:
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }

    *bufSize = outLen;

    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoAgreement_init(SeosCrypto_MemIf*               memIf,
                         SeosCryptoAgreement*            self,
                         SeosCryptoAgreement_Algorithm   algorithm,
                         SeosCryptoKey*                  prvKey)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == prvKey || NULL == memIf)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm  = algorithm;
    self->prvKey = prvKey;

    retval = initImpl(memIf, self);
    if (retval != SEOS_SUCCESS)
    {
        goto exit;
    }

    retval = setKeyImpl(self);
    if (retval != SEOS_SUCCESS)
    {
        goto err0;
    }

    goto exit;
err0:
    deInitImpl(memIf, self);
exit:
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: failed with err %d", __func__, retval);
    }

    return retval;
}

seos_err_t
SeosCryptoAgreement_computeShared(SeosCryptoAgreement*  self,
                                  SeosCryptoRng*        rng,
                                  SeosCryptoKey*        pubKey,
                                  unsigned char*        buf,
                                  size_t*               bufSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == pubKey || NULL == buf || NULL == bufSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = computeImpl(self, rng, pubKey, buf, bufSize);
    }

    return retval;
}

void
SeosCryptoAgreement_deInit(SeosCrypto_MemIf*        memIf,
                           SeosCryptoAgreement*     self)
{
    if (NULL == self || NULL != memIf)
    {
        deInitImpl(memIf, self);
    }
}