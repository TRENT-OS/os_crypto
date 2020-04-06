/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibAgreement.h"
#include "lib/CryptoLibRng.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct CryptoLibAgreement
{
    union
    {
        mbedtls_dhm_context dh;
        mbedtls_ecdh_context ecdh;
    } mbedtls;
    OS_CryptoAgreement_Alg_t algorithm;
    const CryptoLibKey_t* prvKey;
};

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(
    CryptoLibAgreement_t**         self,
    const CryptoLibKey_t*          prvKey,
    const OS_CryptoAgreement_Alg_t algorithm,
    const OS_Crypto_Memory_t*      memIf)
{
    seos_err_t err;
    CryptoLibAgreement_t* agr;

    if ((agr = memIf->malloc(sizeof(CryptoLibAgreement_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(agr, 0, sizeof(CryptoLibAgreement_t));
    agr->algorithm = algorithm;
    agr->prvKey    = prvKey;

    err = SEOS_SUCCESS;
    switch (agr->algorithm)
    {
    case OS_CryptoAgreement_ALG_DH:
        mbedtls_dhm_init(&agr->mbedtls.dh);
        break;
    case OS_CryptoAgreement_ALG_ECDH:
        mbedtls_ecdh_init(&agr->mbedtls.ecdh);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (err != SEOS_SUCCESS)
    {
        memIf->free(agr);
    }

    *self = agr;

    return err;
}

static seos_err_t
freeImpl(
    CryptoLibAgreement_t*     self,
    const OS_Crypto_Memory_t* memIf)
{
    seos_err_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoAgreement_ALG_DH:
        mbedtls_dhm_free(&self->mbedtls.dh);
        err = SEOS_SUCCESS;
        break;
    case OS_CryptoAgreement_ALG_ECDH:
        mbedtls_ecdh_free(&self->mbedtls.ecdh);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    memIf->free(self);

    return err;
}

static seos_err_t
setKeyImpl(
    CryptoLibAgreement_t* self)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoAgreement_ALG_DH:
        err = (CryptoLibKey_getType(self->prvKey)
               != OS_CryptoKey_TYPE_DH_PRV) ?
              SEOS_ERROR_INVALID_PARAMETER :
              CryptoLibKey_writeDhPrv(self->prvKey, &self->mbedtls.dh);
        break;
    case OS_CryptoAgreement_ALG_ECDH:
        err = (CryptoLibKey_getType(self->prvKey)
               != OS_CryptoKey_TYPE_SECP256R1_PRV) ?
              SEOS_ERROR_INVALID_PARAMETER :
              CryptoLibKey_writeSecp256r1Prv(self->prvKey, &self->mbedtls.ecdh);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
agreeImpl(
    CryptoLibAgreement_t* self,
    CryptoLibRng_t*       rng,
    const CryptoLibKey_t* pubKey,
    void*                 buf,
    size_t*               bufSize)
{
    void* rngFunc = (NULL != rng) ? CryptoLibRng_getBytesMbedtls : NULL;
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoAgreement_ALG_DH:
        if ((CryptoLibKey_getType(pubKey) != OS_CryptoKey_TYPE_DH_PUB)
            || CryptoLibKey_writeDhPub(pubKey, &self->mbedtls.dh) != SEOS_SUCCESS)
        {
            err = SEOS_ERROR_INVALID_PARAMETER;
        }
        else if (*bufSize < mbedtls_mpi_size(&self->mbedtls.dh.P))
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
            *bufSize = mbedtls_mpi_size(&self->mbedtls.dh.P);
        }
        else
        {
            err = mbedtls_dhm_calc_secret(&self->mbedtls.dh, buf, *bufSize, bufSize,
                                          rngFunc, rng) != 0 ?
                  SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    case OS_CryptoAgreement_ALG_ECDH:
        if ((CryptoLibKey_getType(pubKey) != OS_CryptoKey_TYPE_SECP256R1_PUB)
            || CryptoLibKey_writeSecp256r1Pub(pubKey,
                                              &self->mbedtls.ecdh) != SEOS_SUCCESS)
        {
            err = SEOS_ERROR_INVALID_PARAMETER;
        }
        else if (*bufSize < mbedtls_mpi_size(&self->mbedtls.ecdh.grp.P))
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
            *bufSize = mbedtls_mpi_size(&self->mbedtls.ecdh.grp.P);
        }
        else
        {
            err = mbedtls_ecdh_calc_secret(&self->mbedtls.ecdh, bufSize, buf, *bufSize,
                                           rngFunc, rng) != 0 ?
                  SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

// Public Functions ------------------------------------------------------------

seos_err_t
CryptoLibAgreement_init(
    CryptoLibAgreement_t**         self,
    const CryptoLibKey_t*          prvKey,
    const OS_CryptoAgreement_Alg_t algorithm,
    const OS_Crypto_Memory_t*      memIf)
{
    seos_err_t err;

    if (NULL == self || NULL == prvKey || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = initImpl(self, prvKey, algorithm, memIf)) == SEOS_SUCCESS)
    {
        if ((err = setKeyImpl(*self)) != SEOS_SUCCESS)
        {
            freeImpl(*self, memIf);
        }
    }

    return err;
}

seos_err_t
CryptoLibAgreement_free(
    CryptoLibAgreement_t*     self,
    const OS_Crypto_Memory_t* memIf)
{
    if (NULL == self || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
CryptoLibAgreement_agree(
    CryptoLibAgreement_t* self,
    CryptoLibRng_t*       rng,
    const CryptoLibKey_t* pubKey,
    void*                 shared,
    size_t*               sharedSize)
{
    if (NULL == self || NULL == pubKey || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return agreeImpl(self, rng, pubKey, shared, sharedSize);
}