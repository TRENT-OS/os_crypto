/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Agreement.h"
#include "lib/SeosCryptoLib_Rng.h"
#include "lib/SeosCryptoLib_Key.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoLib_Agreement
{
    union
    {
        mbedtls_dhm_context dh;
        mbedtls_ecdh_context ecdh;
    }
    mbedtls;
    SeosCryptoApi_Agreement_Alg algorithm;
    const SeosCryptoLib_Key* prvKey;
};

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(
    SeosCryptoLib_Agreement**         self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey)
{
    seos_err_t err;
    SeosCryptoLib_Agreement* agr;

    if ((agr = memIf->malloc(sizeof(SeosCryptoLib_Agreement))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(agr, 0, sizeof(SeosCryptoLib_Agreement));
    agr->algorithm = algorithm;
    agr->prvKey    = prvKey;

    err = SEOS_SUCCESS;
    switch (agr->algorithm)
    {
    case SeosCryptoApi_Agreement_ALG_DH:
        mbedtls_dhm_init(&agr->mbedtls.dh);
        break;
    case SeosCryptoApi_Agreement_ALG_ECDH:
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
    SeosCryptoLib_Agreement*   self,
    const SeosCryptoApi_MemIf* memIf)
{
    seos_err_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoApi_Agreement_ALG_DH:
        mbedtls_dhm_free(&self->mbedtls.dh);
        err = SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Agreement_ALG_ECDH:
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
    SeosCryptoLib_Agreement* self)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Agreement_ALG_DH:
        err = (self->prvKey->type != SeosCryptoApi_Key_TYPE_DH_PRV) ?
              SEOS_ERROR_INVALID_PARAMETER :
              SeosCryptoLib_Key_writeDhPrv(self->prvKey, &self->mbedtls.dh);
        break;
    case SeosCryptoApi_Agreement_ALG_ECDH:
        err = (self->prvKey->type != SeosCryptoApi_Key_TYPE_SECP256R1_PRV) ?
              SEOS_ERROR_INVALID_PARAMETER :
              SeosCryptoLib_Key_writeSecp256r1Prv(self->prvKey, &self->mbedtls.ecdh);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
agreeImpl(
    SeosCryptoLib_Agreement* self,
    SeosCryptoLib_Rng*       rng,
    const SeosCryptoLib_Key* pubKey,
    void*                    buf,
    size_t*                  bufSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoLib_Rng_getBytesMbedtls : NULL;
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Agreement_ALG_DH:
        if ((pubKey->type != SeosCryptoApi_Key_TYPE_DH_PUB)
            || SeosCryptoLib_Key_writeDhPub(pubKey, &self->mbedtls.dh) != SEOS_SUCCESS)
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
    case SeosCryptoApi_Agreement_ALG_ECDH:
        if ((pubKey->type != SeosCryptoApi_Key_TYPE_SECP256R1_PUB)
            || SeosCryptoLib_Key_writeSecp256r1Pub(pubKey,
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
SeosCryptoLib_Agreement_init(
    SeosCryptoLib_Agreement**         self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey)
{
    seos_err_t err;

    if (NULL == self || NULL == prvKey || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = initImpl(self, memIf, algorithm, prvKey)) == SEOS_SUCCESS)
    {
        if ((err = setKeyImpl(*self)) != SEOS_SUCCESS)
        {
            freeImpl(*self, memIf);
        }
    }

    return err;
}

seos_err_t
SeosCryptoLib_Agreement_free(
    SeosCryptoLib_Agreement*   self,
    const SeosCryptoApi_MemIf* memIf)
{
    if (NULL == self || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoLib_Agreement_agree(
    SeosCryptoLib_Agreement* self,
    SeosCryptoLib_Rng*       rng,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    if (NULL == self || NULL == pubKey || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return agreeImpl(self, rng, pubKey, shared, sharedSize);
}