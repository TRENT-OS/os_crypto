/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoAgreement.h"
#include "lib/SeosCryptoRng.h"
#include "lib/SeosCryptoKey.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(SeosCryptoAgreement*       self,
         const SeosCryptoApi_MemIf* memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Agreement_ALG_DH:
        mbedtls_dhm_init(&self->mbedtls.dh);
        retval = SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Agreement_ALG_ECDH:
        mbedtls_ecdh_init(&self->mbedtls.ecdh);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
freeImpl(SeosCryptoAgreement*       self,
         const SeosCryptoApi_MemIf* memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Agreement_ALG_DH:
        mbedtls_dhm_free(&self->mbedtls.dh);
        retval = SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Agreement_ALG_ECDH:
        mbedtls_ecdh_free(&self->mbedtls.ecdh);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
setKeyImpl(SeosCryptoAgreement* self)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Agreement_ALG_DH:
        retval = (self->prvKey->type != SeosCryptoApi_Key_TYPE_DH_PRV) ?
                 SEOS_ERROR_INVALID_PARAMETER :
                 SeosCryptoKey_writeDHPrv(self->prvKey, &self->mbedtls.dh);
        break;
    case SeosCryptoApi_Agreement_ALG_ECDH:
        retval = (self->prvKey->type != SeosCryptoApi_Key_TYPE_SECP256R1_PRV) ?
                 SEOS_ERROR_INVALID_PARAMETER :
                 SeosCryptoKey_writeSECP256r1Prv(self->prvKey, &self->mbedtls.ecdh);
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
agreeImpl(SeosCryptoAgreement* self,
          SeosCryptoRng*       rng,
          const SeosCryptoKey* pubKey,
          void*                buf,
          size_t*              bufSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Agreement_ALG_DH:
        if ((pubKey->type != SeosCryptoApi_Key_TYPE_DH_PUB)
            || SeosCryptoKey_writeDHPub(pubKey, &self->mbedtls.dh) != SEOS_SUCCESS)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else if (*bufSize < mbedtls_mpi_size(&self->mbedtls.dh.P))
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
            *bufSize = mbedtls_mpi_size(&self->mbedtls.dh.P);
        }
        else
        {
            retval = mbedtls_dhm_calc_secret(&self->mbedtls.dh, buf, *bufSize, bufSize,
                                             rngFunc, rng) != 0 ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    case SeosCryptoApi_Agreement_ALG_ECDH:
        if ((pubKey->type != SeosCryptoApi_Key_TYPE_SECP256R1_PUB)
            || SeosCryptoKey_writeSECP256r1Pub(pubKey,
                                               &self->mbedtls.ecdh) != SEOS_SUCCESS)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else if (*bufSize < mbedtls_mpi_size(&self->mbedtls.ecdh.grp.P))
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
            *bufSize = mbedtls_mpi_size(&self->mbedtls.ecdh.grp.P);
        }
        else
        {
            retval = mbedtls_ecdh_calc_secret(&self->mbedtls.ecdh, bufSize, buf, *bufSize,
                                              rngFunc, rng) != 0 ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoAgreement_init(SeosCryptoAgreement*              self,
                         const SeosCryptoApi_MemIf*        memIf,
                         const SeosCryptoApi_Agreement_Alg algorithm,
                         const SeosCryptoKey*              prvKey)
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

    retval = initImpl(self, memIf);
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
    freeImpl(self, memIf);
exit:
    return retval;
}

seos_err_t
SeosCryptoAgreement_agree(SeosCryptoAgreement* self,
                          SeosCryptoRng*       rng,
                          const SeosCryptoKey* pubKey,
                          void*                shared,
                          size_t*              sharedSize)
{
    if (NULL == self || NULL == pubKey || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return agreeImpl(self, rng, pubKey, shared, sharedSize);
}

seos_err_t
SeosCryptoAgreement_free(SeosCryptoAgreement*       self,
                         const SeosCryptoApi_MemIf* memIf)
{
    if (NULL == self || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}