/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoAgreement.h"
#include "SeosCryptoRng.h"
#include "SeosCryptoKey.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

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

static seos_err_t
deInitImpl(SeosCrypto_MemIf*               memIf,
           SeosCryptoAgreement*            self)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        mbedtls_dhm_free(&self->mbedtls.dh);
        retval = SEOS_SUCCESS;
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        mbedtls_ecdh_free(&self->mbedtls.ecdh);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
}

static seos_err_t
setKeyImpl(SeosCryptoAgreement*            self)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->prvKey->type)
    {
    case SeosCryptoKey_Type_DH_PRV:
        retval = (self->algorithm == SeosCryptoAgreement_Algorithm_DH) ?
                 SeosCryptoKey_writeDHPrv(self->prvKey,
                                          &self->mbedtls.dh) : SEOS_ERROR_INVALID_PARAMETER;
        break;
    case SeosCryptoKey_Type_SECP256R1_PRV:
        retval =  (self->algorithm == SeosCryptoAgreement_Algorithm_ECDH) ?
                  SeosCryptoKey_writeSECP256r1Prv(self->prvKey,
                                                  &self->mbedtls.ecdh) : SEOS_ERROR_INVALID_PARAMETER;
        break;
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
        retval = (self->algorithm != SeosCryptoAgreement_Algorithm_DH)
                 || SeosCryptoKey_writeDHPub(pubKey, &self->mbedtls.dh) != SEOS_SUCCESS
                 || mbedtls_dhm_calc_secret(&self->mbedtls.dh, buf, *bufSize, &outLen, rngFunc,
                                            rng) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoKey_Type_SECP256R1_PUB:
        retval = (self->algorithm != SeosCryptoAgreement_Algorithm_ECDH)
                 || SeosCryptoKey_writeSECP256r1Pub(pubKey,
                                                    &self->mbedtls.ecdh) != SEOS_SUCCESS
                 || mbedtls_ecdh_calc_secret(&self->mbedtls.ecdh, &outLen, buf, *bufSize,
                                             rngFunc, rng) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
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
                                  void**                shared,
                                  size_t*               sharedSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == pubKey || NULL == shared || NULL == sharedSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (NULL == *shared)
        {
            *shared      = self->outBuf;
            *sharedSize  = sizeof(self->outBuf);
        }
        retval = computeImpl(self, rng, pubKey, *shared, sharedSize);
    }

    return retval;
}

seos_err_t
SeosCryptoAgreement_deInit(SeosCrypto_MemIf*        memIf,
                           SeosCryptoAgreement*     self)
{
    if (NULL == self || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return deInitImpl(memIf, self);;
}