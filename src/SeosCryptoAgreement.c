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
    }

    return retval;
}

static seos_err_t
freeImpl(SeosCrypto_MemIf*               memIf,
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
    }

    return retval;
}

static seos_err_t
setKeyImpl(SeosCryptoAgreement*            self)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        retval = (self->prvKey->type != SeosCryptoKey_Type_DH_PRV) ?
                 SEOS_ERROR_INVALID_PARAMETER :
                 SeosCryptoKey_writeDHPrv(self->prvKey, &self->mbedtls.dh);
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        retval = (self->prvKey->type != SeosCryptoKey_Type_SECP256R1_PRV) ?
                 SEOS_ERROR_INVALID_PARAMETER :
                 SeosCryptoKey_writeSECP256r1Prv(self->prvKey, &self->mbedtls.ecdh);
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
            void*                           buf,
            size_t*                         bufSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;
    size_t rc, outLen = 0;

    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        if ((pubKey->type != SeosCryptoKey_Type_DH_PUB)
            || SeosCryptoKey_writeDHPub(pubKey, &self->mbedtls.dh) != SEOS_SUCCESS)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            rc = mbedtls_dhm_calc_secret(&self->mbedtls.dh, buf, *bufSize, &outLen,
                                         rngFunc, rng);
            retval = (rc == 0) ? SEOS_SUCCESS :
                     (rc == MBEDTLS_ERR_DHM_BAD_INPUT_DATA) ?
                     SEOS_ERROR_BUFFER_TOO_SMALL : SEOS_ERROR_ABORTED;
        }
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        if ((pubKey->type != SeosCryptoKey_Type_SECP256R1_PUB)
            || SeosCryptoKey_writeSECP256r1Pub(pubKey, &self->mbedtls.ecdh) != SEOS_SUCCESS)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            rc = mbedtls_ecdh_calc_secret(&self->mbedtls.ecdh, &outLen, buf, *bufSize,
                                          rngFunc, rng);
            retval = (rc == 0) ? SEOS_SUCCESS :
                     (rc == MBEDTLS_ERR_ECP_BAD_INPUT_DATA) ?
                     SEOS_ERROR_BUFFER_TOO_SMALL : SEOS_ERROR_ABORTED;
        }
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
    freeImpl(memIf, self);
exit:
    return retval;
}

seos_err_t
SeosCryptoAgreement_agree(SeosCryptoAgreement*  self,
                          SeosCryptoRng*        rng,
                          SeosCryptoKey*        pubKey,
                          void*                 shared,
                          size_t*               sharedSize)
{
    if (NULL == self || NULL == pubKey || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return computeImpl(self, rng, pubKey, shared, sharedSize);
}

seos_err_t
SeosCryptoAgreement_free(SeosCrypto_MemIf*        memIf,
                         SeosCryptoAgreement*     self)
{
    if (NULL == self || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(memIf, self);;
}