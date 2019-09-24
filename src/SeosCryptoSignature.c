/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoSignature.h"
#include "SeosCryptoKey.h"
#include "SeosCryptoRng.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(SeosCryptoSignature*   self,
         SeosCrypto_MemIf*      memIf)

{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        mbedtls_rsa_init(&self->mbedtls.rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
freeImpl(SeosCryptoSignature*     self,
         SeosCrypto_MemIf*        memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        mbedtls_rsa_free(&self->mbedtls.rsa);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
setKeyImpl(SeosCryptoSignature*     self)
{
    seos_err_t retval = SEOS_SUCCESS;

    if (NULL != self->pubKey)
    {
        switch (self->pubKey->type)
        {
        case SeosCryptoKey_Type_RSA_PUB:
            retval = (self->algorithm != SeosCryptoSignature_Algorithm_RSA_PKCS1) ?
                     SEOS_ERROR_ABORTED :
                     SeosCryptoKey_writeRSAPub(self->pubKey, &self->mbedtls.rsa);
            break;
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
        }
    }

    if (SEOS_SUCCESS == retval && NULL != self->prvKey)
    {
        switch (self->prvKey->type)
        {
        case SeosCryptoKey_Type_RSA_PRV:
            retval = (self->algorithm != SeosCryptoSignature_Algorithm_RSA_PKCS1) ?
                     SEOS_ERROR_ABORTED :
                     SeosCryptoKey_writeRSAPrv(self->prvKey, &self->mbedtls.rsa);
            break;
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
        }
    }

    return retval;
}

static seos_err_t
verifyHashImpl(SeosCryptoSignature*         self,
               SeosCryptoRng*               rng,
               const void*                  hash,
               size_t                       hashSize,
               const void*                  signature,
               size_t                       signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        if (self->mbedtls.rsa.len != signatureSize)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            retval = (self->pubKey->type != SeosCryptoKey_Type_RSA_PUB)
                     || mbedtls_rsa_pkcs1_verify(&self->mbedtls.rsa, rngFunc, rng,
                                                 MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE, hashSize,
                                                 hash, signature) != 0 ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
signHashImpl(SeosCryptoSignature*       self,
             SeosCryptoRng*             rng,
             const void*                hash,
             size_t                     hashSize,
             void*                      signature,
             size_t*                    signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        if (self->mbedtls.rsa.len > *signatureSize)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            retval = (self->prvKey->type != SeosCryptoKey_Type_RSA_PRV)
                     ||  mbedtls_rsa_pkcs1_sign(&self->mbedtls.rsa, rngFunc, rng,
                                                MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE, hashSize,
                                                hash, signature) != 0 ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            if (retval == SEOS_SUCCESS)
            {
                *signatureSize = self->mbedtls.rsa.len;
            }
        }
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoSignature_init(SeosCryptoSignature*           self,
                         SeosCrypto_MemIf*              memIf,
                         SeosCryptoSignature_Algorithm  algorithm,
                         SeosCryptoKey*                 prvKey,
                         SeosCryptoKey*                 pubKey)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    // We can have one of those keys be empty, but not both
    if (NULL == memIf || NULL == self || (NULL == prvKey && NULL == pubKey))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm  = algorithm;
    self->prvKey     = prvKey;
    self->pubKey     = pubKey;

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
SeosCryptoSignature_free(SeosCryptoSignature*         self,
                         SeosCrypto_MemIf*            memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoSignature_sign(SeosCryptoSignature*       self,
                         SeosCryptoRng*             rng,
                         const void*                hash,
                         size_t                     hashSize,
                         void*                      signature,
                         size_t*                    signatureSize)
{
    if (NULL == self || NULL == hash || 0 == hashSize || NULL == signature
        || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (self->prvKey != NULL) ?
           signHashImpl(self, rng, hash, hashSize, signature, signatureSize) :
           SEOS_ERROR_ABORTED;
}

seos_err_t
SeosCryptoSignature_verify(SeosCryptoSignature*         self,
                           SeosCryptoRng*               rng,
                           const void*                  hash,
                           size_t                       hashSize,
                           const void*                  signature,
                           size_t                       signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == hash || 0 == hashSize || NULL == signature
        || 0 == signatureSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = (self->pubKey != NULL) ?
                 verifyHashImpl(self, rng, hash, hashSize, signature, signatureSize) :
                 SEOS_ERROR_ABORTED ;
    }

    return retval;
}
