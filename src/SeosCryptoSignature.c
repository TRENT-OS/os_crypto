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
initImpl(SeosCrypto_MemIf*      memIf,
         SeosCryptoSignature*   self)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        mbedtls_rsa_init(&self->mbedtls.rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

static void
deInitImpl(SeosCrypto_MemIf*        memIf,
           SeosCryptoSignature*     self)
{
    UNUSED_VAR(memIf);

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        mbedtls_rsa_free(&self->mbedtls.rsa);
        break;
    default:
        break;
    }
}

static seos_err_t
setKeyImpl(SeosCryptoSignature*     self)
{
    seos_err_t retval = SEOS_SUCCESS;

    if (self->pubKey != NULL)
    {
        switch (self->pubKey->type)
        {
        case SeosCryptoKey_Type_RSA_PUB:
        {
            SeosCryptoKey_RSAPub* pubKey;
            retval = (self->algorithm != SeosCryptoSignature_Algorithm_RSA_PKCS1)
                     || (pubKey = SeosCryptoKey_getRSAPub(self->pubKey)) == NULL
                     || (mbedtls_rsa_import_raw(&self->mbedtls.rsa,
                                                pubKey->nBytes, pubKey->nLen,
                                                NULL, 0, NULL, 0, NULL, 0,
                                                pubKey->eBytes, pubKey->eLen) != 0)
                     || (mbedtls_rsa_complete(&self->mbedtls.rsa) != 0)
                     || (mbedtls_rsa_check_pubkey(&self->mbedtls.rsa) != 0) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            break;
        }
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
        }
    }

    if (retval != SEOS_SUCCESS)
    {
        goto exit;
    }

    if (self->prvKey != NULL)
    {
        switch (self->prvKey->type)
        {
        case SeosCryptoKey_Type_RSA_PRV:
        {
            SeosCryptoKey_RSAPrv* prvKey;
            retval = (self->algorithm != SeosCryptoSignature_Algorithm_RSA_PKCS1)
                     || (prvKey = SeosCryptoKey_getRSAPrv(self->prvKey)) == NULL
                     || (mbedtls_rsa_import_raw(&self->mbedtls.rsa,
                                                prvKey->nBytes, prvKey->nLen,
                                                prvKey->pBytes, prvKey->pLen,
                                                prvKey->qBytes, prvKey->qLen,
                                                prvKey->dBytes, prvKey->dLen,
                                                NULL, 0) != 0)
                     || (mbedtls_rsa_complete(&self->mbedtls.rsa) != 0)
                     || (mbedtls_rsa_check_privkey(&self->mbedtls.rsa) != 0) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;

            break;
        }
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
        }
    }

exit:
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
        break;
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
            retval = (self->pubKey->type != SeosCryptoKey_Type_RSA_PUB)
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
        break;
    }

    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoSignature_init(SeosCrypto_MemIf*              memIf,
                         SeosCryptoSignature*           self,
                         SeosCryptoSignature_Algorithm  algorithm,
                         SeosCryptoKey*                 prvKey,
                         SeosCryptoKey*                 pubKey)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    // We can have one of those keys be empty, but not both
    if (NULL == memIf || NULL == self || ( NULL == prvKey && NULL == pubKey))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm  = algorithm;
    self->prvKey     = prvKey;
    self->pubKey     = pubKey;

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
    return retval;
}

void
SeosCryptoSignature_deInit(SeosCrypto_MemIf*            memIf,
                           SeosCryptoSignature*         self)
{
    if (NULL != memIf && NULL != self)
    {
        deInitImpl(memIf, self);
    }
}

seos_err_t
SeosCryptoSignature_sign(SeosCryptoSignature*       self,
                         SeosCryptoRng*             rng,
                         const void*                hash,
                         size_t                     hashSize,
                         void*                      signature,
                         size_t*                    signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == hash || 0 == hashSize || NULL == signature
        || NULL == signatureSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = (self->prvKey != NULL) ?
                 signHashImpl(self, rng, hash, hashSize, signature, signatureSize) :
                 SEOS_ERROR_ABORTED;
    }

    return retval;
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

    if (NULL == self || NULL == hash || 0 == hashSize)
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
