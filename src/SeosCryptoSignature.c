/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoSignature.h"
#include "SeosCryptoRng.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(SeosCryptoSignature*       self,
         const SeosCrypto_MemIf*    memIf)

{
    UNUSED_VAR(memIf);
    int padding;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V15:
        padding = MBEDTLS_RSA_PKCS_V15;
        break;
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V21:
        padding = MBEDTLS_RSA_PKCS_V21;
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    // Make sure we only get in the digests here which we currently support.
    switch (self->digest)
    {
    case SeosCryptoDigest_Algorithm_NONE:
    case SeosCryptoDigest_Algorithm_MD5:
    case SeosCryptoDigest_Algorithm_SHA256:
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    // digest is matched to mbedTLS constants
    mbedtls_rsa_init(&self->mbedtls.rsa, padding, self->digest);

    return SEOS_SUCCESS;
}

static seos_err_t
freeImpl(SeosCryptoSignature*       self,
         const SeosCrypto_MemIf*    memIf)
{
    UNUSED_VAR(memIf);

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V15:
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V21:
        mbedtls_rsa_free(&self->mbedtls.rsa);
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_SUCCESS;
}

static seos_err_t
setKeyImpl(SeosCryptoSignature* self)
{
    seos_err_t retval;

    retval = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V15:
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V21:
        if (NULL != self->pubKey)
        {
            if (self->pubKey->type != SeosCryptoKey_Type_RSA_PUB)
            {
                return SEOS_ERROR_INVALID_PARAMETER;
            }
            retval = SeosCryptoKey_writeRSAPub(self->pubKey, &self->mbedtls.rsa);
        }
        if (SEOS_SUCCESS == retval && NULL != self->prvKey)
        {
            if (self->prvKey->type != SeosCryptoKey_Type_RSA_PRV)
            {
                return SEOS_ERROR_INVALID_PARAMETER;
            }
            retval = SeosCryptoKey_writeRSAPrv(self->prvKey, &self->mbedtls.rsa);
        }
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
verifyHashImpl(SeosCryptoSignature*             self,
               SeosCryptoRng*                   rng,
               const void*                      hash,
               const size_t                     hashSize,
               const void*                      signature,
               const size_t                     signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V15:
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V21:
        if (self->mbedtls.rsa.len != signatureSize)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            // digest is matched to mbedTLS constants
            retval = mbedtls_rsa_pkcs1_verify(&self->mbedtls.rsa, rngFunc, rng,
                                              MBEDTLS_RSA_PUBLIC, self->digest, hashSize,
                                              hash, signature) != 0 ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
signHashImpl(SeosCryptoSignature*               self,
             SeosCryptoRng*                     rng,
             const void*                        hash,
             const size_t                       hashSize,
             void*                              signature,
             size_t*                            signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V15:
    case SeosCryptoSignature_Algorithm_RSA_PKCS1_V21:
        if (self->mbedtls.rsa.len > *signatureSize)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            // digest is matched to mbedTLS constants
            retval = mbedtls_rsa_pkcs1_sign(&self->mbedtls.rsa, rngFunc, rng,
                                            MBEDTLS_RSA_PRIVATE, self->digest, hashSize,
                                            hash, signature) != 0 ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    *signatureSize = self->mbedtls.rsa.len;

    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoSignature_init(SeosCryptoSignature*                   self,
                         const SeosCrypto_MemIf*                memIf,
                         const SeosCryptoSignature_Algorithm    algorithm,
                         const SeosCryptoDigest_Algorithm       digest,
                         const SeosCryptoKey*                   prvKey,
                         const SeosCryptoKey*                   pubKey)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    // We can have one of those keys be empty, but not both
    if (NULL == memIf || NULL == self || (NULL == prvKey && NULL == pubKey))
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm = algorithm;
    self->digest    = digest;
    self->prvKey    = prvKey;
    self->pubKey    = pubKey;

    if ((retval = initImpl(self, memIf)) != SEOS_SUCCESS)
    {
        return retval;
    }
    if ((retval = setKeyImpl(self)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    freeImpl(self, memIf);
    return retval;
}

seos_err_t
SeosCryptoSignature_free(SeosCryptoSignature*       self,
                         const SeosCrypto_MemIf*    memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoSignature_sign(SeosCryptoSignature*               self,
                         SeosCryptoRng*                     rng,
                         const void*                        hash,
                         const size_t                       hashSize,
                         void*                              signature,
                         size_t*                            signatureSize)
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
SeosCryptoSignature_verify(SeosCryptoSignature* self,
                           SeosCryptoRng*       rng,
                           const void*          hash,
                           const size_t         hashSize,
                           const void*          signature,
                           const size_t         signatureSize)
{
    if (NULL == self || NULL == hash || 0 == hashSize || NULL == signature
        || 0 == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (self->pubKey != NULL) ?
           verifyHashImpl(self, rng, hash, hashSize, signature, signatureSize) :
           SEOS_ERROR_ABORTED ;
}
