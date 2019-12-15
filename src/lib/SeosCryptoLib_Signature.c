/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Signature.h"
#include "lib/SeosCryptoRng.h"
#include "lib/SeosCryptoKey.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(
    SeosCryptoLib_Signature*   self,
    const SeosCryptoApi_MemIf* memIf)
{
    UNUSED_VAR(memIf);
    int padding;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
        padding = MBEDTLS_RSA_PKCS_V15;
        break;
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
        padding = MBEDTLS_RSA_PKCS_V21;
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    // Make sure we only get in the digests here which we currently support.
    switch (self->digest)
    {
    case SeosCryptoApi_Digest_ALG_NONE:
    case SeosCryptoApi_Digest_ALG_MD5:
    case SeosCryptoApi_Digest_ALG_SHA256:
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    // digest is matched to mbedTLS constants
    mbedtls_rsa_init(&self->mbedtls.rsa, padding, self->digest);

    return SEOS_SUCCESS;
}

static seos_err_t
freeImpl(
    SeosCryptoLib_Signature*   self,
    const SeosCryptoApi_MemIf* memIf)
{
    UNUSED_VAR(memIf);

    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
        mbedtls_rsa_free(&self->mbedtls.rsa);
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_SUCCESS;
}

static seos_err_t
setKeyImpl(
    SeosCryptoLib_Signature* self)
{
    seos_err_t retval;

    retval = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
        if (NULL != self->pubKey)
        {
            if (self->pubKey->type != SeosCryptoApi_Key_TYPE_RSA_PUB)
            {
                return SEOS_ERROR_INVALID_PARAMETER;
            }
            retval = SeosCryptoKey_writeRsaPub(self->pubKey, &self->mbedtls.rsa);
        }
        if (SEOS_SUCCESS == retval && NULL != self->prvKey)
        {
            if (self->prvKey->type != SeosCryptoApi_Key_TYPE_RSA_PRV)
            {
                return SEOS_ERROR_INVALID_PARAMETER;
            }
            retval = SeosCryptoKey_writeRsaPrv(self->prvKey, &self->mbedtls.rsa);
        }
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
verifyHashImpl(
    SeosCryptoLib_Signature* self,
    SeosCryptoRng*           rng,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
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
signHashImpl(
    SeosCryptoLib_Signature* self,
    SeosCryptoRng*           rng,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
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
SeosCryptoSignature_init(
    SeosCryptoLib_Signature*          self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoKey*              prvKey,
    const SeosCryptoKey*              pubKey)
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
SeosCryptoSignature_free(
    SeosCryptoLib_Signature*   self,
    const SeosCryptoApi_MemIf* memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoSignature_sign(
    SeosCryptoLib_Signature* self,
    SeosCryptoRng*           rng,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
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
SeosCryptoSignature_verify(
    SeosCryptoLib_Signature* self,
    SeosCryptoRng*           rng,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    if (NULL == self || NULL == hash || 0 == hashSize || NULL == signature
        || 0 == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (self->pubKey != NULL) ?
           verifyHashImpl(self, rng, hash, hashSize, signature, signatureSize) :
           SEOS_ERROR_ABORTED;
}
