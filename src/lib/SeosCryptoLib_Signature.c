/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Signature.h"

#include <stdbool.h>

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoLib_Signature
{
    union
    {
        mbedtls_rsa_context rsa;
    }
    mbedtls;
    SeosCryptoApi_Signature_Alg algorithm;
    SeosCryptoApi_Digest_Alg digest;
    const SeosCryptoLib_Key* prvKey;
    const SeosCryptoLib_Key* pubKey;
};

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(
    SeosCryptoLib_Signature**         self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey)
{
    seos_err_t err;
    SeosCryptoLib_Signature* sig;
    int padding;

    // We can have one of those keys be empty, but not both
    if (NULL == memIf || NULL == self || (NULL == prvKey && NULL == pubKey))
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((sig = memIf->malloc(sizeof(SeosCryptoLib_Signature))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(sig, 0, sizeof(SeosCryptoLib_Signature));
    sig->algorithm = algorithm;
    sig->digest    = digest;
    sig->prvKey    = prvKey;
    sig->pubKey    = pubKey;

    switch (sig->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
        padding = MBEDTLS_RSA_PKCS_V15;
        break;
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
        padding = MBEDTLS_RSA_PKCS_V21;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
        goto err0;
    }

    // Make sure we only get in the digests here which we currently support.
    switch (sig->digest)
    {
    case SeosCryptoApi_Digest_ALG_NONE:
    case SeosCryptoApi_Digest_ALG_MD5:
    case SeosCryptoApi_Digest_ALG_SHA256:
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
        goto err0;
    }

    // digest is matched to mbedTLS constants
    mbedtls_rsa_init(&sig->mbedtls.rsa, padding, sig->digest);

    *self = sig;

    return SEOS_SUCCESS;

err0:
    memIf->free(sig);

    return err;
}

static seos_err_t
freeImpl(
    SeosCryptoLib_Signature*   self,
    const SeosCryptoApi_MemIf* memIf)
{
    seos_err_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
        mbedtls_rsa_free(&self->mbedtls.rsa);
        break;
    default:

        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    memIf->free(self);

    return err;
}

static seos_err_t
setKeyImpl(
    SeosCryptoLib_Signature* self)
{
    seos_err_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
        if (NULL != self->pubKey)
        {
            if (SeosCryptoLib_Key_getType(self->pubKey) != SeosCryptoApi_Key_TYPE_RSA_PUB)
            {
                return SEOS_ERROR_INVALID_PARAMETER;
            }
            err = SeosCryptoLib_Key_writeRsaPub(self->pubKey, &self->mbedtls.rsa);
        }
        if (SEOS_SUCCESS == err && NULL != self->prvKey)
        {
            if (SeosCryptoLib_Key_getType(self->prvKey) != SeosCryptoApi_Key_TYPE_RSA_PRV)
            {
                return SEOS_ERROR_INVALID_PARAMETER;
            }
            err = SeosCryptoLib_Key_writeRsaPrv(self->prvKey, &self->mbedtls.rsa);
        }
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
verifyHashImpl(
    SeosCryptoLib_Signature* self,
    SeosCryptoLib_Rng*       rng,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoLib_Rng_getBytesMbedtls : NULL;
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
        if (self->mbedtls.rsa.len != signatureSize)
        {
            err = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            // digest is matched to mbedTLS constants
            err = mbedtls_rsa_pkcs1_verify(&self->mbedtls.rsa, rngFunc, rng,
                                           MBEDTLS_RSA_PUBLIC, self->digest, hashSize,
                                           hash, signature) != 0 ?
                  SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
signHashImpl(
    SeosCryptoLib_Signature* self,
    SeosCryptoLib_Rng*       rng,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoLib_Rng_getBytesMbedtls : NULL;
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V15:
    case SeosCryptoApi_Signature_ALG_RSA_PKCS1_V21:
        if (self->mbedtls.rsa.len > *signatureSize)
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            // digest is matched to mbedTLS constants
            err = mbedtls_rsa_pkcs1_sign(&self->mbedtls.rsa, rngFunc, rng,
                                         MBEDTLS_RSA_PRIVATE, self->digest, hashSize,
                                         hash, signature) != 0 ?
                  SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    *signatureSize = self->mbedtls.rsa.len;

    return err;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoLib_Signature_init(
    SeosCryptoLib_Signature**         self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey)
{
    seos_err_t err;

    // We can have one of those keys be empty, but not both
    if (NULL == memIf || NULL == self || (NULL == prvKey && NULL == pubKey))
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = initImpl(self, memIf, algorithm, digest, prvKey,
                        pubKey)) == SEOS_SUCCESS)
    {
        if ((err = setKeyImpl(*self)) != SEOS_SUCCESS)
        {
            freeImpl(*self, memIf);
        }
    }

    return err;
}

seos_err_t
SeosCryptoLib_Signature_free(
    SeosCryptoLib_Signature*   self,
    const SeosCryptoApi_MemIf* memIf)
{
    if (NULL == self || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoLib_Signature_sign(
    SeosCryptoLib_Signature* self,
    SeosCryptoLib_Rng*       rng,
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
SeosCryptoLib_Signature_verify(
    SeosCryptoLib_Signature* self,
    SeosCryptoLib_Rng*       rng,
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
