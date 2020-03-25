/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/OS_CryptoLibSignature.h"

#include <stdbool.h>

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct OS_CryptoLibSignature
{
    union
    {
        mbedtls_rsa_context rsa;
    } mbedtls;
    OS_CryptoSignature_Alg algorithm;
    OS_CryptoDigest_Alg digest;
    const OS_CryptoLibKey* prvKey;
    const OS_CryptoLibKey* pubKey;
};

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(
    OS_CryptoLibSignature**      self,
    const OS_Crypto_Memory*      memIf,
    const OS_CryptoSignature_Alg algorithm,
    const OS_CryptoDigest_Alg    digest,
    const OS_CryptoLibKey*       prvKey,
    const OS_CryptoLibKey*       pubKey)
{
    seos_err_t err;
    OS_CryptoLibSignature* sig;
    int padding;

    // We can have one of those keys be empty, but not both
    if (NULL == memIf || NULL == self || (NULL == prvKey && NULL == pubKey))
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((sig = memIf->malloc(sizeof(OS_CryptoLibSignature))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(sig, 0, sizeof(OS_CryptoLibSignature));
    sig->algorithm = algorithm;
    sig->digest    = digest;
    sig->prvKey    = prvKey;
    sig->pubKey    = pubKey;

    switch (sig->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
        padding = MBEDTLS_RSA_PKCS_V15;
        break;
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
        padding = MBEDTLS_RSA_PKCS_V21;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
        goto err0;
    }

    // Make sure we only get in the digests here which we currently support.
    switch (sig->digest)
    {
    case OS_CryptoDigest_ALG_NONE:
    case OS_CryptoDigest_ALG_MD5:
    case OS_CryptoDigest_ALG_SHA256:
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
    OS_CryptoLibSignature*  self,
    const OS_Crypto_Memory* memIf)
{
    seos_err_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
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
    OS_CryptoLibSignature* self)
{
    seos_err_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
        if (NULL != self->pubKey)
        {
            if (OS_CryptoLibKey_getType(self->pubKey) != OS_CryptoKey_TYPE_RSA_PUB)
            {
                return SEOS_ERROR_INVALID_PARAMETER;
            }
            err = OS_CryptoLibKey_writeRsaPub(self->pubKey, &self->mbedtls.rsa);
        }
        if (SEOS_SUCCESS == err && NULL != self->prvKey)
        {
            if (OS_CryptoLibKey_getType(self->prvKey) != OS_CryptoKey_TYPE_RSA_PRV)
            {
                return SEOS_ERROR_INVALID_PARAMETER;
            }
            err = OS_CryptoLibKey_writeRsaPrv(self->prvKey, &self->mbedtls.rsa);
        }
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
verifyHashImpl(
    OS_CryptoLibSignature* self,
    OS_CryptoLibRng*       rng,
    const void*            hash,
    const size_t           hashSize,
    const void*            signature,
    const size_t           signatureSize)
{
    void* rngFunc = (NULL != rng) ? OS_CryptoLibRng_getBytesMbedtls : NULL;
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
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
    OS_CryptoLibSignature* self,
    OS_CryptoLibRng*       rng,
    const void*            hash,
    const size_t           hashSize,
    void*                  signature,
    size_t*                signatureSize)
{
    void* rngFunc = (NULL != rng) ? OS_CryptoLibRng_getBytesMbedtls : NULL;
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
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
OS_CryptoLibSignature_init(
    OS_CryptoLibSignature**      self,
    const OS_Crypto_Memory*      memIf,
    const OS_CryptoSignature_Alg algorithm,
    const OS_CryptoDigest_Alg    digest,
    const OS_CryptoLibKey*       prvKey,
    const OS_CryptoLibKey*       pubKey)
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
OS_CryptoLibSignature_free(
    OS_CryptoLibSignature*  self,
    const OS_Crypto_Memory* memIf)
{
    if (NULL == self || NULL == memIf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
OS_CryptoLibSignature_sign(
    OS_CryptoLibSignature* self,
    OS_CryptoLibRng*       rng,
    const void*            hash,
    const size_t           hashSize,
    void*                  signature,
    size_t*                signatureSize)
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
OS_CryptoLibSignature_verify(
    OS_CryptoLibSignature* self,
    OS_CryptoLibRng*       rng,
    const void*            hash,
    const size_t           hashSize,
    const void*            signature,
    const size_t           signatureSize)
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
