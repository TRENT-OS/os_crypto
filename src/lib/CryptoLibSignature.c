/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibSignature.h"

#include <stdbool.h>

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct CryptoLibSignature
{
    union
    {
        mbedtls_rsa_context rsa;
    } mbedtls;
    OS_CryptoSignature_Alg_t algorithm;
    OS_CryptoDigest_Alg_t digest;
    const CryptoLibKey_t* prvKey;
    const CryptoLibKey_t* pubKey;
};

// Private Functions -----------------------------------------------------------

static OS_Error_t
initImpl(
    CryptoLibSignature_t**         self,
    const CryptoLibKey_t*          prvKey,
    const CryptoLibKey_t*          pubKey,
    const OS_CryptoSignature_Alg_t algorithm,
    const OS_CryptoDigest_Alg_t    digest,
    const OS_Crypto_Memory_t*      memory)
{
    OS_Error_t err;
    CryptoLibSignature_t* sig;
    int padding;

    // We can have one of those keys be empty, but not both
    if (NULL == memory || NULL == self || (NULL == prvKey && NULL == pubKey))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((sig = memory->calloc(1, sizeof(CryptoLibSignature_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(sig, 0, sizeof(CryptoLibSignature_t));
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
        err = OS_ERROR_NOT_SUPPORTED;
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
        err = OS_ERROR_NOT_SUPPORTED;
        goto err0;
    }

    // digest is matched to mbedTLS constants
    mbedtls_rsa_init(&sig->mbedtls.rsa, padding, sig->digest);

    *self = sig;

    return OS_SUCCESS;

err0:
    memory->free(sig);

    return err;
}

static OS_Error_t
freeImpl(
    CryptoLibSignature_t*     self,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err;

    err = OS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
        mbedtls_rsa_free(&self->mbedtls.rsa);
        break;
    default:

        err = OS_ERROR_NOT_SUPPORTED;
    }

    memory->free(self);

    return err;
}

static OS_Error_t
setKeyImpl(
    CryptoLibSignature_t* self)
{
    OS_Error_t err;

    err = OS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
        if (NULL != self->pubKey)
        {
            if (CryptoLibKey_getType(self->pubKey) != OS_CryptoKey_TYPE_RSA_PUB)
            {
                return OS_ERROR_INVALID_PARAMETER;
            }
            err = CryptoLibKey_writeRsaPub(self->pubKey, &self->mbedtls.rsa);
        }
        if (OS_SUCCESS == err && NULL != self->prvKey)
        {
            if (CryptoLibKey_getType(self->prvKey) != OS_CryptoKey_TYPE_RSA_PRV)
            {
                return OS_ERROR_INVALID_PARAMETER;
            }
            err = CryptoLibKey_writeRsaPrv(self->prvKey, &self->mbedtls.rsa);
        }
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static OS_Error_t
verifyHashImpl(
    CryptoLibSignature_t* self,
    const void*           hash,
    const size_t          hashSize,
    const void*           signature,
    const size_t          signatureSize,
    CryptoLibRng_t*       rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
        if (self->mbedtls.rsa.len != signatureSize)
        {
            err = OS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            // digest is matched to mbedTLS constants
            err = mbedtls_rsa_pkcs1_verify(&self->mbedtls.rsa,
                                           CryptoLibRng_getBytesMbedtls, rng,
                                           MBEDTLS_RSA_PUBLIC, self->digest, hashSize,
                                           hash, signature) != 0 ?
                  OS_ERROR_ABORTED : OS_SUCCESS;
        }
        break;
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static OS_Error_t
signHashImpl(
    CryptoLibSignature_t* self,
    const void*           hash,
    const size_t          hashSize,
    void*                 signature,
    size_t*               signatureSize,
    CryptoLibRng_t*       rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoSignature_ALG_RSA_PKCS1_V15:
    case OS_CryptoSignature_ALG_RSA_PKCS1_V21:
        if (self->mbedtls.rsa.len > *signatureSize)
        {
            err = OS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            // digest is matched to mbedTLS constants
            err = mbedtls_rsa_pkcs1_sign(&self->mbedtls.rsa,
                                         CryptoLibRng_getBytesMbedtls, rng,
                                         MBEDTLS_RSA_PRIVATE, self->digest, hashSize,
                                         hash, signature) != 0 ?
                  OS_ERROR_ABORTED : OS_SUCCESS;
        }
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    *signatureSize = self->mbedtls.rsa.len;

    return err;
}

// Public Functions ------------------------------------------------------------

OS_Error_t
CryptoLibSignature_init(
    CryptoLibSignature_t**         self,
    const CryptoLibKey_t*          prvKey,
    const CryptoLibKey_t*          pubKey,
    const OS_CryptoSignature_Alg_t algorithm,
    const OS_CryptoDigest_Alg_t    digest,
    const OS_Crypto_Memory_t*      memory)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);

    // We can have one of those keys be empty, but not both
    if (NULL == prvKey && NULL == pubKey)
    {
        Debug_LOG_ERROR("Must at least have non-NULL private or "
                        "public key");
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((err = initImpl(self, prvKey, pubKey, algorithm, digest,
                        memory)) == OS_SUCCESS)
    {
        if ((err = setKeyImpl(*self)) != OS_SUCCESS)
        {
            freeImpl(*self, memory);
        }
    }

    return err;
}

OS_Error_t
CryptoLibSignature_free(
    CryptoLibSignature_t*     self,
    const OS_Crypto_Memory_t* memory)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);

    return freeImpl(self, memory);
}

OS_Error_t
CryptoLibSignature_sign(
    CryptoLibSignature_t* self,
    const void*           hash,
    const size_t          hashSize,
    void*                 signature,
    size_t*               signatureSize,
    CryptoLibRng_t*       rng)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hash);
    CHECK_PTR_NOT_NULL(signature);
    CHECK_PTR_NOT_NULL(signatureSize);
    CHECK_PTR_NOT_NULL(rng);
    CHECK_VALUE_NOT_ZERO(hashSize);

    return (self->prvKey != NULL) ?
           signHashImpl(self, hash, hashSize, signature, signatureSize, rng) :
           OS_ERROR_ABORTED;
}

OS_Error_t
CryptoLibSignature_verify(
    CryptoLibSignature_t* self,
    const void*           hash,
    const size_t          hashSize,
    const void*           signature,
    const size_t          signatureSize,
    CryptoLibRng_t*       rng)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hash);
    CHECK_PTR_NOT_NULL(signature);
    CHECK_PTR_NOT_NULL(rng);
    CHECK_VALUE_NOT_ZERO(hashSize);
    CHECK_VALUE_NOT_ZERO(signatureSize);

    return (self->pubKey != NULL) ?
           verifyHashImpl(self, hash, hashSize, signature, signatureSize, rng) :
           OS_ERROR_ABORTED;
}