/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibDigest.h"

#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

#include "compiler.h"

#include <stdbool.h>
#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct CryptoLibDigest
{
    union
    {
        mbedtls_md5_context md5;
        mbedtls_sha256_context sha256;
    } mbedtls;
    OS_CryptoDigest_Alg_t algorithm;
    bool processed;
};

// Make sure these hold, otherwise stuff will break!
Debug_STATIC_ASSERT((int)OS_CryptoDigest_ALG_NONE     ==
                    (int)MBEDTLS_MD_NONE);
Debug_STATIC_ASSERT((int)OS_CryptoDigest_ALG_MD5      ==
                    (int)MBEDTLS_MD_MD5);
Debug_STATIC_ASSERT((int)OS_CryptoDigest_ALG_SHA256   ==
                    (int)MBEDTLS_MD_SHA256);

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(
    CryptoLibDigest_t**         self,
    const OS_CryptoDigest_Alg_t algorithm,
    const OS_Crypto_Memory_t*   memIf)
{
    seos_err_t err;
    CryptoLibDigest_t* dig;

    if ((dig = memIf->malloc(sizeof(CryptoLibDigest_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(dig, 0, sizeof(CryptoLibDigest_t));
    dig->algorithm = algorithm;
    dig->processed = false;

    switch (dig->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        mbedtls_md5_init(&dig->mbedtls.md5);
        err = mbedtls_md5_starts_ret(&dig->mbedtls.md5) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case OS_CryptoDigest_ALG_SHA256:
        mbedtls_sha256_init(&dig->mbedtls.sha256);
        err = mbedtls_sha256_starts_ret(&dig->mbedtls.sha256, 0) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (err != SEOS_SUCCESS)
    {
        memIf->free(dig);
    }

    *self = dig;

    return err;
}

static seos_err_t
freeImpl(
    CryptoLibDigest_t*        self,
    const OS_Crypto_Memory_t* memIf)
{
    seos_err_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        mbedtls_md5_free(&self->mbedtls.md5);
        break;
    case OS_CryptoDigest_ALG_SHA256:
        mbedtls_sha256_free(&self->mbedtls.sha256);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    memIf->free(self);

    return err;
}

static seos_err_t
finalizeImpl(
    CryptoLibDigest_t* self,
    void*              digest,
    size_t*            digestSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        if (*digestSize < OS_CryptoDigest_SIZE_MD5)
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            err = mbedtls_md5_finish_ret(&self->mbedtls.md5, digest) ||
                  mbedtls_md5_starts_ret(&self->mbedtls.md5) ?
                  SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        *digestSize = OS_CryptoDigest_SIZE_MD5;
        break;
    case OS_CryptoDigest_ALG_SHA256:
        if (*digestSize < OS_CryptoDigest_SIZE_SHA256)
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            err = mbedtls_sha256_finish_ret(&self->mbedtls.sha256, digest) ||
                  mbedtls_sha256_starts_ret(&self->mbedtls.sha256, 0) ?
                  SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        *digestSize = OS_CryptoDigest_SIZE_SHA256;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
processImpl(
    CryptoLibDigest_t* self,
    const void*        data,
    const size_t       len)
{
    switch (self->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        return mbedtls_md5_update_ret(&self->mbedtls.md5, data, len) ?
               SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    case OS_CryptoDigest_ALG_SHA256:
        return mbedtls_sha256_update_ret(&self->mbedtls.sha256, data, len) ?
               SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

static seos_err_t
cloneImpl(
    CryptoLibDigest_t*       self,
    const CryptoLibDigest_t* source)
{
    switch (self->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        mbedtls_md5_clone(&self->mbedtls.md5, &source->mbedtls.md5);
        break;
    case OS_CryptoDigest_ALG_SHA256:
        mbedtls_sha256_clone(&self->mbedtls.sha256, &source->mbedtls.sha256);
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_SUCCESS;
}

// Public Functions ------------------------------------------------------------

seos_err_t
CryptoLibDigest_init(
    CryptoLibDigest_t**         self,
    const OS_CryptoDigest_Alg_t algorithm,
    const OS_Crypto_Memory_t*   memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return initImpl(self, algorithm, memIf);
}

seos_err_t
CryptoLibDigest_free(
    CryptoLibDigest_t*        self,
    const OS_Crypto_Memory_t* memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
CryptoLibDigest_clone(
    CryptoLibDigest_t*       self,
    const CryptoLibDigest_t* source)
{
    if (NULL == self || NULL == source || self->algorithm != source->algorithm)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    self->processed = source->processed;

    return cloneImpl(self, source);
}

seos_err_t
CryptoLibDigest_process(
    CryptoLibDigest_t* self,
    const void*        data,
    const size_t       len)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == data || 0 == len)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = processImpl(self, data, len);
    self->processed |= (SEOS_SUCCESS == err);

    return err;
}

seos_err_t
CryptoLibDigest_finalize(
    CryptoLibDigest_t* self,
    void*              digest,
    size_t*            digestSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == digest || NULL == digestSize || 0 == *digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = !self->processed ?
          SEOS_ERROR_ABORTED : finalizeImpl(self, digest, digestSize);

    // We want to be able to re-use the digest object after finalizing it
    if (SEOS_SUCCESS == err)
    {
        self->processed = false;
    }

    return err;
}