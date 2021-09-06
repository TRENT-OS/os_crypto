/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibDigest.h"

#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

#include "lib_macros/Check.h"

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

static OS_Error_t
initImpl(
    CryptoLibDigest_t**         self,
    const OS_CryptoDigest_Alg_t algorithm,
    const OS_Crypto_Memory_t*   memory)
{
    OS_Error_t err;
    CryptoLibDigest_t* dig;

    if ((dig = memory->calloc(1, sizeof(CryptoLibDigest_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(dig, 0, sizeof(CryptoLibDigest_t));
    dig->algorithm = algorithm;
    dig->processed = false;

    switch (dig->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        mbedtls_md5_init(&dig->mbedtls.md5);
        err = mbedtls_md5_starts_ret(&dig->mbedtls.md5) ?
              OS_ERROR_ABORTED : OS_SUCCESS;
        break;
    case OS_CryptoDigest_ALG_SHA256:
        mbedtls_sha256_init(&dig->mbedtls.sha256);
        err = mbedtls_sha256_starts_ret(&dig->mbedtls.sha256, 0) ?
              OS_ERROR_ABORTED : OS_SUCCESS;
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    if (err != OS_SUCCESS)
    {
        memory->free(dig);
    }

    *self = dig;

    return err;
}

static OS_Error_t
freeImpl(
    CryptoLibDigest_t*        self,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err;

    err = OS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        mbedtls_md5_free(&self->mbedtls.md5);
        break;
    case OS_CryptoDigest_ALG_SHA256:
        mbedtls_sha256_free(&self->mbedtls.sha256);
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    memory->free(self);

    return err;
}

static OS_Error_t
finalizeImpl(
    CryptoLibDigest_t* self,
    void*              digest,
    size_t*            digestSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        if (*digestSize < OS_CryptoDigest_SIZE_MD5)
        {
            err = OS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            err = mbedtls_md5_finish_ret(&self->mbedtls.md5, digest) ||
                  mbedtls_md5_starts_ret(&self->mbedtls.md5) ?
                  OS_ERROR_ABORTED : OS_SUCCESS;
        }
        *digestSize = OS_CryptoDigest_SIZE_MD5;
        break;
    case OS_CryptoDigest_ALG_SHA256:
        if (*digestSize < OS_CryptoDigest_SIZE_SHA256)
        {
            err = OS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            err = mbedtls_sha256_finish_ret(&self->mbedtls.sha256, digest) ||
                  mbedtls_sha256_starts_ret(&self->mbedtls.sha256, 0) ?
                  OS_ERROR_ABORTED : OS_SUCCESS;
        }
        *digestSize = OS_CryptoDigest_SIZE_SHA256;
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static OS_Error_t
processImpl(
    CryptoLibDigest_t* self,
    const void*        data,
    const size_t       len)
{
    switch (self->algorithm)
    {
    case OS_CryptoDigest_ALG_MD5:
        return mbedtls_md5_update_ret(&self->mbedtls.md5, data, len) ?
               OS_ERROR_ABORTED : OS_SUCCESS;
    case OS_CryptoDigest_ALG_SHA256:
        return mbedtls_sha256_update_ret(&self->mbedtls.sha256, data, len) ?
               OS_ERROR_ABORTED : OS_SUCCESS;
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    return OS_ERROR_GENERIC;
}

static OS_Error_t
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
        return OS_ERROR_NOT_SUPPORTED;
    }

    return OS_SUCCESS;
}

// Public Functions ------------------------------------------------------------

OS_Error_t
CryptoLibDigest_init(
    CryptoLibDigest_t**         self,
    const OS_CryptoDigest_Alg_t algorithm,
    const OS_Crypto_Memory_t*   memory)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);

    return initImpl(self, algorithm, memory);
}

OS_Error_t
CryptoLibDigest_clone(
    CryptoLibDigest_t**       self,
    const CryptoLibDigest_t*  source,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(source);

    if ((err = initImpl(self, source->algorithm, memory)) == OS_SUCCESS)
    {
        (*self)->processed = source->processed;
        if ((err = cloneImpl(*self, source)) != OS_SUCCESS)
        {
            freeImpl(*self, memory);
        }
    }

    return err;
}

OS_Error_t
CryptoLibDigest_free(
    CryptoLibDigest_t*        self,
    const OS_Crypto_Memory_t* memory)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);

    return freeImpl(self, memory);
}

OS_Error_t
CryptoLibDigest_process(
    CryptoLibDigest_t* self,
    const void*        data,
    const size_t       len)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(data);
    CHECK_VALUE_NOT_ZERO(len);

    err = processImpl(self, data, len);
    self->processed |= (OS_SUCCESS == err);

    return err;
}

OS_Error_t
CryptoLibDigest_finalize(
    CryptoLibDigest_t* self,
    void*              digest,
    size_t*            digestSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(digest);
    CHECK_PTR_NOT_NULL(digestSize);
    CHECK_VALUE_NOT_ZERO(*digestSize);

    err = !self->processed ?
          OS_ERROR_ABORTED : finalizeImpl(self, digest, digestSize);

    // We want to be able to re-use the digest object after finalizing it
    if (OS_SUCCESS == err)
    {
        self->processed = false;
    }

    return err;
}