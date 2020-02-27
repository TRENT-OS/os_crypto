/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Digest.h"

#include "compiler.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(
    SeosCryptoLib_Digest*      self,
    const SeosCryptoApi_MemIf* memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Digest_ALG_MD5:
        mbedtls_md5_init(&self->mbedtls.md5);
        err = mbedtls_md5_starts_ret(&self->mbedtls.md5) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Digest_ALG_SHA256:
        mbedtls_sha256_init(&self->mbedtls.sha256);
        err = mbedtls_sha256_starts_ret(&self->mbedtls.sha256, 0) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
freeImpl(
    SeosCryptoLib_Digest*      self,
    const SeosCryptoApi_MemIf* memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Digest_ALG_MD5:
        mbedtls_md5_free(&self->mbedtls.md5);
        err = SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Digest_ALG_SHA256:
        mbedtls_sha256_free(&self->mbedtls.sha256);
        err = SEOS_SUCCESS;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
finalizeImpl(
    SeosCryptoLib_Digest* self,
    void*                 digest,
    size_t*               digestSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Digest_ALG_MD5:
        if (*digestSize < SeosCryptoApi_Digest_SIZE_MD5)
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            err = mbedtls_md5_finish_ret(&self->mbedtls.md5, digest) ||
                  mbedtls_md5_starts_ret(&self->mbedtls.md5) ?
                  SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        *digestSize = SeosCryptoApi_Digest_SIZE_MD5;
        break;
    case SeosCryptoApi_Digest_ALG_SHA256:
        if (*digestSize < SeosCryptoApi_Digest_SIZE_SHA256)
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            err = mbedtls_sha256_finish_ret(&self->mbedtls.sha256, digest) ||
                  mbedtls_sha256_starts_ret(&self->mbedtls.sha256, 0) ?
                  SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        *digestSize = SeosCryptoApi_Digest_SIZE_SHA256;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
processImpl(
    SeosCryptoLib_Digest* self,
    const void*           data,
    const size_t          len)
{
    switch (self->algorithm)
    {
    case SeosCryptoApi_Digest_ALG_MD5:
        return mbedtls_md5_update_ret(&self->mbedtls.md5, data, len) ?
               SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    case SeosCryptoApi_Digest_ALG_SHA256:
        return mbedtls_sha256_update_ret(&self->mbedtls.sha256, data, len) ?
               SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

static seos_err_t
cloneImpl(
    SeosCryptoLib_Digest*       self,
    const SeosCryptoLib_Digest* source)
{
    switch (self->algorithm)
    {
    case SeosCryptoApi_Digest_ALG_MD5:
        mbedtls_md5_clone(&self->mbedtls.md5, &source->mbedtls.md5);
        break;
    case SeosCryptoApi_Digest_ALG_SHA256:
        mbedtls_sha256_clone(&self->mbedtls.sha256, &source->mbedtls.sha256);
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_SUCCESS;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoLib_Digest_init(
    SeosCryptoLib_Digest*          self,
    const SeosCryptoApi_MemIf*     memIf,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm = algorithm;
    self->processed = false;

    return initImpl(self, memIf);
}

seos_err_t
SeosCryptoLib_Digest_free(
    SeosCryptoLib_Digest*      self,
    const SeosCryptoApi_MemIf* memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoLib_Digest_clone(
    SeosCryptoLib_Digest*       self,
    const SeosCryptoLib_Digest* source)
{
    if (NULL == self || NULL == source || self->algorithm != source->algorithm)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    self->processed = source->processed;

    return cloneImpl(self, source);
}

seos_err_t
SeosCryptoLib_Digest_process(
    SeosCryptoLib_Digest* self,
    const void*           data,
    const size_t          len)
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
SeosCryptoLib_Digest_finalize(
    SeosCryptoLib_Digest* self,
    void*                 digest,
    size_t*               digestSize)
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