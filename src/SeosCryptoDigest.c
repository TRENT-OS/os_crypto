/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoDigest.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(SeosCryptoDigest*   self,
         SeosCrypto_MemIf*   memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        mbedtls_md5_init(&self->mbedtls.md5);
        retval = mbedtls_md5_starts_ret(&self->mbedtls.md5) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoDigest_Algorithm_SHA256:
        mbedtls_sha256_init(&self->mbedtls.sha256);
        retval = mbedtls_sha256_starts_ret(&self->mbedtls.sha256, 0) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
freeImpl(SeosCryptoDigest*   self,
         SeosCrypto_MemIf*   memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        mbedtls_md5_free(&self->mbedtls.md5);
        retval = SEOS_SUCCESS;
        break;
    case SeosCryptoDigest_Algorithm_SHA256:
        mbedtls_sha256_free(&self->mbedtls.sha256);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
finalizeImpl(SeosCryptoDigest*  self,
             void*              digest,
             size_t*            digestSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        if (*digestSize < SeosCryptoDigest_SIZE_MD5)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            retval = mbedtls_md5_finish_ret(&self->mbedtls.md5, digest) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            *digestSize = SeosCryptoDigest_SIZE_MD5;
        }
        break;
    case SeosCryptoDigest_Algorithm_SHA256:
        if (*digestSize < SeosCryptoDigest_SIZE_SHA256)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            retval = mbedtls_sha256_finish_ret(&self->mbedtls.sha256, digest) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            *digestSize = SeosCryptoDigest_SIZE_SHA256;
        }
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
updateImpl(SeosCryptoDigest*        self,
           const void*              data,
           size_t                   len)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        retval = mbedtls_md5_update_ret(&self->mbedtls.md5, data, len) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoDigest_Algorithm_SHA256:
        retval = mbedtls_sha256_update_ret(&self->mbedtls.sha256, data, len) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }
    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoDigest_init(SeosCryptoDigest*              self,
                      SeosCrypto_MemIf*              memIf,
                      SeosCryptoDigest_Algorithm     algorithm)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm = algorithm;
    self->updated   = false;
    self->finalized = false;

    return initImpl(self, memIf);
}

seos_err_t
SeosCryptoDigest_free(SeosCryptoDigest*    self,
                      SeosCrypto_MemIf*    memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoDigest_update(SeosCryptoDigest*    self,
                        const void*         data,
                        size_t              len)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == data || 0 == len)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = self->finalized ?
             SEOS_ERROR_ABORTED : updateImpl(self, data, len);
    self->updated |= (SEOS_SUCCESS == retval);

    return retval;
}

seos_err_t
SeosCryptoDigest_finalize(SeosCryptoDigest* self,
                          void*             digest,
                          size_t*           digestSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == digest || NULL == digestSize || 0 == *digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = !self->updated || self->finalized ?
             SEOS_ERROR_ABORTED : finalizeImpl(self, digest, digestSize);
    self->finalized |= (SEOS_SUCCESS == retval);

    return retval;
}