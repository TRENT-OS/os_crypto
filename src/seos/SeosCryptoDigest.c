/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoDigest.h"
#include "LibDebug/Debug.h"
#include "SeosCryptoCipher.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
finalize(SeosCryptoDigest* self,
         char const* data,
         size_t len,
         char* digest)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        retval = (data != NULL &&
                  mbedtls_md5_update_ret(&self->agorithmCtx.md5,
                                         (const unsigned char*) data,
                                         len))
                 || mbedtls_md5_finish_ret(&self->agorithmCtx.md5,
                                           (unsigned char*) digest) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoDigest_Algorithm_SHA256:
        retval = (data != NULL &&
                  mbedtls_sha256_update_ret(&self->agorithmCtx.sha256,
                                            (const unsigned char*) data,
                                            len))
                 || mbedtls_sha256_finish_ret(&self->agorithmCtx.sha256,
                                              (unsigned char*) digest) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

seos_err_t
update(SeosCryptoDigest* self,
       const char* data,
       size_t len)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        retval = mbedtls_md5_update_ret(&self->agorithmCtx.md5,
                                        (unsigned char*) data,
                                        len) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoDigest_Algorithm_SHA256:
        retval = mbedtls_sha256_update_ret(&self->agorithmCtx.sha256,
                                           (unsigned char*) data,
                                           len) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoDigest_init(SeosCryptoDigest* self,
                      SeosCryptoDigest_Algorithm algorithm,
                      char* iv,
                      size_t ivLen)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        mbedtls_md5_init(&self->agorithmCtx.md5);
        retval = mbedtls_md5_starts_ret(&self->agorithmCtx.md5) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoDigest_Algorithm_SHA256:
        mbedtls_sha256_init(&self->agorithmCtx.sha256);
        retval = mbedtls_sha256_starts_ret(&self->agorithmCtx.sha256, 0) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    self->algorithm = algorithm;
    return retval;
}

void
SeosCryptoDigest_deInit(SeosCryptoDigest* self)
{
    Debug_ASSERT_SELF(self);

    switch (self->algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        mbedtls_md5_free(&self->agorithmCtx.md5);
        break;
    case SeosCryptoDigest_Algorithm_SHA256:
        mbedtls_sha256_free(&self->agorithmCtx.sha256);
        break;
    default:
        break;
    }
}

seos_err_t
SeosCryptoDigest_update(SeosCryptoDigest* self,
                        const char* data,
                        size_t len)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == data)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = update(self, data, len);
    }
    return retval;
}

seos_err_t
SeosCryptoDigest_finalize(SeosCryptoDigest* self,
                          const char* data,
                          size_t len,
                          char** digest,
                          size_t* digestSize)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == digest || NULL == digestSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        size_t algoDigestSize = SeosCryptoDigest_getDigestSize(self);

        /* Check Buffer (either provided or internal) and Size*/
        if (NULL == *digest)
        {
            *digest = self->digest;
        }
        else if (*digestSize < algoDigestSize)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        { /* do nothing, writing is safe */ }

        if (retval != SEOS_ERROR_BUFFER_TOO_SMALL)
        {
            *digestSize = algoDigestSize;
            retval      = finalize(self, data, len, *digest);
        }
    }
    return retval;
}

seos_err_t
SeosCryptoDigest_verify(SeosCryptoDigest* self,
                        const char* data,
                        size_t len,
                        char* expectedDigest)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == data || NULL == expectedDigest)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        char* digest = NULL;
        size_t digestSize = 0;
        seos_err_t retval = SeosCryptoDigest_finalize(self,
                                                      data,
                                                      len,
                                                      &digest,
                                                      &digestSize);

        if (SEOS_SUCCESS == retval
            && memcmp(digest, expectedDigest, digestSize))
        {
            retval = SEOS_ERROR_GENERIC;
        }
    }
    return retval;
}

size_t
SeosCryptoDigest_getDigestSize(SeosCryptoDigest* self)
{
    switch (self->algorithm)
    {
    case SeosCryptoDigest_Algorithm_MD5:
        return SeosCryptoDigest_SIZE_MD5;
    case SeosCryptoDigest_Algorithm_SHA256:
        return SeosCryptoDigest_SIZE_SHA256;
    default:
        Debug_ASSERT(false);
        return 0;
    }
}
