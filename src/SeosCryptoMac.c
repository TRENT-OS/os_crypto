/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoMac.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(SeosCryptoMac*             self,
         const SeosCrypto_MemIf*    memIf)
{
    UNUSED_VAR(memIf);
    mbedtls_md_type_t type;

    switch (self->algorithm)
    {
    case SeosCryptoMac_Algorithm_HMAC_MD5:
        type = MBEDTLS_MD_MD5;
        break;
    case SeosCryptoMac_Algorithm_HMAC_SHA256:
        type = MBEDTLS_MD_SHA256;
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    mbedtls_md_init(&self->mbedtls.md);
    return mbedtls_md_setup(&self->mbedtls.md, mbedtls_md_info_from_type(type), 1) ?
           SEOS_ERROR_ABORTED : SEOS_SUCCESS;
}

static seos_err_t
freeImpl(SeosCryptoMac*             self,
         const SeosCrypto_MemIf*    memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoMac_Algorithm_HMAC_MD5:
    case SeosCryptoMac_Algorithm_HMAC_SHA256:
        mbedtls_md_free(&self->mbedtls.md);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
startImpl(SeosCryptoMac*  self,
          const void*     secret,
          const size_t    secretSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoMac_Algorithm_HMAC_MD5:
    case SeosCryptoMac_Algorithm_HMAC_SHA256:
        retval = mbedtls_md_hmac_starts(&self->mbedtls.md, secret, secretSize) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
processImpl(SeosCryptoMac*  self,
            const void*     data,
            const size_t    dataSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoMac_Algorithm_HMAC_MD5:
    case SeosCryptoMac_Algorithm_HMAC_SHA256:
        retval = mbedtls_md_hmac_update(&self->mbedtls.md, data, dataSize) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
finalizeImpl(SeosCryptoMac*  self,
             void*           mac,
             size_t*         macSize)
{
    seos_err_t retval;

    retval = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoMac_Algorithm_HMAC_MD5:
        if (*macSize < SeosCryptoMac_Size_HMAC_MD5)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        *macSize = SeosCryptoMac_Size_HMAC_MD5;
        break;
    case SeosCryptoMac_Algorithm_HMAC_SHA256:
        if (*macSize < SeosCryptoMac_Size_HMAC_SHA256)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        *macSize = SeosCryptoMac_Size_HMAC_SHA256;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (SEOS_SUCCESS == retval)
    {
        retval = mbedtls_md_hmac_finish(&self->mbedtls.md, mac) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }

    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoMac_init(SeosCryptoMac*                 self,
                   const SeosCrypto_MemIf*        memIf,
                   const SeosCryptoMac_Algorithm  algorithm)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm = algorithm;
    self->started   = false;
    self->processed = false;
    self->finalized = false;

    return initImpl(self, memIf);
}

seos_err_t
SeosCryptoMac_free(SeosCryptoMac*           self,
                   const SeosCrypto_MemIf*  memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoMac_start(SeosCryptoMac*    self,
                    const void*       secret,
                    const size_t      secretSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == secret || 0 == secretSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = self->started || self->processed || self->finalized ?
             SEOS_ERROR_ABORTED : startImpl(self, secret, secretSize);
    self->started |= (SEOS_SUCCESS == retval);

    return retval;
}

seos_err_t
SeosCryptoMac_process(SeosCryptoMac*    self,
                      const void*       data,
                      const size_t      dataSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == data || 0 == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = !self->started || self->finalized ?
             SEOS_ERROR_ABORTED : processImpl(self, data, dataSize);
    self->processed |= (SEOS_SUCCESS == retval);

    return retval;
}

seos_err_t
SeosCryptoMac_finalize(SeosCryptoMac*   self,
                       void*            mac,
                       size_t*          macSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == mac || NULL == macSize || 0 == *macSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = !self->started || !self->processed || self->finalized ?
             SEOS_ERROR_ABORTED : finalizeImpl(self, mac, macSize);
    self->finalized |= (SEOS_SUCCESS == retval);

    return retval;
}