/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Mac.h"

#include "LibDebug/Debug.h"
#include "compiler.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(
    SeosCryptoLib_Mac*         self,
    const SeosCryptoApi_MemIf* memIf)
{
    UNUSED_VAR(memIf);
    mbedtls_md_type_t type;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Mac_ALG_HMAC_MD5:
        type = MBEDTLS_MD_MD5;
        break;
    case SeosCryptoApi_Mac_ALG_HMAC_SHA256:
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
freeImpl(
    SeosCryptoLib_Mac*         self,
    const SeosCryptoApi_MemIf* memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Mac_ALG_HMAC_MD5:
    case SeosCryptoApi_Mac_ALG_HMAC_SHA256:
        mbedtls_md_free(&self->mbedtls.md);
        err = SEOS_SUCCESS;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
startImpl(
    SeosCryptoLib_Mac* self,
    const void*        secret,
    const size_t       secretSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Mac_ALG_HMAC_MD5:
    case SeosCryptoApi_Mac_ALG_HMAC_SHA256:
        err = mbedtls_md_hmac_starts(&self->mbedtls.md, secret, secretSize) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
processImpl(
    SeosCryptoLib_Mac* self,
    const void*        data,
    const size_t       dataSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Mac_ALG_HMAC_MD5:
    case SeosCryptoApi_Mac_ALG_HMAC_SHA256:
        err = mbedtls_md_hmac_update(&self->mbedtls.md, data, dataSize) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static seos_err_t
finalizeImpl(
    SeosCryptoLib_Mac* self,
    void*              mac,
    size_t*            macSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoApi_Mac_ALG_HMAC_MD5:
        if (*macSize < SeosCryptoApi_Mac_SIZE_HMAC_MD5)
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        *macSize = SeosCryptoApi_Mac_SIZE_HMAC_MD5;
        break;
    case SeosCryptoApi_Mac_ALG_HMAC_SHA256:
        if (*macSize < SeosCryptoApi_Mac_SIZE_HMAC_SHA256)
        {
            err = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        *macSize = SeosCryptoApi_Mac_SIZE_HMAC_SHA256;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (SEOS_SUCCESS == err)
    {
        // We do not need to reset anything here, as the internal state machine
        // will force the user to call start() again first, which re-sets the
        // hmac and the underlying digest context.
        err = mbedtls_md_hmac_finish(&self->mbedtls.md, mac) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }

    return err;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoMac_init(
    SeosCryptoLib_Mac*          self,
    const SeosCryptoApi_MemIf*  memIf,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm = algorithm;
    self->started   = false;
    self->processed = false;

    return initImpl(self, memIf);
}

seos_err_t
SeosCryptoMac_free(
    SeosCryptoLib_Mac*         self,
    const SeosCryptoApi_MemIf* memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoMac_start(
    SeosCryptoLib_Mac* self,
    const void*        secret,
    const size_t       secretSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == secret || 0 == secretSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = self->started || self->processed ?
          SEOS_ERROR_ABORTED : startImpl(self, secret, secretSize);
    self->started |= (SEOS_SUCCESS == err);

    return err;
}

seos_err_t
SeosCryptoMac_process(
    SeosCryptoLib_Mac* self,
    const void*        data,
    const size_t       dataSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == data || 0 == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = !self->started ?
          SEOS_ERROR_ABORTED : processImpl(self, data, dataSize);
    self->processed |= (SEOS_SUCCESS == err);

    return err;
}

seos_err_t
SeosCryptoMac_finalize(
    SeosCryptoLib_Mac* self,
    void*              mac,
    size_t*            macSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == mac || NULL == macSize || 0 == *macSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = !self->started || !self->processed ?
          SEOS_ERROR_ABORTED : finalizeImpl(self, mac, macSize);

    // Finalize also resets the underlying algorithms, so that we can re-use the
    // MAC object again
    if (err == SEOS_SUCCESS)
    {
        self->started = false;
        self->processed = false;
    }

    return err;
}