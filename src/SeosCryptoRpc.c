/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoRpc.h"
#include "SeosCrypto.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <stdlib.h>


// At the moment we manage one handle only.
SeosCryptoRpc* handle = NULL;

static inline bool
isValidHandle(SeosCryptoRpc* self)
{
    return handle != NULL && self == handle;
}

static inline bool
registerHandle(SeosCryptoRpc* self)
{
    bool retval = true;

    if (handle != NULL)
    {
        retval = false;
    }
    else
    {
        handle = self;
    }
    return retval;
}

static inline void
deregisterHandle(SeosCryptoRpc* self)
{
    handle = NULL;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoRpc_init(SeosCryptoRpc*   self,
                   SeosCrypto*      seosCryptoApiCtx,
                   void*            serverDataport)
{
    Debug_ASSERT_SELF(self);
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == seosCryptoApiCtx || NULL == serverDataport)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    memset(self, 0, sizeof(*self));
    self->seosCryptoApi     = SeosCrypto_TO_SEOS_CRYPTO_CTX(seosCryptoApiCtx);
    self->serverDataport    = serverDataport;
    retval                  = SEOS_SUCCESS;

    if (!registerHandle(self))
    {
        SeosCryptoRpc_deInit(self);
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
    }
exit:
    return retval;
}

void
SeosCryptoRpc_deInit(SeosCryptoRpc* self)
{
    return;
}

seos_err_t
SeosCryptoRpc_getRandomData(SeosCryptoRpc* self,
                            size_t dataLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if (dataLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCrypto_getRandomData(self->seosCryptoApi,
                                          self->serverDataport,
                                          dataLen);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_digestInit(SeosCryptoRpc*                 self,
                         SeosCrypto_DigestHandle*    pDigestHandle,
                         SeosCryptoDigest_Algorithm     algorithm,
                         size_t                         ivLen)
{
    Debug_LOG_TRACE("%s: algo %d, ivLen %u",
                    __func__,
                    algorithm,
                    ivLen);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_digestInit(self->seosCryptoApi,
                                       pDigestHandle,
                                       algorithm,
                                       self->serverDataport,
                                       ivLen);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_digestClose(SeosCryptoRpc*            self,
                          SeosCrypto_DigestHandle   digestHandle)
{
    Debug_LOG_TRACE("%s", __func__);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_digestClose(self->seosCryptoApi,
                                        digestHandle);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_digestUpdate(SeosCryptoRpc*           self,
                           SeosCrypto_DigestHandle  digestHandle,
                           size_t                   len)
{
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if (len > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCrypto_digestUpdate(self->seosCryptoApi,
                                         digestHandle,
                                         self->serverDataport,
                                         len);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_digestFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_DigestHandle    digestHandle,
                             size_t                     len)
{
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t  retval  = SEOS_ERROR_GENERIC;
    void*       digest  = NULL;
    size_t      size    = 0;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if (len > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCrypto_digestFinalize(self->seosCryptoApi,
                                           digestHandle,
                                           len ?
                                           self->serverDataport : NULL,
                                           len,
                                           &digest,
                                           &size);
    }
    if (SEOS_SUCCESS == retval)
    {
        if (NULL == digest)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            void* dest = memcpy(self->serverDataport, &size, sizeof(size))
                         + sizeof(size);
            memcpy(dest, digest, size);
        }
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_keyGenerate(SeosCryptoRpc*                self,
                          SeosCrypto_KeyHandle*         pKeyHandle,
                          unsigned int                  algorithm,
                          unsigned int                  flags,
                          size_t                        lenBits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_keyGenerate(self->seosCryptoApi,
                                        pKeyHandle,
                                        algorithm,
                                        flags,
                                        lenBits);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_keyImport(SeosCryptoRpc*              self,
                        SeosCrypto_KeyHandle*       pKeyHandle,
                        unsigned int                algorithm,
                        unsigned int                flags,
                        size_t                      keyImportLenBits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_keyImport(self->seosCryptoApi,
                                      pKeyHandle,
                                      algorithm,
                                      flags,
                                      self->serverDataport,
                                      keyImportLenBits);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_keyExport(SeosCryptoRpc*         self,
                        SeosCrypto_KeyHandle   keyHandle,
                        void*                  buffer,
                        size_t                 bufferLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_keyExport(self->seosCryptoApi,
                                      keyHandle,
                                      buffer,
                                      bufferLen);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_keyClose(SeosCryptoRpc*          self,
                       SeosCrypto_KeyHandle    keyHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_keyClose(self->seosCryptoApi,
                                     keyHandle);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_cipherInit(SeosCryptoRpc*             self,
                         SeosCrypto_CipherHandle*   pCipherHandle,
                         SeosCryptoCipher_Algorithm algorithm,
                         SeosCrypto_KeyHandle       keyHandle,
                         size_t                     ivLen)
{
    Debug_LOG_TRACE("%s: algo %d, keyHandle %p, ivLen %zu",
                    __func__,
                    algorithm,
                    keyHandle
                    ivLen);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_cipherInit(self->seosCryptoApi,
                                       pCipherHandle,
                                       algorithm,
                                       keyHandle,
                                       self->serverDataport,
                                       ivLen);
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_cipherClose(SeosCryptoRpc*            self,
                          SeosCrypto_CipherHandle   cipherHandle)
{
    Debug_LOG_TRACE("%s", __func__);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (isValidHandle(self))
    {
        retval = SeosCrypto_cipherClose(self->seosCryptoApi, cipherHandle);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_cipherUpdate(SeosCryptoRpc*           self,
                           SeosCrypto_CipherHandle  cipherHandle,
                           size_t                   len)
{
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t  retval      = SEOS_ERROR_GENERIC;
    void*       output      = NULL;
    size_t      outputSize  = 0;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if (len > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCrypto_cipherUpdate(self->seosCryptoApi,
                                         cipherHandle,
                                         self->serverDataport,
                                         len,
                                         &output,
                                         &outputSize);
    }
    if (SEOS_SUCCESS == retval)
    {
        if (outputSize + sizeof(outputSize) > PAGE_SIZE)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            void* dest = memcpy(self->serverDataport,
                                &outputSize,
                                sizeof(outputSize)) + sizeof(outputSize);
            memcpy(dest, output, outputSize);
        }
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_cipherUpdateAd(SeosCryptoRpc*           self,
                             SeosCrypto_CipherHandle  cipherHandle,
                             size_t                   len)
{
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t  retval      = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if (len > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCrypto_cipherUpdateAd(self->seosCryptoApi,
                                           cipherHandle,
                                           self->serverDataport,
                                           len);
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_CipherHandle    cipherHandle)
{
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t  retval      = SEOS_ERROR_GENERIC;
    void*       output      = NULL;
    size_t      outputSize  = 0;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_cipherFinalize(self->seosCryptoApi,
                                           cipherHandle,
                                           &output,
                                           &outputSize);
    }
    if (SEOS_SUCCESS == retval)
    {
        if (outputSize + sizeof(outputSize) > PAGE_SIZE)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            void* dest = memcpy(self->serverDataport,
                                &outputSize,
                                sizeof(outputSize)) + sizeof(outputSize);
            memcpy(dest, output, outputSize);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_cipherVerifyTag(SeosCryptoRpc*             self,
                              SeosCrypto_CipherHandle    cipherHandle,
                              size_t                     len)
{
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t  retval      = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if (len > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCrypto_cipherVerifyTag(self->seosCryptoApi,
                                            cipherHandle,
                                            self->serverDataport,
                                            len);
    }

    return retval;
}