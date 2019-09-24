/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCrypto.h"
#include "SeosCryptoRpc.h"

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
SeosCryptoRpc_rngGetBytes(SeosCryptoRpc* self,
                          size_t dataLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    void*      rnd  = NULL;

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
        rnd = self->serverDataport;
        retval = SeosCrypto_rngGetBytes(self->seosCryptoApi,
                                        &rnd,
                                        dataLen);
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_rngReSeed(SeosCryptoRpc* self,
                        size_t seedLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        retval = SeosCrypto_rngReSeed(self->seosCryptoApi,
                                      self->serverDataport,
                                      seedLen);
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
SeosCryptoRpc_keyInit(SeosCryptoRpc*                   self,
                      SeosCrypto_KeyHandle*            keyHandle,
                      unsigned int                     type,
                      SeosCryptoKey_Flag               flags,
                      size_t                           bits)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyInit(self->seosCryptoApi, keyHandle, type, flags, bits);
}

seos_err_t
SeosCryptoRpc_keyGenerate(SeosCryptoRpc*               self,
                          SeosCrypto_KeyHandle         keyHandle)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyGenerate(self->seosCryptoApi, keyHandle);
}

seos_err_t
SeosCryptoRpc_keyGeneratePair(SeosCryptoRpc*           self,
                              SeosCrypto_KeyHandle     prvKeyHandle,
                              SeosCrypto_KeyHandle     pubKeyHandle)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyGeneratePair(self->seosCryptoApi, prvKeyHandle, pubKeyHandle);
}

seos_err_t
SeosCryptoRpc_keyImport(SeosCryptoRpc*                 self,
                        SeosCrypto_KeyHandle           keyHandle,
                        SeosCrypto_KeyHandle           wrapKeyHandle,
                        size_t                         keyLen)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyImport(self->seosCryptoApi, keyHandle, wrapKeyHandle,
                                self->serverDataport, keyLen);
}

seos_err_t
SeosCryptoRpc_keyExport(SeosCryptoRpc*                 self,
                        SeosCrypto_KeyHandle           keyHandle,
                        SeosCrypto_KeyHandle           wrapKeyHandle)
{
    seos_err_t  retval      = SEOS_ERROR_GENERIC;
    void*       output      = NULL;
    size_t      outputSize  = 0;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if ((retval = SeosCrypto_keyExport(self->seosCryptoApi, keyHandle,
                                            wrapKeyHandle, &output, &outputSize)) == SEOS_SUCCESS)
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
SeosCryptoRpc_keyDeInit(SeosCryptoRpc*                  self,
                        SeosCrypto_KeyHandle            keyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyDeInit(self->seosCryptoApi, keyHandle);
}

seos_err_t
SeosCryptoRpc_agreementInit(SeosCryptoRpc*                   self,
                            SeosCrypto_AgreementHandle*      pAgrHandle,
                            unsigned int                     algorithm,
                            SeosCrypto_KeyHandle             prvHandle)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_agreementInit(self->seosCryptoApi, pAgrHandle, algorithm, prvHandle);
}

seos_err_t
SeosCryptoRpc_agreementComputeShared(SeosCryptoRpc*                self,
                                     SeosCrypto_AgreementHandle    agrHandle,
                                     SeosCrypto_KeyHandle          pubHandle)
{
    seos_err_t  retval      = SEOS_ERROR_GENERIC;
    void*       shared      = NULL;
    size_t      sharedSize  = 0;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if ((retval = SeosCrypto_agreementComputeShared(self->seosCryptoApi,
                                                         agrHandle, pubHandle, &shared, &sharedSize)) == SEOS_SUCCESS)
    {
        if (sharedSize + sizeof(sharedSize) > PAGE_SIZE)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            memcpy(self->serverDataport, &sharedSize, sizeof(sharedSize));
            memcpy(self->serverDataport + sizeof(sharedSize), shared, sharedSize);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_agreementDeInit(SeosCryptoRpc*                self,
                              SeosCrypto_AgreementHandle    agrHandle)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_agreementDeInit(self->seosCryptoApi, agrHandle);
}

seos_err_t
SeosCryptoRpc_signatureInit(SeosCryptoRpc*                   self,
                            SeosCrypto_SignatureHandle*      pSigHandle,
                            unsigned int                     algorithm,
                            SeosCrypto_KeyHandle             prvHandle,
                            SeosCrypto_KeyHandle             pubHandle)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_signatureInit(self->seosCryptoApi, pSigHandle, algorithm, prvHandle,
                                    pubHandle);
}

seos_err_t
SeosCryptoRpc_signatureVerify(SeosCryptoRpc*                self,
                              SeosCrypto_SignatureHandle    sigHandle,
                              size_t                        hashSize,
                              size_t                        signatureSize)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_signatureVerify(self->seosCryptoApi, sigHandle, self->serverDataport,
                                      hashSize, self->serverDataport + hashSize, signatureSize);
}

seos_err_t
SeosCryptoRpc_signatureSign(SeosCryptoRpc*                self,
                            SeosCrypto_SignatureHandle    sigHandle,
                            size_t                        hashSize)
{
    seos_err_t      retval = SEOS_ERROR_GENERIC;
    size_t          sigSize = 0;
    void*           pSig = NULL;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    else if ((retval = SeosCrypto_signatureSign(self->seosCryptoApi, sigHandle,
                                                self->serverDataport, hashSize, &pSig, &sigSize)) == SEOS_SUCCESS)
    {
        if (sigSize + sizeof(sigSize) > PAGE_SIZE)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            memcpy(self->serverDataport, &sigSize, sizeof(sigSize));
            memcpy(self->serverDataport + sizeof(sigSize), pSig, sigSize);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_signatureDeInit(SeosCryptoRpc*                  self,
                              SeosCrypto_SignatureHandle      sigHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_signatureDeInit(self->seosCryptoApi, sigHandle);
}

seos_err_t
SeosCryptoRpc_cipherInit(SeosCryptoRpc*                 self,
                         SeosCrypto_CipherHandle*       pCipherHandle,
                         SeosCryptoCipher_Algorithm     algorithm,
                         SeosCrypto_KeyHandle           keyHandle,
                         size_t                         ivLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_cipherInit(self->seosCryptoApi, pCipherHandle, algorithm, keyHandle,
                                 self->serverDataport, ivLen);
}

seos_err_t
SeosCryptoRpc_cipherClose(SeosCryptoRpc*                self,
                          SeosCrypto_CipherHandle       cipherHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_cipherClose(self->seosCryptoApi, cipherHandle);
}

seos_err_t
SeosCryptoRpc_cipherUpdate(SeosCryptoRpc*           self,
                           SeosCrypto_CipherHandle  cipherHandle,
                           size_t                   len)
{
    seos_err_t  retval      = SEOS_ERROR_GENERIC;
    void*       output      = NULL;
    size_t      outputSize  = 0;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (len > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    if ((retval = SeosCrypto_cipherUpdate(self->seosCryptoApi, cipherHandle,
                                          self->serverDataport, len, &output, &outputSize)) == SEOS_SUCCESS)
    {
        if (outputSize + sizeof(outputSize) > PAGE_SIZE)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            memcpy(self->serverDataport, &outputSize,  sizeof(outputSize));
            memcpy(self->serverDataport + sizeof(outputSize), output, outputSize);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_cipherStart(SeosCryptoRpc*            self,
                          SeosCrypto_CipherHandle   cipherHandle,
                          size_t                    len)
{
    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (len > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    return SeosCrypto_cipherStart(self->seosCryptoApi, cipherHandle,
                                  self->serverDataport, len);
}

seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_CipherHandle    cipherHandle,
                             size_t                     len)
{
    seos_err_t  retval   = SEOS_ERROR_GENERIC;
    size_t      bufSize  = 0;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (len > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    bufSize = len;
    memcpy(self->buffer, self->serverDataport, bufSize);

    if ((retval = SeosCrypto_cipherFinalize(self->seosCryptoApi, cipherHandle,
                                            self->buffer, &bufSize)) == SEOS_SUCCESS)
    {

        if (bufSize + sizeof(bufSize) > PAGE_SIZE)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            memcpy(self->serverDataport, &bufSize, sizeof(bufSize));
            memcpy(self->serverDataport + sizeof(bufSize), self->buffer, bufSize);
        }
    }

    return retval;
}