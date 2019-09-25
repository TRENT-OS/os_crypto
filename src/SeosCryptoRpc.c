/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCrypto.h"
#include "SeosCryptoRpc.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <stdlib.h>
#include <sys/user.h>

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

static seos_err_t
writeRpcResult(SeosCryptoRpc*    self,
               void*             output,
               size_t            outputSize)
{
    if (outputSize + sizeof(outputSize) > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(self->serverDataport, &outputSize, sizeof(outputSize));
    memcpy(self->serverDataport + sizeof(outputSize), output, outputSize);

    return SEOS_SUCCESS;
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
        SeosCryptoRpc_free(self);
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
    }
exit:
    return retval;
}

void
SeosCryptoRpc_free(SeosCryptoRpc* self)
{
    return;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpc_rngGetBytes(SeosCryptoRpc*    self,
                          unsigned int      flags,
                          size_t            bufSize)
{
    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > PAGE_SIZE)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_rngGetBytes(self->seosCryptoApi, flags, self->serverDataport,
                                  bufSize);
}

seos_err_t
SeosCryptoRpc_rngReSeed(SeosCryptoRpc* self,
                        size_t seedLen)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_rngReSeed(self->seosCryptoApi, self->serverDataport, seedLen);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpc_digestInit(SeosCryptoRpc*                 self,
                         SeosCrypto_DigestHandle*       pDigestHandle,
                         SeosCryptoDigest_Algorithm     algorithm)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_digestInit(self->seosCryptoApi, pDigestHandle, algorithm);
}

seos_err_t
SeosCryptoRpc_digestFree(SeosCryptoRpc*            self,
                         SeosCrypto_DigestHandle   digestHandle)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_digestFree(self->seosCryptoApi, digestHandle);
}

seos_err_t
SeosCryptoRpc_digestProcess(SeosCryptoRpc*           self,
                            SeosCrypto_DigestHandle  digestHandle,
                            size_t                   inLen)
{
    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    return SeosCrypto_digestProcess(self->seosCryptoApi, digestHandle,
                                    self->serverDataport, inLen);
}

seos_err_t
SeosCryptoRpc_digestFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_DigestHandle    digestHandle,
                             size_t                     bufSize)
{
    seos_err_t  retval = SEOS_ERROR_GENERIC;
    size_t      outputSize = 0;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    outputSize = bufSize;

    if ((retval = SeosCrypto_digestFinalize(self->seosCryptoApi, digestHandle,
                                            self->buffer, &outputSize)) == SEOS_SUCCESS)
    {
        retval = writeRpcResult(self, self->buffer, outputSize);
    }

    return retval;
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpc_keyInit(SeosCryptoRpc*                   self,
                      SeosCrypto_KeyHandle*            keyHandle,
                      unsigned int                     type,
                      SeosCryptoKey_Flags               flags,
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
                        SeosCrypto_KeyHandle           wrapKeyHandle,
                        size_t                         bufSize)
{
    seos_err_t  retval      = SEOS_ERROR_GENERIC;
    size_t      outputSize  = 0;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    outputSize = bufSize;

    if ((retval = SeosCrypto_keyExport(self->seosCryptoApi, keyHandle,
                                       wrapKeyHandle, self->buffer, &outputSize)) == SEOS_SUCCESS)
    {
        retval = writeRpcResult(self, self->buffer, outputSize);
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_keyFree(SeosCryptoRpc*                  self,
                      SeosCrypto_KeyHandle            keyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyFree(self->seosCryptoApi, keyHandle);
}

// ----------------------------- Agreement API ---------------------------------

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
SeosCryptoRpc_agreementAgree(SeosCryptoRpc*                self,
                             SeosCrypto_AgreementHandle    agrHandle,
                             SeosCrypto_KeyHandle          pubHandle,
                             size_t                        bufSize)
{
    seos_err_t  retval      = SEOS_ERROR_GENERIC;
    size_t      outputSize  = 0;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    outputSize = bufSize;

    if ((retval = SeosCrypto_agreementAgree(self->seosCryptoApi, agrHandle,
                                            pubHandle, self->buffer, &outputSize)) == SEOS_SUCCESS)
    {
        retval = writeRpcResult(self, self->buffer, outputSize);
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_agreementFree(SeosCryptoRpc*                self,
                            SeosCrypto_AgreementHandle    agrHandle)
{
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_agreementFree(self->seosCryptoApi, agrHandle);
}

// ----------------------------- Signature API ---------------------------------

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
                            size_t                        hashSize,
                            size_t                        bufSize)
{
    seos_err_t      retval = SEOS_ERROR_GENERIC;
    size_t          outputSize = 0;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    outputSize = bufSize;

    if ((retval = SeosCrypto_signatureSign(self->seosCryptoApi, sigHandle,
                                           self->serverDataport, hashSize, self->buffer, &outputSize)) == SEOS_SUCCESS)
    {
        retval = writeRpcResult(self, self->buffer, outputSize);
    }

    return retval;
}

seos_err_t
SeosCryptoRpc_signatureFree(SeosCryptoRpc*                  self,
                            SeosCrypto_SignatureHandle      sigHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_signatureFree(self->seosCryptoApi, sigHandle);
}

// ------------------------------- Cipher API ----------------------------------

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
SeosCryptoRpc_cipherFree(SeosCryptoRpc*                self,
                         SeosCrypto_CipherHandle       cipherHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_cipherFree(self->seosCryptoApi, cipherHandle);
}

seos_err_t
SeosCryptoRpc_cipherProcess(SeosCryptoRpc*           self,
                            SeosCrypto_CipherHandle  cipherHandle,
                            size_t                   inputLen,
                            size_t                   bufSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    size_t outputSize;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    outputSize = bufSize;
    memcpy(self->buffer, self->serverDataport, inputLen);

    if ((retval = SeosCrypto_cipherProcess(self->seosCryptoApi, cipherHandle,
                                           self->serverDataport, inputLen, self->buffer, &outputSize)) == SEOS_SUCCESS)
    {
        retval = writeRpcResult(self, self->buffer, outputSize);
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

    return SeosCrypto_cipherStart(self->seosCryptoApi, cipherHandle,
                                  self->serverDataport, len);
}

seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_CipherHandle    cipherHandle,
                             size_t                     bufSize)
{
    seos_err_t  retval = SEOS_ERROR_GENERIC;
    size_t      outputSize;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    outputSize = bufSize;
    // For finalize, the buffer can be used as OUTPUT (when computing a tag) or
    // as INPUT (when verifying a tag)
    memcpy(self->buffer, self->serverDataport, bufSize);

    if ((retval = SeosCrypto_cipherFinalize(self->seosCryptoApi, cipherHandle,
                                            self->buffer, &outputSize)) == SEOS_SUCCESS)
    {
        retval = writeRpcResult(self, self->buffer, outputSize);
    }

    return retval;
}