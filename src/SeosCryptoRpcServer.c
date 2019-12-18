/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoLib.h"
#include "SeosCryptoRpcServer.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <stdlib.h>
#include <sys/user.h>

// At the moment we manage one handle only.
SeosCryptoRpcServer* handle = NULL;

static inline bool
isValidHandle(SeosCryptoRpcServer* self)
{
    return handle != NULL && self == handle;
}

static inline bool
registerHandle(SeosCryptoRpcServer* self)
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
deregisterHandle(SeosCryptoRpcServer* self)
{
    handle = NULL;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoRpcServer_init(SeosCryptoRpcServer* self,
                         SeosCryptoLib*       seosCryptoApiCtx,
                         void*                serverDataport)
{
    if (NULL == self || NULL == seosCryptoApiCtx || NULL == serverDataport)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->seosCryptoApi     = SeosCryptoLib_TO_SEOS_CRYPTO_CTX(seosCryptoApiCtx);
    self->serverDataport    = serverDataport;

    if (!registerHandle(self))
    {
        SeosCryptoRpcServer_free(self);
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoRpcServer_free(SeosCryptoRpcServer* self)
{
    return SEOS_SUCCESS;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpcServer_rngGetBytes(SeosCryptoRpcServer* self,
                                unsigned int         flags,
                                size_t               bufSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_rngGetBytes(self->seosCryptoApi, flags, self->serverDataport,
                                     bufSize);
}

seos_err_t
SeosCryptoRpcServer_rngReSeed(SeosCryptoRpcServer* self,
                              size_t               seedLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_rngReSeed(self->seosCryptoApi, self->serverDataport, seedLen);
}


// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcServer_macInit(SeosCryptoRpcServer*  self,
                            SeosCryptoApi_Mac*    pMacHandle,
                            SeosCryptoApi_Mac_Alg algorithm)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_macInit(self->seosCryptoApi, pMacHandle, algorithm);
}

seos_err_t
SeosCryptoRpcServer_macFree(SeosCryptoRpcServer* self,
                            SeosCryptoApi_Mac    macHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_macFree(self->seosCryptoApi, macHandle);
}

seos_err_t
SeosCryptoRpcServer_macStart(SeosCryptoRpcServer* self,
                             SeosCryptoApi_Mac    macHandle,
                             size_t               secretSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_macStart(self->seosCryptoApi, macHandle,
                                  self->serverDataport, secretSize);
}

seos_err_t
SeosCryptoRpcServer_macProcess(SeosCryptoRpcServer* self,
                               SeosCryptoApi_Mac    macHandle,
                               size_t               dataSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_macProcess(self->seosCryptoApi, macHandle,
                                    self->serverDataport, dataSize);
}

seos_err_t
SeosCryptoRpcServer_macFinalize(SeosCryptoRpcServer* self,
                                SeosCryptoApi_Mac    macHandle,
                                size_t*              macSize)
{
    *macSize = (*macSize <= SeosCryptoApi_SIZE_DATAPORT) ? *macSize :
               SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_macFinalize(self->seosCryptoApi, macHandle,
                                     self->serverDataport, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcServer_digestInit(SeosCryptoRpcServer*     self,
                               SeosCryptoApi_Digest*    pDigestHandle,
                               SeosCryptoApi_Digest_Alg algorithm)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_digestInit(self->seosCryptoApi, pDigestHandle, algorithm);
}

seos_err_t
SeosCryptoRpcServer_digestFree(SeosCryptoRpcServer* self,
                               SeosCryptoApi_Digest digestHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_digestFree(self->seosCryptoApi, digestHandle);
}

seos_err_t
SeosCryptoRpcServer_digestClone(SeosCryptoRpcServer* self,
                                SeosCryptoApi_Digest dstDigHandle,
                                SeosCryptoApi_Digest srcDigHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_digestClone(self->seosCryptoApi, dstDigHandle, srcDigHandle);
}

seos_err_t
SeosCryptoRpcServer_digestProcess(SeosCryptoRpcServer* self,
                                  SeosCryptoApi_Digest digestHandle,
                                  size_t               inLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_digestProcess(self->seosCryptoApi, digestHandle,
                                       self->serverDataport, inLen);
}

seos_err_t
SeosCryptoRpcServer_digestFinalize(SeosCryptoRpcServer* self,
                                   SeosCryptoApi_Digest digestHandle,
                                   size_t*              digestSize)
{
    *digestSize = (*digestSize <= SeosCryptoApi_SIZE_DATAPORT) ? *digestSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_digestFinalize(self->seosCryptoApi, digestHandle,
                                        self->serverDataport, digestSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpcServer_keyGenerate(SeosCryptoRpcServer* self,
                                SeosCryptoApi_Key*   pKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_keyGenerate(self->seosCryptoApi, pKeyHandle,
                                     self->serverDataport);
}

seos_err_t
SeosCryptoRpcServer_keyMakePublic(SeosCryptoRpcServer* self,
                                  SeosCryptoApi_Key*   pPubKeyHandle,
                                  SeosCryptoApi_Key    prvKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_keyMakePublic(self->seosCryptoApi, pPubKeyHandle, prvKeyHandle,
                                       self->serverDataport);
}

seos_err_t
SeosCryptoRpcServer_keyImport(SeosCryptoRpcServer* self,
                              SeosCryptoApi_Key*   pKeyHandle,
                              SeosCryptoApi_Key    wrapKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_keyImport(self->seosCryptoApi, pKeyHandle, wrapKeyHandle,
                                   self->serverDataport);
}

seos_err_t
SeosCryptoRpcServer_keyExport(SeosCryptoRpcServer* self,
                              SeosCryptoApi_Key    keyHandle,
                              SeosCryptoApi_Key    wrapKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_keyExport(self->seosCryptoApi, keyHandle, wrapKeyHandle,
                                   self->serverDataport);
}

seos_err_t
SeosCryptoRpcServer_keyGetParams(SeosCryptoRpcServer* self,
                                 SeosCryptoApi_Key    keyHandle,
                                 size_t*              paramSize)
{
    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_keyGetParams(self->seosCryptoApi, keyHandle,
                                      self->serverDataport, paramSize);
}

seos_err_t
SeosCryptoRpcServer_keyLoadParams(SeosCryptoRpcServer*    self,
                                  SeosCryptoApi_Key_Param name,
                                  size_t*                 paramSize)
{
    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_keyLoadParams(self->seosCryptoApi, name,
                                       self->serverDataport, paramSize);
}

seos_err_t
SeosCryptoRpcServer_keyFree(SeosCryptoRpcServer* self,
                            SeosCryptoApi_Key    keyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_keyFree(self->seosCryptoApi, keyHandle);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpcServer_agreementInit(SeosCryptoRpcServer*        self,
                                  SeosCryptoApi_Agreement*    pAgrHandle,
                                  SeosCryptoApi_Agreement_Alg algorithm,
                                  SeosCryptoApi_Key           prvHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_agreementInit(self->seosCryptoApi, pAgrHandle, algorithm,
                                       prvHandle);
}

seos_err_t
SeosCryptoRpcServer_agreementAgree(SeosCryptoRpcServer*    self,
                                   SeosCryptoApi_Agreement agrHandle,
                                   SeosCryptoApi_Key       pubHandle,
                                   size_t*                 sharedSize)
{
    *sharedSize = (*sharedSize <= SeosCryptoApi_SIZE_DATAPORT) ? *sharedSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_agreementAgree(self->seosCryptoApi, agrHandle,
                                        pubHandle, self->serverDataport, sharedSize);
}

seos_err_t
SeosCryptoRpcServer_agreementFree(SeosCryptoRpcServer*    self,
                                  SeosCryptoApi_Agreement agrHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_agreementFree(self->seosCryptoApi, agrHandle);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpcServer_signatureInit(SeosCryptoRpcServer*              self,
                                  SeosCryptoApi_Signature*          pSigHandle,
                                  const SeosCryptoApi_Signature_Alg algorithm,
                                  const SeosCryptoApi_Digest_Alg    digest,
                                  SeosCryptoApi_Key                 prvHandle,
                                  SeosCryptoApi_Key                 pubHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_signatureInit(self->seosCryptoApi, pSigHandle, algorithm, digest,
                                       prvHandle, pubHandle);
}

seos_err_t
SeosCryptoRpcServer_signatureVerify(SeosCryptoRpcServer*    self,
                                    SeosCryptoApi_Signature sigHandle,
                                    size_t                  hashSize,
                                    size_t                  signatureSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_signatureVerify(self->seosCryptoApi, sigHandle,
                                         self->serverDataport,
                                         hashSize, self->serverDataport + hashSize, signatureSize);
}

seos_err_t
SeosCryptoRpcServer_signatureSign(SeosCryptoRpcServer*    self,
                                  SeosCryptoApi_Signature sigHandle,
                                  size_t                  hashSize,
                                  size_t*                 signatureSize)
{
    *signatureSize = (*signatureSize <= SeosCryptoApi_SIZE_DATAPORT) ?
                     *signatureSize :
                     SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_signatureSign(self->seosCryptoApi, sigHandle,
                                       self->serverDataport, hashSize,
                                       self->serverDataport, signatureSize);
}

seos_err_t
SeosCryptoRpcServer_signatureFree(SeosCryptoRpcServer*    self,
                                  SeosCryptoApi_Signature sigHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_signatureFree(self->seosCryptoApi, sigHandle);
}

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoRpcServer_cipherInit(SeosCryptoRpcServer*     self,
                               SeosCryptoApi_Cipher*    pCipherHandle,
                               SeosCryptoApi_Cipher_Alg algorithm,
                               SeosCryptoApi_Key        keyHandle,
                               size_t                   ivLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_cipherInit(self->seosCryptoApi, pCipherHandle, algorithm,
                                    keyHandle,
                                    self->serverDataport, ivLen);
}

seos_err_t
SeosCryptoRpcServer_cipherFree(SeosCryptoRpcServer* self,
                               SeosCryptoApi_Cipher cipherHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_cipherFree(self->seosCryptoApi, cipherHandle);
}

seos_err_t
SeosCryptoRpcServer_cipherProcess(SeosCryptoRpcServer* self,
                                  SeosCryptoApi_Cipher cipherHandle,
                                  size_t               inputLen,
                                  size_t*              outputSize)
{
    *outputSize = (*outputSize <= SeosCryptoApi_SIZE_DATAPORT) ? *outputSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_cipherProcess(self->seosCryptoApi, cipherHandle,
                                       self->serverDataport, inputLen,
                                       self->serverDataport, outputSize);
}

seos_err_t
SeosCryptoRpcServer_cipherStart(SeosCryptoRpcServer* self,
                                SeosCryptoApi_Cipher cipherHandle,
                                size_t               len)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_cipherStart(self->seosCryptoApi, cipherHandle,
                                     self->serverDataport,
                                     len);
}

seos_err_t
SeosCryptoRpcServer_cipherFinalize(SeosCryptoRpcServer* self,
                                   SeosCryptoApi_Cipher cipherHandle,
                                   size_t*              tagSize)
{
    *tagSize = (*tagSize <= SeosCryptoApi_SIZE_DATAPORT) ? *tagSize :
               SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ?  SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_cipherFinalize(self->seosCryptoApi, cipherHandle,
                                        self->serverDataport, tagSize);
}