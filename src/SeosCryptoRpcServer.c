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
isValidHandle(
    SeosCryptoRpcServer* self)
{
    return handle != NULL && self == handle;
}

static inline bool
registerHandle(
    SeosCryptoRpcServer* self)
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
deregisterHandle(
    SeosCryptoRpcServer* self)
{
    handle = NULL;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoRpcServer_init(
    SeosCryptoRpcServer* self,
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
SeosCryptoRpcServer_free(
    SeosCryptoRpcServer* self)
{
    return SEOS_SUCCESS;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpcServer_Rng_getBytes(
    SeosCryptoRpcServer* self,
    unsigned int         flags,
    size_t               bufSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Rng_getBytes(self->seosCryptoApi, flags, self->serverDataport,
                                      bufSize);
}

seos_err_t
SeosCryptoRpcServer_Rng_reseed(
    SeosCryptoRpcServer* self,
    size_t               seedLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Rng_reseed(self->seosCryptoApi, self->serverDataport, seedLen);
}


// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcServer_Mac_init(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Mac_Ptr* pMacObj,
    SeosCryptoApi_Mac_Alg  algorithm)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_init(self->seosCryptoApi, pMacObj, algorithm);
}

seos_err_t
SeosCryptoRpcServer_Mac_free(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Mac_Ptr macObj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_free(self->seosCryptoApi, macObj);
}

seos_err_t
SeosCryptoRpcServer_Mac_start(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t                secretSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_start(self->seosCryptoApi, macObj,
                                   self->serverDataport, secretSize);
}

seos_err_t
SeosCryptoRpcServer_Mac_process(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t                dataSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_process(self->seosCryptoApi, macObj,
                                     self->serverDataport, dataSize);
}

seos_err_t
SeosCryptoRpcServer_Mac_finalize(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t*               macSize)
{
    *macSize = (*macSize <= SeosCryptoApi_SIZE_DATAPORT) ? *macSize :
               SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_finalize(self->seosCryptoApi, macObj,
                                      self->serverDataport, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcServer_Digest_init(
    SeosCryptoRpcServer*      self,
    SeosCryptoLib_Digest_Ptr* pDigestObj,
    SeosCryptoApi_Digest_Alg  algorithm)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_init(self->seosCryptoApi, pDigestObj, algorithm);
}

seos_err_t
SeosCryptoRpcServer_Digest_free(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Digest_Ptr digestObj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_free(self->seosCryptoApi, digestObj);
}

seos_err_t
SeosCryptoRpcServer_Digest_clone(
    SeosCryptoRpcServer*      self,
    SeosCryptoLib_Digest_Ptr  dstDigHandle,
    SeosCryptoLib_Digest_CPtr srcDigHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_clone(self->seosCryptoApi, dstDigHandle, srcDigHandle);
}

seos_err_t
SeosCryptoRpcServer_Digest_process(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Digest_Ptr digestObj,
    size_t                   inLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_process(self->seosCryptoApi, digestObj,
                                        self->serverDataport, inLen);
}

seos_err_t
SeosCryptoRpcServer_Digest_finalize(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Digest_Ptr digestObj,
    size_t*                  digestSize)
{
    *digestSize = (*digestSize <= SeosCryptoApi_SIZE_DATAPORT) ? *digestSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_finalize(self->seosCryptoApi, digestObj,
                                         self->serverDataport, digestSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpcServer_Key_generate(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_Ptr* pKeyObj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_generate(self->seosCryptoApi, pKeyObj,
                                      self->serverDataport);
}

seos_err_t
SeosCryptoRpcServer_Key_makePublic(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_Ptr* pPubKeyHandle,
    SeosCryptoLib_Key_CPtr prvKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_makePublic(self->seosCryptoApi, pPubKeyHandle, prvKeyHandle,
                                        self->serverDataport);
}

seos_err_t
SeosCryptoRpcServer_Key_import(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_Ptr* pKeyObj,
    SeosCryptoLib_Key_CPtr wrapKeyObj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_import(self->seosCryptoApi, pKeyObj, wrapKeyObj,
                                    self->serverDataport);
}

seos_err_t
SeosCryptoRpcServer_Key_export(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_CPtr keyObj,
    SeosCryptoLib_Key_CPtr wrapKeyObj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_export(self->seosCryptoApi, keyObj, wrapKeyObj,
                                    self->serverDataport);
}

seos_err_t
SeosCryptoRpcServer_Key_getParams(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_CPtr keyObj,
    size_t*                paramSize)
{
    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_getParams(self->seosCryptoApi, keyObj,
                                       self->serverDataport, paramSize);
}

seos_err_t
SeosCryptoRpcServer_Key_loadParams(
    SeosCryptoRpcServer*    self,
    SeosCryptoApi_Key_Param name,
    size_t*                 paramSize)
{
    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_loadParams(self->seosCryptoApi, name,
                                        self->serverDataport, paramSize);
}

seos_err_t
SeosCryptoRpcServer_Key_free(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Key_Ptr keyObj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_free(self->seosCryptoApi, keyObj);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpcServer_Agreement_init(
    SeosCryptoRpcServer*         self,
    SeosCryptoLib_Agreement_Ptr* pAgrObj,
    SeosCryptoApi_Agreement_Alg  algorithm,
    SeosCryptoLib_Key_CPtr       prvKey)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Agreement_init(self->seosCryptoApi, pAgrObj, algorithm,
                                        prvKey);
}

seos_err_t
SeosCryptoRpcServer_Agreement_agree(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Agreement_Ptr agrObj,
    SeosCryptoLib_Key_CPtr      pubKey,
    size_t*                     sharedSize)
{
    *sharedSize = (*sharedSize <= SeosCryptoApi_SIZE_DATAPORT) ? *sharedSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Agreement_agree(self->seosCryptoApi, agrObj,
                                         pubKey, self->serverDataport, sharedSize);
}

seos_err_t
SeosCryptoRpcServer_Agreement_free(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Agreement_Ptr agrObj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Agreement_free(self->seosCryptoApi, agrObj);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpcServer_Signature_init(
    SeosCryptoRpcServer*         self,
    SeosCryptoLib_Signature_Ptr* pObj,
    SeosCryptoApi_Signature_Alg  algorithm,
    SeosCryptoApi_Digest_Alg     digest,
    SeosCryptoLib_Key_CPtr       prvKey,
    SeosCryptoLib_Key_CPtr       pubKey)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Signature_init(self->seosCryptoApi, pObj, algorithm, digest,
                                        prvKey, pubKey);
}

seos_err_t
SeosCryptoRpcServer_Signature_verify(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Signature_Ptr obj,
    size_t                      hashSize,
    size_t                      signatureSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Signature_verify(self->seosCryptoApi, obj, self->serverDataport,
                                          hashSize, self->serverDataport + hashSize, signatureSize);
}

seos_err_t
SeosCryptoRpcServer_Signature_sign(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Signature_Ptr obj,
    size_t                      hashSize,
    size_t*                     signatureSize)
{
    *signatureSize = (*signatureSize <= SeosCryptoApi_SIZE_DATAPORT) ?
                     *signatureSize :
                     SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Signature_sign(self->seosCryptoApi, obj, self->serverDataport,
                                        hashSize, self->serverDataport, signatureSize);
}

seos_err_t
SeosCryptoRpcServer_Signature_free(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Signature_Ptr obj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Signature_free(self->seosCryptoApi, obj);
}

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoRpcServer_Cipher_init(
    SeosCryptoRpcServer*      self,
    SeosCryptoLib_Cipher_Ptr* pCipherObj,
    SeosCryptoApi_Cipher_Alg  algorithm,
    SeosCryptoLib_Key_CPtr    key,
    size_t                    ivLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_init(self->seosCryptoApi, pCipherObj, algorithm,
                                     key, self->serverDataport, ivLen);
}

seos_err_t
SeosCryptoRpcServer_Cipher_free(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Cipher_Ptr cipherObj)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_free(self->seosCryptoApi, cipherObj);
}

seos_err_t
SeosCryptoRpcServer_Cipher_process(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t                   inputLen,
    size_t*                  outputSize)
{
    *outputSize = (*outputSize <= SeosCryptoApi_SIZE_DATAPORT) ? *outputSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_process(self->seosCryptoApi, cipherObj,
                                        self->serverDataport, inputLen,
                                        self->serverDataport, outputSize);
}

seos_err_t
SeosCryptoRpcServer_Cipher_start(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t                   len)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_start(self->seosCryptoApi, cipherObj,
                                      self->serverDataport, len);
}

seos_err_t
SeosCryptoRpcServer_Cipher_finalize(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t*                  tagSize)
{
    *tagSize = (*tagSize <= SeosCryptoApi_SIZE_DATAPORT) ? *tagSize :
               SeosCryptoApi_SIZE_DATAPORT;
    return !isValidHandle(self) ?  SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_finalize(self->seosCryptoApi, cipherObj,
                                         self->serverDataport, tagSize);
}