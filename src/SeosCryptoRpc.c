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

seos_err_t
SeosCryptoRpc_free(SeosCryptoRpc* self)
{
    return SEOS_SUCCESS;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpc_rngGetBytes(SeosCryptoRpc*    self,
                          unsigned int      flags,
                          size_t            bufSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_rngGetBytes(self->seosCryptoApi, flags, self->serverDataport,
                                  bufSize);
}

seos_err_t
SeosCryptoRpc_rngReSeed(SeosCryptoRpc* self,
                        size_t seedLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_rngReSeed(self->seosCryptoApi, self->serverDataport, seedLen);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpc_digestInit(SeosCryptoRpc*                 self,
                         SeosCrypto_DigestHandle*       pDigestHandle,
                         SeosCryptoDigest_Algorithm     algorithm)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_digestInit(self->seosCryptoApi, pDigestHandle, algorithm);
}

seos_err_t
SeosCryptoRpc_digestFree(SeosCryptoRpc*            self,
                         SeosCrypto_DigestHandle   digestHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_digestFree(self->seosCryptoApi, digestHandle);
}

seos_err_t
SeosCryptoRpc_digestProcess(SeosCryptoRpc*           self,
                            SeosCrypto_DigestHandle  digestHandle,
                            size_t                   inLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_digestProcess(self->seosCryptoApi, digestHandle,
                                    self->serverDataport, inLen);
}

seos_err_t
SeosCryptoRpc_digestFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_DigestHandle    digestHandle,
                             size_t*                    digestSize)
{
    *digestSize = (*digestSize <= SeosCrypto_BUFFER_SIZE) ? *digestSize :
                  SeosCrypto_BUFFER_SIZE;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_digestFinalize(self->seosCryptoApi, digestHandle,
                                     self->serverDataport, digestSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpc_keyGenerate(SeosCryptoRpc*          self,
                          SeosCrypto_KeyHandle*   pKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyGenerate(self->seosCryptoApi, pKeyHandle,
                                  self->serverDataport);
}

seos_err_t
SeosCryptoRpc_keyMakePublic(SeosCryptoRpc*        self,
                            SeosCrypto_KeyHandle* pPubKeyHandle,
                            SeosCrypto_KeyHandle  prvKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyMakePublic(self->seosCryptoApi, pPubKeyHandle, prvKeyHandle,
                                    self->serverDataport);
}

seos_err_t
SeosCryptoRpc_keyImport(SeosCryptoRpc*        self,
                        SeosCrypto_KeyHandle* pKeyHandle,
                        SeosCrypto_KeyHandle  wrapKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyImport(self->seosCryptoApi, pKeyHandle, wrapKeyHandle,
                                self->serverDataport);
}

seos_err_t
SeosCryptoRpc_keyExport(SeosCryptoRpc*        self,
                        SeosCrypto_KeyHandle  keyHandle,
                        SeosCrypto_KeyHandle  wrapKeyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyExport(self->seosCryptoApi, keyHandle, wrapKeyHandle,
                                self->serverDataport);
}

seos_err_t
SeosCryptoRpc_keyGetParams(SeosCryptoRpc*       self,
                           SeosCrypto_KeyHandle keyHandle,
                           size_t*              paramSize)
{
    *paramSize = (*paramSize <= SeosCrypto_BUFFER_SIZE) ? *paramSize :
                 SeosCrypto_BUFFER_SIZE;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyGetParams(self->seosCryptoApi, keyHandle,
                                   self->serverDataport, paramSize);
}

seos_err_t
SeosCryptoRpc_keyLoadParams(SeosCryptoRpc*       self,
                            SeosCryptoKey_Param  name,
                            size_t*              paramSize)
{
    *paramSize = (*paramSize <= SeosCrypto_BUFFER_SIZE) ? *paramSize :
                 SeosCrypto_BUFFER_SIZE;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyLoadParams(self->seosCryptoApi, name,
                                    self->serverDataport, paramSize);
}

seos_err_t
SeosCryptoRpc_keyFree(SeosCryptoRpc*         self,
                      SeosCrypto_KeyHandle   keyHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyFree(self->seosCryptoApi, keyHandle);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpc_agreementInit(SeosCryptoRpc*                   self,
                            SeosCrypto_AgreementHandle*      pAgrHandle,
                            SeosCryptoAgreement_Algorithm    algorithm,
                            SeosCrypto_KeyHandle             prvHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_agreementInit(self->seosCryptoApi, pAgrHandle, algorithm, prvHandle);
}

seos_err_t
SeosCryptoRpc_agreementAgree(SeosCryptoRpc*                self,
                             SeosCrypto_AgreementHandle    agrHandle,
                             SeosCrypto_KeyHandle          pubHandle,
                             size_t*                       sharedSize)
{
    *sharedSize = (*sharedSize <= SeosCrypto_BUFFER_SIZE) ? *sharedSize :
                  SeosCrypto_BUFFER_SIZE;
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_agreementAgree(self->seosCryptoApi, agrHandle,
                                     pubHandle, self->serverDataport, sharedSize);
}

seos_err_t
SeosCryptoRpc_agreementFree(SeosCryptoRpc*                self,
                            SeosCrypto_AgreementHandle    agrHandle)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
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
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_signatureInit(self->seosCryptoApi, pSigHandle, algorithm, prvHandle,
                                    pubHandle);
}

seos_err_t
SeosCryptoRpc_signatureVerify(SeosCryptoRpc*                self,
                              SeosCrypto_SignatureHandle    sigHandle,
                              size_t                        hashSize,
                              size_t                        signatureSize)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_signatureVerify(self->seosCryptoApi, sigHandle, self->serverDataport,
                                      hashSize, self->serverDataport + hashSize, signatureSize);
}

seos_err_t
SeosCryptoRpc_signatureSign(SeosCryptoRpc*                self,
                            SeosCrypto_SignatureHandle    sigHandle,
                            size_t                        hashSize,
                            size_t*                       signatureSize)
{
    *signatureSize = (*signatureSize <= SeosCrypto_BUFFER_SIZE) ? *signatureSize :
                     SeosCrypto_BUFFER_SIZE ;
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_signatureSign(self->seosCryptoApi, sigHandle,
                                    self->serverDataport, hashSize,
                                    self->serverDataport, signatureSize);
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
                            size_t*                  outputSize)
{
    *outputSize = (*outputSize <= SeosCrypto_BUFFER_SIZE) ? *outputSize :
                  SeosCrypto_BUFFER_SIZE;
    return !isValidHandle(self) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_cipherProcess(self->seosCryptoApi, cipherHandle,
                                    self->serverDataport, inputLen,
                                    self->serverDataport, outputSize);
}

seos_err_t
SeosCryptoRpc_cipherStart(SeosCryptoRpc*            self,
                          SeosCrypto_CipherHandle   cipherHandle,
                          size_t                    len)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_cipherStart(self->seosCryptoApi, cipherHandle, self->serverDataport,
                                  len);
}

seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_CipherHandle    cipherHandle,
                             size_t*                    tagSize)
{
    *tagSize = (*tagSize <= SeosCrypto_BUFFER_SIZE) ? *tagSize :
               SeosCrypto_BUFFER_SIZE;
    return !isValidHandle(self) ?  SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_cipherFinalize(self->seosCryptoApi, cipherHandle,
                                     self->serverDataport, tagSize);
}