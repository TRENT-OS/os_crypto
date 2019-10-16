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
                             size_t                     bufSize)
{
    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > DATAPORT_BUFFER_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(get_dataport_len_ptr(self), &bufSize, sizeof(size_t));
    return SeosCrypto_digestFinalize(self->seosCryptoApi, digestHandle,
                                     get_dataport_buf_ptr(self), get_dataport_len_ptr(self));
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpc_keyGenerate(SeosCryptoRpc*        self,
                          SeosCrypto_KeyHandle* pKeyHandle,
                          SeosCryptoKey_Type    type,
                          SeosCryptoKey_Flags   flags,
                          size_t                bits)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyGenerate(self->seosCryptoApi, pKeyHandle, type, flags, bits);
}

seos_err_t
SeosCryptoRpc_keyGeneratePair(SeosCryptoRpc*            self,
                              SeosCrypto_KeyHandle*     pPrvKeyHandle,
                              SeosCrypto_KeyHandle*     pPubKeyHandle,
                              SeosCryptoKey_PairType    type,
                              SeosCryptoKey_Flags       prvFlags,
                              SeosCryptoKey_Flags       pubFlags,
                              size_t                    bits)

{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyGeneratePair(self->seosCryptoApi, pPrvKeyHandle, pPubKeyHandle,
                                      type, prvFlags, pubFlags, bits);
}

seos_err_t
SeosCryptoRpc_keyImport(SeosCryptoRpc*          self,
                        SeosCrypto_KeyHandle*   pKeyHandle,
                        SeosCrypto_KeyHandle    wrapKeyHandle,
                        SeosCryptoKey_Type      type,
                        SeosCryptoKey_Flags     flags,
                        size_t                  keyLen)
{
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_keyImport(self->seosCryptoApi, pKeyHandle, wrapKeyHandle, type,
                                flags, self->serverDataport, keyLen);
}

seos_err_t
SeosCryptoRpc_keyExport(SeosCryptoRpc*          self,
                        SeosCrypto_KeyHandle    keyHandle,
                        SeosCrypto_KeyHandle    wrapKeyHandle,
                        SeosCryptoKey_Type*     type,
                        SeosCryptoKey_Flags*    flags,
                        size_t                  bufSize)
{
    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > DATAPORT_BUFFER_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(get_dataport_len_ptr(self), &bufSize, sizeof(size_t));
    return SeosCrypto_keyExport(self->seosCryptoApi, keyHandle, wrapKeyHandle, type,
                                flags, get_dataport_buf_ptr(self), get_dataport_len_ptr(self));
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
    return !isValidHandle(self) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCrypto_agreementInit(self->seosCryptoApi, pAgrHandle, algorithm, prvHandle);
}

seos_err_t
SeosCryptoRpc_agreementAgree(SeosCryptoRpc*                self,
                             SeosCrypto_AgreementHandle    agrHandle,
                             SeosCrypto_KeyHandle          pubHandle,
                             size_t                        bufSize)
{
    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > DATAPORT_BUFFER_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(get_dataport_len_ptr(self), &bufSize, sizeof(size_t));
    return SeosCrypto_agreementAgree(self->seosCryptoApi, agrHandle,
                                     pubHandle, get_dataport_buf_ptr(self), get_dataport_len_ptr(self));
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
                            size_t                        bufSize)
{
    size_t outSize;
    seos_err_t retval;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > DATAPORT_BUFFER_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    outSize = bufSize;
    if ((retval = SeosCrypto_signatureSign(self->seosCryptoApi, sigHandle,
                                           self->serverDataport, hashSize,
                                           get_dataport_buf_ptr(self), &outSize)) == SEOS_SUCCESS)
    {
        memcpy(get_dataport_len_ptr(self), &outSize, sizeof(size_t));
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
    size_t outSize;
    seos_err_t retval;

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > DATAPORT_BUFFER_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    outSize = bufSize;
    if ((retval = SeosCrypto_cipherProcess(self->seosCryptoApi, cipherHandle,
                                           self->serverDataport, inputLen,
                                           get_dataport_buf_ptr(self), &outSize)) == SEOS_SUCCESS)
    {
        memcpy(get_dataport_len_ptr(self), &outSize, sizeof(size_t));
    }

    return retval;
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
                             size_t                     bufSize)
{
    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (bufSize > DATAPORT_BUFFER_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    // Dataport may already hold a value (e.g. in case we want to validate a
    // tag), so we must move that to the appropriate place
    memmove(get_dataport_buf_ptr(self), self->serverDataport, bufSize);
    memcpy(get_dataport_len_ptr(self), &bufSize, sizeof(size_t));
    return SeosCrypto_cipherFinalize(self->seosCryptoApi, cipherHandle,
                                     get_dataport_buf_ptr(self), get_dataport_len_ptr(self));
}