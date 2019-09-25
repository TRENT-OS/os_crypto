/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoClient.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <sys/user.h>

static const SeosCryptoCtx_Vtable SeosCryptoClient_vtable =
{
    .rngGetBytes             = SeosCryptoClient_rngGetBytes,
    .rngReSeed               = SeosCryptoClient_rngReSeed,
    .digestInit              = SeosCryptoClient_digestInit,
    .digestFree              = SeosCryptoClient_digestFree,
    .digestProcess           = SeosCryptoClient_digestProcess,
    .digestFinalize          = SeosCryptoClient_digestFinalize,
    .keyInit                 = SeosCryptoClient_keyInit,
    .keyGenerate             = SeosCryptoClient_keyGenerate,
    .keyGeneratePair         = SeosCryptoClient_keyGeneratePair,
    .keyImport               = SeosCryptoClient_keyImport,
    .keyExport               = SeosCryptoClient_keyExport,
    .keyFree                 = SeosCryptoClient_keyFree,
    .signatureInit           = SeosCryptoClient_signatureInit,
    .signatureFree           = SeosCryptoClient_signatureFree,
    .signatureSign           = SeosCryptoClient_signatureSign,
    .signatureVerify         = SeosCryptoClient_signatureVerify,
    .agreementInit           = SeosCryptoClient_agreementInit,
    .agreementFree           = SeosCryptoClient_agreementFree,
    .agreementAgree          = SeosCryptoClient_agreementAgree,
    .cipherInit              = SeosCryptoClient_cipherInit,
    .cipherFree              = SeosCryptoClient_cipherFree,
    .cipherProcess           = SeosCryptoClient_cipherProcess,
    .cipherStart             = SeosCryptoClient_cipherStart,
    .cipherFinalize          = SeosCryptoClient_cipherFinalize,
    .free                    = SeosCryptoClient_free
};

// Private functions -----------------------------------------------------------

static seos_err_t
readRpcResult(SeosCryptoClient*    self,
              void*                output,
              size_t*              outputSize)
{
    size_t* rpcOutputLen = (size_t*) self->clientDataport;
    void*   rpcOutput = self->clientDataport + sizeof(rpcOutputLen);

    if (*outputSize < *rpcOutputLen)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    *outputSize = *rpcOutputLen;
    memcpy(output, rpcOutput, *outputSize);

    return SEOS_SUCCESS;
}

static seos_err_t
writeRpcArguments(SeosCryptoClient*      self,
                  const void*            arg0,
                  const size_t           arg0Size,
                  const void*            arg1,
                  const size_t           arg1Size)
{
    void* p = self->clientDataport;

    if (arg0Size + arg1Size > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    if (NULL != arg0 && arg0Size > 0)
    {
        memcpy(p, arg0, arg0Size);
        p += arg0Size;
    }
    if (NULL != arg1 && arg1Size > 0)
    {
        memcpy(p, arg1, arg1Size);
        p += arg1Size;
    }

    return SEOS_SUCCESS;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoClient_init(SeosCryptoClient* self,
                      SeosCryptoRpc_Handle rpcHandle,
                      void* dataport)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    memset(self, 0, sizeof(*self));

    if (NULL == rpcHandle || NULL == dataport)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    self->clientDataport = dataport;
    self->rpcHandle      = rpcHandle;
    self->parent.vtable  = &SeosCryptoClient_vtable;

    retval = SEOS_SUCCESS;
exit:
    return retval;
}

void
SeosCryptoClient_free(SeosCryptoCtx* api)
{
    return;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoClient_rngGetBytes(SeosCryptoCtx*       api,
                             unsigned int         flags,
                             void*                buf,
                             size_t               bufLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || NULL == buf
        || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (bufLen > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    if ((retval = SeosCryptoRpc_rngGetBytes(self->rpcHandle, flags,
                                            bufLen)) == SEOS_SUCCESS)
    {
        memcpy(buf, self->clientDataport, bufLen);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_rngReSeed(SeosCryptoCtx*       api,
                           const void*          seed,
                           size_t               seedLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || NULL == seed
        || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, seed, seedLen, NULL, 0)) == SEOS_SUCCESS)
    {
        retval = SeosCryptoRpc_rngReSeed(self->rpcHandle, seedLen);
    }

    return retval;
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoClient_digestInit(SeosCryptoCtx*                  api,
                            SeosCrypto_DigestHandle*        pDigestHandle,
                            SeosCryptoDigest_Algorithm      algorithm)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == pDigestHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_digestInit(self->rpcHandle, pDigestHandle, algorithm);
}

seos_err_t
SeosCryptoClient_digestFree(SeosCryptoCtx*             api,
                            SeosCrypto_DigestHandle digestHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_digestFree(self->rpcHandle, digestHandle);
}

seos_err_t
SeosCryptoClient_digestProcess(SeosCryptoCtx*                api,
                               SeosCrypto_DigestHandle       digestHandle,
                               const void*                   data,
                               size_t                        dataLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == data || 0 == dataLen)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, data, dataLen, NULL, 0)) == SEOS_SUCCESS)
    {
        retval = SeosCryptoRpc_digestProcess(self->rpcHandle, digestHandle, dataLen);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoCtx*              api,
                                SeosCrypto_DigestHandle     digestHandle,
                                void*                       digest,
                                size_t*                     digestSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == digest || NULL == digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_digestFinalize(self->rpcHandle, digestHandle,
                                               *digestSize)) == SEOS_SUCCESS)
    {
        retval = readRpcResult(self, digest, digestSize);
    }

    return retval;
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoClient_signatureInit(SeosCryptoCtx*                api,
                               SeosCrypto_SignatureHandle*   pSigHandle,
                               unsigned int                  algorithm,
                               SeosCrypto_KeyHandle          prvHandle,
                               SeosCrypto_KeyHandle          pubHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || NULL == pSigHandle
        || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_signatureInit(self->rpcHandle, pSigHandle, algorithm,
                                       prvHandle, pubHandle);
}

seos_err_t
SeosCryptoClient_signatureFree(SeosCryptoCtx*               api,
                               SeosCrypto_SignatureHandle   sigHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_signatureFree(self->rpcHandle, sigHandle);
}

seos_err_t
SeosCryptoClient_signatureSign(SeosCryptoCtx*                 api,
                               SeosCrypto_SignatureHandle     sigHandle,
                               const void*                    hash,
                               size_t                         hashSize,
                               void*                          signature,
                               size_t*                        signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == hash || NULL == signature || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, hash, hashSize, NULL, 0)) == SEOS_SUCCESS)
    {
        if ((retval = SeosCryptoRpc_signatureSign(self->rpcHandle, sigHandle,
                                                  hashSize, *signatureSize)) == SEOS_SUCCESS)
        {
            retval = readRpcResult(self, signature, signatureSize);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoClient_signatureVerify(SeosCryptoCtx*                 api,
                                 SeosCrypto_SignatureHandle     sigHandle,
                                 const void*                    hash,
                                 size_t                         hashSize,
                                 const void*                    signature,
                                 size_t                         signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == hash || NULL == signature)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, hash, hashSize, signature,
                                    signatureSize)) == SEOS_SUCCESS)
    {
        retval = SeosCryptoRpc_signatureVerify(self->rpcHandle, sigHandle, hashSize,
                                               signatureSize);
    }

    return retval;
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoClient_agreementInit(SeosCryptoCtx*                api,
                               SeosCrypto_AgreementHandle*   pAgrHandle,
                               unsigned int                  algorithm,
                               SeosCrypto_KeyHandle          prvHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || NULL == pAgrHandle
        || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_agreementInit(self->rpcHandle, pAgrHandle, algorithm,
                                       prvHandle);
}

seos_err_t
SeosCryptoClient_agreementFree(SeosCryptoCtx*               api,
                               SeosCrypto_AgreementHandle   agrHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_agreementFree(self->rpcHandle, agrHandle);
}

seos_err_t
SeosCryptoClient_agreementAgree(SeosCryptoCtx*                 api,
                                SeosCrypto_AgreementHandle     agrHandle,
                                SeosCrypto_KeyHandle           pubHandle,
                                void*                          shared,
                                size_t*                        sharedSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_agreementAgree(self->rpcHandle, agrHandle,
                                               pubHandle, *sharedSize)) == SEOS_SUCCESS)
    {
        retval = readRpcResult(self, shared, sharedSize);
    }

    return retval;
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoClient_keyInit(SeosCryptoCtx*                   api,
                         SeosCrypto_KeyHandle*            pKeyHandle,
                         unsigned int                     type,
                         SeosCryptoKey_Flags               flags,
                         size_t                           bits)
{

    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || NULL == pKeyHandle
        || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_keyInit(self->rpcHandle, pKeyHandle, type, flags, bits);
}

seos_err_t
SeosCryptoClient_keyGenerate(SeosCryptoCtx*               api,
                             SeosCrypto_KeyHandle         keyHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_keyGenerate(self->rpcHandle, keyHandle);
}

seos_err_t
SeosCryptoClient_keyGeneratePair(SeosCryptoCtx*           api,
                                 SeosCrypto_KeyHandle     prvKeyHandle,
                                 SeosCrypto_KeyHandle     pubKeyHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_keyGeneratePair(self->rpcHandle, prvKeyHandle,
                                         pubKeyHandle);
}

seos_err_t
SeosCryptoClient_keyImport(SeosCryptoCtx*                 api,
                           SeosCrypto_KeyHandle           keyHandle,
                           SeosCrypto_KeyHandle           wrapKeyHandle,
                           const void*                    key,
                           size_t                         keySize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == key)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, key, keySize, NULL, 0)) == SEOS_SUCCESS)
    {
        retval = SeosCryptoRpc_keyImport(self->rpcHandle, keyHandle, wrapKeyHandle,
                                         keySize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_keyExport(SeosCryptoCtx*                 api,
                           SeosCrypto_KeyHandle           keyHandle,
                           SeosCrypto_KeyHandle           wrapKeyHandle,
                           void*                          key,
                           size_t*                        keySize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == key || NULL == keySize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_keyExport(self->rpcHandle, keyHandle,
                                          wrapKeyHandle, *keySize)) == SEOS_SUCCESS)
    {
        retval = readRpcResult(self, key, keySize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_keyFree(SeosCryptoCtx*                 api,
                         SeosCrypto_KeyHandle           keyHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_keyFree(self->rpcHandle, keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoClient_cipherInit(SeosCryptoCtx*                  api,
                            SeosCrypto_CipherHandle*        pCipherHandle,
                            SeosCryptoCipher_Algorithm      algorithm,
                            SeosCrypto_KeyHandle            key,
                            const void*                     iv,
                            size_t                          ivLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == pCipherHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, iv, ivLen, NULL, 0)) == SEOS_SUCCESS)
    {
        retval = SeosCryptoRpc_cipherInit(self->rpcHandle, pCipherHandle, algorithm,
                                          key, ivLen);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_cipherFree(SeosCryptoCtx*             api,
                            SeosCrypto_CipherHandle    cipherHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_cipherFree(self->rpcHandle, cipherHandle);
}

seos_err_t
SeosCryptoClient_cipherProcess(SeosCryptoCtx*                api,
                               SeosCrypto_CipherHandle       cipherHandle,
                               const void*                   data,
                               size_t                        dataLen,
                               void*                         output,
                               size_t*                       outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable ||
        NULL == data  || NULL == output || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, data, dataLen, NULL, 0)) == SEOS_SUCCESS)
    {
        if ((retval = SeosCryptoRpc_cipherProcess(self->rpcHandle, cipherHandle,
                                                  dataLen, *outputSize)) == SEOS_SUCCESS)
        {
            retval = readRpcResult(self, output, outputSize);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoClient_cipherStart(SeosCryptoCtx*                api,
                             SeosCrypto_CipherHandle       cipherHandle,
                             const void*                   data,
                             size_t                        dataLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, data, dataLen, NULL, 0)) == SEOS_SUCCESS)
    {
        retval = SeosCryptoRpc_cipherStart(self->rpcHandle, cipherHandle, dataLen);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_cipherFinalize(SeosCryptoCtx*              api,
                                SeosCrypto_CipherHandle     cipherHandle,
                                void*                       buf,
                                size_t*                     bufSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == buf || NULL == bufSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = writeRpcArguments(self, buf, *bufSize, NULL, 0)) == SEOS_SUCCESS)
    {
        if ((retval = SeosCryptoRpc_cipherFinalize(self->rpcHandle, cipherHandle,
                                                   *bufSize)) == SEOS_SUCCESS)
        {
            retval = readRpcResult(self, buf, bufSize);
        }
    }

    return retval;
}