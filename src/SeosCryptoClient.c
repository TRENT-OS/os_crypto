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
    .digestClose             = SeosCryptoClient_digestClose,
    .digestUpdate            = SeosCryptoClient_digestUpdate,
    .digestFinalize          = SeosCryptoClient_digestFinalize,
    .keyInit                 = SeosCryptoClient_keyInit,
    .keyGenerate             = SeosCryptoClient_keyGenerate,
    .keyGeneratePair         = SeosCryptoClient_keyGeneratePair,
    .keyImport               = SeosCryptoClient_keyImport,
    .keyExport               = SeosCryptoClient_keyExport,
    .keyDeInit               = SeosCryptoClient_keyDeInit,
    .signatureInit           = SeosCryptoClient_signatureInit,
    .signatureDeInit         = SeosCryptoClient_signatureDeInit,
    .signatureSign           = SeosCryptoClient_signatureSign,
    .signatureVerify         = SeosCryptoClient_signatureVerify,
    .agreementInit           = SeosCryptoClient_agreementInit,
    .agreementDeInit         = SeosCryptoClient_agreementDeInit,
    .agreementAgree          = SeosCryptoClient_agreementAgree,
    .cipherInit              = SeosCryptoClient_cipherInit,
    .cipherClose             = SeosCryptoClient_cipherClose,
    .cipherUpdate            = SeosCryptoClient_cipherUpdate,
    .cipherStart             = SeosCryptoClient_cipherStart,
    .cipherFinalize          = SeosCryptoClient_cipherFinalize,
    .deInit                  = SeosCryptoClient_deInit
};

// Private functions -----------------------------------------------------------

static seos_err_t
parseRpcOutput(SeosCryptoClient*    self,
               void**               output,
               size_t*              outputSize)
{
    seos_err_t retval;
    size_t* rpcOutputLen;
    void*   rpcOutput;

    rpcOutputLen = (size_t*) self->clientDataport;
    rpcOutput = self->clientDataport + sizeof(rpcOutputLen);

    retval = SEOS_SUCCESS;
    if (*output != NULL)
    {
        if (*outputSize < *rpcOutputLen)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            *outputSize = *rpcOutputLen;
            memcpy(*output, rpcOutput, *outputSize);
        }
    }
    else
    {
        *outputSize = *rpcOutputLen;
        *output     = rpcOutput;
    }

    return retval;
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
SeosCryptoClient_deInit(SeosCryptoCtx* api)
{
    return;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoClient_rngGetBytes(SeosCryptoCtx*       api,
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

    if ((retval = SeosCryptoRpc_rngGetBytes(self->rpcHandle,
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
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || NULL == seed
        || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (seedLen > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(self->clientDataport, seed, seedLen);

    return SeosCryptoRpc_rngReSeed(self->rpcHandle, seedLen);
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
SeosCryptoClient_digestClose(SeosCryptoCtx*             api,
                             SeosCrypto_DigestHandle digestHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_digestClose(self->rpcHandle, digestHandle);
}

seos_err_t
SeosCryptoClient_digestUpdate(SeosCryptoCtx*                api,
                              SeosCrypto_DigestHandle       digestHandle,
                              const void*                   data,
                              size_t                        dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == data || 0 == dataLen)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataLen > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(self->clientDataport, data, dataLen);

    return SeosCryptoRpc_digestUpdate(self->rpcHandle, digestHandle, dataLen);
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
        retval = parseRpcOutput(self, &digest, digestSize);
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
SeosCryptoClient_signatureDeInit(SeosCryptoCtx*               api,
                                 SeosCrypto_SignatureHandle   sigHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_signatureDeInit(self->rpcHandle, sigHandle);
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
    else if (hashSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(self->clientDataport, hash, hashSize);

    if ((retval = SeosCryptoRpc_signatureSign(self->rpcHandle, sigHandle,
                                              hashSize, *signatureSize)) == SEOS_SUCCESS)
    {
        retval = parseRpcOutput(self, &signature, signatureSize);
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
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == hash || NULL == signature)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize + signatureSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(self->clientDataport, hash, hashSize);
    memcpy(self->clientDataport + hashSize, signature, signatureSize);

    return SeosCryptoRpc_signatureVerify(self->rpcHandle, sigHandle, hashSize,
                                         signatureSize);
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
SeosCryptoClient_agreementDeInit(SeosCryptoCtx*               api,
                                 SeosCrypto_AgreementHandle   agrHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_agreementDeInit(self->rpcHandle, agrHandle);
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
        retval = parseRpcOutput(self, &shared, sharedSize);
    }

    return retval;
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoClient_keyInit(SeosCryptoCtx*                   api,
                         SeosCrypto_KeyHandle*            pKeyHandle,
                         unsigned int                     type,
                         SeosCryptoKey_Flag               flags,
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
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == key)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (keySize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(self->clientDataport, key, keySize);

    return SeosCryptoRpc_keyImport(self->rpcHandle, keyHandle, wrapKeyHandle,
                                   keySize);
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
        retval = parseRpcOutput(self, &key, keySize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_keyDeInit(SeosCryptoCtx*                 api,
                           SeosCrypto_KeyHandle           keyHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_keyDeInit(self->rpcHandle, keyHandle);
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
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == pCipherHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if (ivLen > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    if (iv != NULL)
    {
        memcpy(self->clientDataport, iv, ivLen);
    }

    return SeosCryptoRpc_cipherInit(self->rpcHandle, pCipherHandle, algorithm, key,
                                    ivLen);
}

seos_err_t
SeosCryptoClient_cipherClose(SeosCryptoCtx*             api,
                             SeosCrypto_CipherHandle    cipherHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_cipherClose(self->rpcHandle, cipherHandle);
}

seos_err_t
SeosCryptoClient_cipherUpdate(SeosCryptoCtx*                api,
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
    else if (dataLen > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(self->clientDataport, data, dataLen);

    if ((retval = SeosCryptoRpc_cipherUpdate(self->rpcHandle, cipherHandle,
                                             dataLen, *outputSize)) == SEOS_SUCCESS)
    {
        retval = parseRpcOutput(self, &output, outputSize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_cipherStart(SeosCryptoCtx*                api,
                             SeosCrypto_CipherHandle       cipherHandle,
                             const void*                   data,
                             size_t                        dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataLen > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    if (NULL != data)
    {
        memcpy(self->clientDataport, data, dataLen);
    }

    return SeosCryptoRpc_cipherStart(self->rpcHandle, cipherHandle, dataLen);
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
    else if (*bufSize > PAGE_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    if (*bufSize > 0)
    {
        memcpy(self->clientDataport, buf, *bufSize);
    }

    if ((retval = SeosCryptoRpc_cipherFinalize(self->rpcHandle, cipherHandle,
                                               *bufSize)) == SEOS_SUCCESS)
    {
        // WARNING: we use &buf here, will be removed with the void** cleanup!!
        retval = parseRpcOutput(self, &buf, bufSize);
    }

    return retval;
}