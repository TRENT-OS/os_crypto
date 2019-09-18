/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoClient.h"

#include "LibDebug/Debug.h"

#include <string.h>

static const SeosCryptoCtx_Vtable SeosCryptoClient_vtable =
{
    .rngGetBytes     = SeosCryptoClient_rngGetBytes,
    .rngReSeed       = SeosCryptoClient_rngReSeed,
    .digestInit      = SeosCryptoClient_digestInit,
    .digestClose     = SeosCryptoClient_digestClose,
    .digestUpdate    = SeosCryptoClient_digestUpdate,
    .digestFinalize  = SeosCryptoClient_digestFinalize,
    .keyInit         = SeosCryptoClient_keyInit,
    .keyGenerate     = SeosCryptoClient_keyGenerate,
    .keyGeneratePair = SeosCryptoClient_keyGeneratePair,
    .keyImport       = SeosCryptoClient_keyImport,
    .keyExport       = SeosCryptoClient_keyExport,
    .keyDeInit       = SeosCryptoClient_keyDeInit,
    .signatureInit   = SeosCryptoClient_signatureInit,
    .signatureDeInit = SeosCryptoClient_signatureDeInit,
    .signatureSign   = SeosCryptoClient_signatureSign,
    .signatureVerify = SeosCryptoClient_signatureVerify,
    .cipherInit      = SeosCryptoClient_cipherInit,
    .cipherClose     = SeosCryptoClient_cipherClose,
    .cipherUpdate    = SeosCryptoClient_cipherUpdate,
    .cipherUpdateAd  = SeosCryptoClient_cipherUpdateAd,
    .cipherFinalize  = SeosCryptoClient_cipherFinalize,
    .cipherVerifyTag = SeosCryptoClient_cipherVerifyTag,
    .deInit          = SeosCryptoClient_deInit
};

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

seos_err_t
SeosCryptoClient_rngGetBytes(SeosCryptoCtx*       api,
                             void**               buffer,
                             size_t               dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == buffer || dataLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCryptoRpc_rngGetBytes(self->rpcHandle,
                                           dataLen);

        if (SEOS_SUCCESS == retval)
        {
            if (*buffer != NULL)
            {
                memcpy(*buffer, self->clientDataport, dataLen);
            }
            else
            {
                *buffer = self->clientDataport;
            }
        }
    }

    return retval;
}

seos_err_t
SeosCryptoClient_rngReSeed(SeosCryptoCtx*       api,
                           const void*          seed,
                           size_t               seedLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (seedLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (seed != NULL)
        {
            memcpy(self->clientDataport, seed, seedLen);
        }
        retval = SeosCryptoRpc_rngReSeed(self->rpcHandle, seedLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_digestInit(SeosCryptoCtx*                  api,
                            SeosCrypto_DigestHandle*        pDigestHandle,
                            SeosCryptoDigest_Algorithm      algorithm,
                            void*                           iv,
                            size_t                          ivLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (ivLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (iv != NULL)
        {
            memcpy(self->clientDataport, iv, ivLen);
        }
        retval = SeosCryptoRpc_digestInit(self->rpcHandle,
                                          pDigestHandle,
                                          algorithm,
                                          ivLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_digestClose(SeosCryptoCtx*             api,
                             SeosCrypto_DigestHandle digestHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    return SeosCryptoRpc_digestClose(self->rpcHandle, digestHandle);
}

seos_err_t
SeosCryptoClient_digestUpdate(SeosCryptoCtx*                api,
                              SeosCrypto_DigestHandle       digestHandle,
                              const void*                   data,
                              size_t                        dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == data || dataLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, data, dataLen);
        retval = SeosCryptoRpc_digestUpdate(self->rpcHandle,
                                            digestHandle,
                                            dataLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoCtx*              api,
                                SeosCrypto_DigestHandle     digestHandle,
                                const void*                 data,
                                size_t                      dataLen,
                                void**                      digest,
                                size_t*                     digestSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (dataLen > PAGE_SIZE || NULL == digest || NULL == digestSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (data != NULL)
        {
            memcpy(self->clientDataport, data, dataLen);
        }
        retval = SeosCryptoRpc_digestFinalize(self->rpcHandle,
                                              digestHandle,
                                              dataLen);

        if (SEOS_SUCCESS == retval)
        {
            size_t* serverDigestLen = (size_t*) self->clientDataport;
            char*   serverDigest    = &(((char*) self->clientDataport)
                                        [sizeof(*serverDigestLen)]);

            if (*digest != NULL)
            {
                if (*digestSize < *serverDigestLen)
                {
                    retval = SEOS_ERROR_BUFFER_TOO_SMALL;
                }
                else
                {
                    *digestSize = *serverDigestLen;
                    memcpy(*digest, serverDigest, *serverDigestLen);
                    retval = SEOS_SUCCESS;
                }
            }
            else
            {
                *digestSize = *serverDigestLen;
                *digest     = serverDigest;
                retval      = SEOS_SUCCESS;
            }
        }
    }
    return retval;
}


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
                               void**                         signature,
                               size_t*                        signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == hash || NULL == signature || NULL == signatureSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > PAGE_SIZE)
    {
        retval = SEOS_ERROR_BUFFER_TOO_SMALL;
    }
    else
    {
        memcpy(self->clientDataport, hash, hashSize);
        if ((retval = SeosCryptoRpc_signatureSign(self->rpcHandle, sigHandle,
                                                  hashSize)) == SEOS_SUCCESS)
        {
            size_t* serverSigLen = (size_t*) self->clientDataport;
            char*   serverSig    = (char*) self->clientDataport + sizeof(size_t);
            if (*signature != NULL)
            {
                if  (*signatureSize < *serverSigLen)
                {
                    retval = SEOS_ERROR_BUFFER_TOO_SMALL;
                }
                else
                {
                    *signatureSize = *serverSigLen;
                    memcpy(*signature, serverSig, *serverSigLen);
                }
            }
            else
            {
                *signatureSize = *serverSigLen;
                *signature     = serverSig;
            }
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
    else if (hashSize + signatureSize > PAGE_SIZE)
    {
        retval = SEOS_ERROR_BUFFER_TOO_SMALL;
    }
    else
    {
        memcpy(self->clientDataport, hash, hashSize);
        memcpy(self->clientDataport + hashSize, signature, signatureSize);
        retval = SeosCryptoRpc_signatureVerify(self->rpcHandle, sigHandle, hashSize,
                                               signatureSize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_keyInit(SeosCryptoCtx*                   api,
                         SeosCrypto_KeyHandle*            keyHandle,
                         unsigned int                     type,
                         SeosCryptoKey_Flag               flags,
                         size_t                           bits)
{

    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || NULL == keyHandle
        || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_keyInit(self->rpcHandle, keyHandle, type, flags, bits);
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
    seos_err_t retval   = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == key || keySize > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, key, keySize);
        retval = SeosCryptoRpc_keyImport(self->rpcHandle, keyHandle, wrapKeyHandle,
                                         keySize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_keyExport(SeosCryptoCtx*                 api,
                           SeosCrypto_KeyHandle           keyHandle,
                           SeosCrypto_KeyHandle           wrapKeyHandle,
                           void**                         key,
                           size_t*                        keySize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == key || NULL == keySize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((retval = SeosCryptoRpc_keyExport(self->rpcHandle, keyHandle,
                                               wrapKeyHandle)) == SEOS_SUCCESS)
    {
        size_t* outSize  = (size_t*) self->clientDataport;
        char*   out      = &(((char*) self->clientDataport)[sizeof(*keySize)]);

        if (*key != NULL)
        {
            if (*keySize < *outSize)
            {
                retval = SEOS_ERROR_BUFFER_TOO_SMALL;
            }
            else
            {
                *keySize = *outSize;
                memcpy(*key, out, *keySize);
                retval = SEOS_SUCCESS;
            }
        }
        else
        {
            *keySize = *outSize;
            *key     = out;
            retval   = SEOS_SUCCESS;
        }
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

seos_err_t
SeosCryptoClient_cipherInit(SeosCryptoCtx*                  api,
                            SeosCrypto_CipherHandle*        pKeyHandle,
                            SeosCryptoCipher_Algorithm      algorithm,
                            SeosCrypto_KeyHandle            key,
                            const void*                     iv,
                            size_t                          ivLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (ivLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (iv != NULL)
        {
            memcpy(self->clientDataport, iv, ivLen);
        }
        retval = SeosCryptoRpc_cipherInit(self->rpcHandle,
                                          pKeyHandle,
                                          algorithm,
                                          key,
                                          ivLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_cipherClose(SeosCryptoCtx*             api,
                             SeosCrypto_CipherHandle    cipherHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    return SeosCryptoRpc_cipherClose(self->rpcHandle, cipherHandle);
}

seos_err_t
SeosCryptoClient_cipherUpdate(SeosCryptoCtx*                api,
                              SeosCrypto_CipherHandle       cipherHandle,
                              const void*                   data,
                              size_t                        dataLen,
                              void**                        output,
                              size_t*                       outputSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == data || dataLen > PAGE_SIZE
        || NULL == output || NULL == outputSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, data, dataLen);
        retval = SeosCryptoRpc_cipherUpdate(self->rpcHandle,
                                            cipherHandle,
                                            dataLen);

        if (SEOS_SUCCESS == retval)
        {
            size_t* outSize = (size_t*) self->clientDataport;
            char*   out     = &(((char*) self->clientDataport)[sizeof(*outputSize)]);

            if (*output != NULL)
            {
                if (*outputSize < *outSize)
                {
                    retval = SEOS_ERROR_BUFFER_TOO_SMALL;
                }
                else
                {
                    *outputSize = *outSize;
                    memcpy(*output, out, *outputSize);
                    retval = SEOS_SUCCESS;
                }
            }
            else
            {
                *outputSize = *outSize;
                *output     = out;
                retval      = SEOS_SUCCESS;
            }
        }
    }

    return retval;
}

seos_err_t
SeosCryptoClient_cipherUpdateAd(SeosCryptoCtx*                api,
                                SeosCrypto_CipherHandle       cipherHandle,
                                const void*                   data,
                                size_t                        dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == data || dataLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, data, dataLen);
        retval = SeosCryptoRpc_cipherUpdateAd(self->rpcHandle, cipherHandle, dataLen);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_cipherFinalize(SeosCryptoCtx*              api,
                                SeosCrypto_CipherHandle     cipherHandle,
                                void**                      output,
                                size_t*                     outputSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == output || NULL == outputSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCryptoRpc_cipherFinalize(self->rpcHandle, cipherHandle);
        if (SEOS_SUCCESS == retval)
        {
            size_t* outSize  = (size_t*) self->clientDataport;
            char*   out      = &(((char*) self->clientDataport)[sizeof(*outputSize)]);

            if (*output != NULL)
            {
                if (*outputSize < *outSize)
                {
                    retval = SEOS_ERROR_BUFFER_TOO_SMALL;
                }
                else
                {
                    *outputSize = *outSize;
                    memcpy(*output, out, *outputSize);
                    retval = SEOS_SUCCESS;
                }
            }
            else
            {
                *outputSize = *outSize;
                *output     = out;
                retval      = SEOS_SUCCESS;
            }
        }
    }

    return retval;
}

seos_err_t
SeosCryptoClient_cipherVerifyTag(SeosCryptoCtx*              api,
                                 SeosCrypto_CipherHandle     cipherHandle,
                                 const void*                 tag,
                                 size_t                      tagLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCryptoClient_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == tag || tagLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, tag, tagLen);
        retval = SeosCryptoRpc_cipherVerifyTag(self->rpcHandle, cipherHandle, tagLen);
    }

    return retval;
}