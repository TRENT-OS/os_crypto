/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoRpcClient.h"
#include "SeosCryptoRpcServer.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <sys/user.h>

static const SeosCryptoApi_Vtable SeosCryptoRpcClient_vtable =
{
    .Rng_getBytes        = SeosCryptoRpcClient_Rng_getBytes,
    .Rng_reseed          = SeosCryptoRpcClient_Rng_reseed,
    .Mac_init            = SeosCryptoRpcClient_Mac_init,
    .Mac_free            = SeosCryptoRpcClient_Mac_free,
    .Mac_start           = SeosCryptoRpcClient_Mac_start,
    .Mac_process         = SeosCryptoRpcClient_Mac_process,
    .Mac_finalize        = SeosCryptoRpcClient_Mac_finalize,
    .Digest_init         = SeosCryptoRpcClient_Digest_init,
    .Digest_free         = SeosCryptoRpcClient_Digest_free,
    .Digest_clone        = SeosCryptoRpcClient_Digest_clone,
    .Digest_process      = SeosCryptoRpcClient_Digest_process,
    .Digest_finalize     = SeosCryptoRpcClient_Digest_finalize,
    .Key_generate        = SeosCryptoRpcClient_Key_generate,
    .Key_makePublic      = SeosCryptoRpcClient_Key_makePublic,
    .Key_import          = SeosCryptoRpcClient_Key_import,
    .Key_export          = SeosCryptoRpcClient_Key_export,
    .Key_getParams       = SeosCryptoRpcClient_Key_getParams,
    .Key_loadParams      = SeosCryptoRpcClient_Key_loadParams,
    .Key_free            = SeosCryptoRpcClient_Key_free,
    .Signature_init      = SeosCryptoRpcClient_Signature_init,
    .Signature_free      = SeosCryptoRpcClient_Signature_free,
    .Signature_sign      = SeosCryptoRpcClient_Signature_sign,
    .Signature_verify    = SeosCryptoRpcClient_Signature_verify,
    .Agreement_init      = SeosCryptoRpcClient_Agreement_init,
    .Agreement_free      = SeosCryptoRpcClient_Agreement_free,
    .Agreement_agree     = SeosCryptoRpcClient_Agreement_agree,
    .Cipher_init         = SeosCryptoRpcClient_Cipher_init,
    .Cipher_free         = SeosCryptoRpcClient_Cipher_free,
    .Cipher_process      = SeosCryptoRpcClient_Cipher_process,
    .Cipher_start        = SeosCryptoRpcClient_Cipher_start,
    .Cipher_finalize     = SeosCryptoRpcClient_Cipher_finalize,
    .free               = SeosCryptoRpcClient_free
};

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoRpcClient_init(
    SeosCryptoRpcClient*    self,
    SeosCryptoApi_RpcServer rpcHandle,
    void*                   dataport)
{
    if (NULL == self || NULL == rpcHandle || NULL == dataport)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->clientDataport = dataport;
    self->rpcHandle      = rpcHandle;
    self->parent.vtable  = &SeosCryptoRpcClient_vtable;

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoRpcClient_free(
    SeosCryptoApi_Context* api)
{
    return SEOS_SUCCESS;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpcClient_Rng_getBytes(
    SeosCryptoApi_Context*       api,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == buf
        || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Rng_getBytes(self->rpcHandle, flags,
                                                   bufLen)) == SEOS_SUCCESS)
    {
        if (bufLen > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(buf, self->clientDataport, bufLen);
    }

    return retval;
}

seos_err_t
SeosCryptoRpcClient_Rng_reseed(
    SeosCryptoApi_Context* api,
    const void*            seed,
    const size_t           seedLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == seed
        || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (seedLen > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, seed, seedLen);
    return SeosCryptoRpcServer_Rng_reseed(self->rpcHandle, seedLen);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
SeosCryptoRpcClient_Mac_init(
    SeosCryptoApi_Context*      api,
    SeosCryptoApi_Mac*          pMacHandle,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == pMacHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Mac_init(self->rpcHandle, pMacHandle, algorithm);
}

seos_err_t
SeosCryptoRpcClient_Mac_free(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Mac macHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Mac_free(self->rpcHandle, macHandle);
}

seos_err_t
SeosCryptoRpcClient_Mac_start(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Mac macHandle,
    const void*             secret,
    const size_t            secretSize)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == secret || 0 == secretSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (secretSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, secret, secretSize);
    return SeosCryptoRpcServer_Mac_start(self->rpcHandle, macHandle, secretSize);
}

seos_err_t
SeosCryptoRpcClient_Mac_process(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Mac macHandle,
    const void*             data,
    const size_t            dataLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == data || 0 == dataLen)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataLen > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, data, dataLen);
    return SeosCryptoRpcServer_Mac_process(self->rpcHandle, macHandle, dataLen);
}

seos_err_t
SeosCryptoRpcClient_Mac_finalize(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Mac macHandle,
    void*                   mac,
    size_t*                 macSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == mac || NULL == macSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Mac_finalize(self->rpcHandle, macHandle,
                                                   macSize)) == SEOS_SUCCESS)
    {
        if (*macSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(mac, self->clientDataport, *macSize);
    }

    return retval;
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcClient_Digest_init(
    SeosCryptoApi_Context*         api,
    SeosCryptoApi_Digest*          pDigestHandle,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == pDigestHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Digest_init(self->rpcHandle, pDigestHandle,
                                           algorithm);
}

seos_err_t
SeosCryptoRpcClient_Digest_free(
    SeosCryptoApi_Context*     api,
    const SeosCryptoApi_Digest digestHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Digest_free(self->rpcHandle, digestHandle);
}

seos_err_t
SeosCryptoRpcClient_Digest_clone(
    SeosCryptoApi_Context*     api,
    const SeosCryptoApi_Digest dstDigHandle,
    const SeosCryptoApi_Digest srcDigHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Digest_clone(self->rpcHandle, dstDigHandle,
                                            srcDigHandle);
}

seos_err_t
SeosCryptoRpcClient_Digest_process(
    SeosCryptoApi_Context*     api,
    const SeosCryptoApi_Digest digestHandle,
    const void*                data,
    const size_t               dataLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == data || 0 == dataLen)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataLen > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, data, dataLen);
    return SeosCryptoRpcServer_Digest_process(self->rpcHandle, digestHandle,
                                              dataLen);
}

seos_err_t
SeosCryptoRpcClient_Digest_finalize(
    SeosCryptoApi_Context*     api,
    const SeosCryptoApi_Digest digestHandle,
    void*                      digest,
    size_t*                    digestSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == digest || NULL == digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Digest_finalize(self->rpcHandle, digestHandle,
                                                      digestSize)) == SEOS_SUCCESS)
    {
        if (*digestSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(digest, self->clientDataport, *digestSize);
    }

    return retval;
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpcClient_Signature_init(
    SeosCryptoApi_Context*
    api,
    SeosCryptoApi_Signature*          pSigHandle,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoApi_Key           prvHandle,
    const SeosCryptoApi_Key           pubHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == pSigHandle
        || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Signature_init(self->rpcHandle, pSigHandle,
                                              algorithm,
                                              digest, prvHandle, pubHandle);
}

seos_err_t
SeosCryptoRpcClient_Signature_free(
    SeosCryptoApi_Context*        api,
    const SeosCryptoApi_Signature sigHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Signature_free(self->rpcHandle, sigHandle);
}

seos_err_t
SeosCryptoRpcClient_Signature_sign(
    SeosCryptoApi_Context*        api,
    const SeosCryptoApi_Signature sigHandle,
    const void*                   hash,
    const size_t                  hashSize,
    void*                         signature,
    size_t*                       signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == hash || NULL == signature || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, hash, hashSize);
    if ((retval = SeosCryptoRpcServer_Signature_sign(self->rpcHandle, sigHandle,
                                                     hashSize, signatureSize)) == SEOS_SUCCESS)
    {
        if (*signatureSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(signature, self->clientDataport, *signatureSize);
    }

    return retval;
}

seos_err_t
SeosCryptoRpcClient_Signature_verify(
    SeosCryptoApi_Context*
    api,
    const SeosCryptoApi_Signature sigHandle,
    const void*                   hash,
    const size_t                  hashSize,
    const void*                   signature,
    const size_t                  signatureSize)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == hash || NULL == signature)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize + signatureSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, hash, hashSize);
    memcpy(self->clientDataport + hashSize, signature, signatureSize);
    return SeosCryptoRpcServer_Signature_verify(self->rpcHandle, sigHandle,
                                                hashSize,
                                                signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpcClient_Agreement_init(
    SeosCryptoApi_Context*
    api,
    SeosCryptoApi_Agreement*          pAgrHandle,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoApi_Key           prvHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == pAgrHandle
        || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Agreement_init(self->rpcHandle, pAgrHandle,
                                              algorithm,
                                              prvHandle);
}

seos_err_t
SeosCryptoRpcClient_Agreement_free(
    SeosCryptoApi_Context*        api,
    const SeosCryptoApi_Agreement agrHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Agreement_free(self->rpcHandle, agrHandle);
}

seos_err_t
SeosCryptoRpcClient_Agreement_agree(
    SeosCryptoApi_Context*
    api,
    const SeosCryptoApi_Agreement agrHandle,
    const SeosCryptoApi_Key       pubHandle,
    void*                         shared,
    size_t*                       sharedSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Agreement_agree(self->rpcHandle, agrHandle,
                                                      pubHandle, sharedSize)) == SEOS_SUCCESS)
    {
        if (*sharedSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(shared, self->clientDataport, *sharedSize);
    }

    return retval;
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpcClient_Key_generate(
    SeosCryptoApi_Context*        api,
    SeosCryptoApi_Key*            pKeyHandle,
    const SeosCryptoApi_Key_Spec* spec)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == pKeyHandle || NULL == spec
        || &SeosCryptoRpcClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->clientDataport, spec, sizeof(SeosCryptoApi_Key_Spec));
    return SeosCryptoRpcServer_Key_generate(self->rpcHandle, pKeyHandle);
}

seos_err_t
SeosCryptoRpcClient_Key_makePublic(
    SeosCryptoApi_Context*           api,
    SeosCryptoApi_Key*               pPubKeyHandle,
    const SeosCryptoApi_Key          prvKeyHandle,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == pPubKeyHandle || NULL == attribs
        || &SeosCryptoRpcClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->clientDataport, attribs, sizeof(SeosCryptoApi_Key_Attribs));
    return SeosCryptoRpcServer_Key_makePublic(self->rpcHandle, pPubKeyHandle,
                                              prvKeyHandle);
}

seos_err_t
SeosCryptoRpcClient_Key_import(
    SeosCryptoApi_Context*        api,
    SeosCryptoApi_Key*            pKeyHandle,
    const SeosCryptoApi_Key       wrapKeyHandle,
    const SeosCryptoApi_Key_Data* keyData)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == pKeyHandle || NULL == keyData
        || &SeosCryptoRpcClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->clientDataport, keyData, sizeof(SeosCryptoApi_Key_Data));
    return SeosCryptoRpcServer_Key_import(self->rpcHandle, pKeyHandle,
                                          wrapKeyHandle);
}

seos_err_t
SeosCryptoRpcClient_Key_export(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Key keyHandle,
    const SeosCryptoApi_Key wrapKeyHandle,
    SeosCryptoApi_Key_Data* keyData)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable
        || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Key_export(self->rpcHandle, keyHandle,
                                                 wrapKeyHandle)) == SEOS_SUCCESS)
    {
        memcpy(keyData, self->clientDataport, sizeof(SeosCryptoApi_Key_Data));
    }

    return retval;
}

seos_err_t
SeosCryptoRpcClient_Key_getParams(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Key keyHandle,
    void*                   keyParams,
    size_t*                 paramSize)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable
        || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Key_getParams(self->rpcHandle, keyHandle,
                                                    paramSize)) == SEOS_SUCCESS)
    {
        if (*paramSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(keyParams, self->clientDataport, *paramSize);
    }

    return retval;
}

seos_err_t
SeosCryptoRpcClient_Key_loadParams(
    SeosCryptoApi_Context*        api,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable
        || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Key_loadParams(self->rpcHandle, name,
                                                     paramSize)) == SEOS_SUCCESS)
    {
        if (*paramSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(keyParams, self->clientDataport, *paramSize);
    }

    return retval;
}

seos_err_t
SeosCryptoRpcClient_Key_free(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Key keyHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Key_free(self->rpcHandle, keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoRpcClient_Cipher_init(
    SeosCryptoApi_Context*         api,
    SeosCryptoApi_Cipher*          pCipherHandle,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoApi_Key        key,
    const void*                    iv,
    const size_t                   ivLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable
        || NULL == pCipherHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (iv != NULL)
    {
        if (ivLen > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(self->clientDataport, iv, ivLen);
    }

    return SeosCryptoRpcServer_Cipher_init(self->rpcHandle, pCipherHandle,
                                           algorithm,
                                           key, ivLen);
}

seos_err_t
SeosCryptoRpcClient_Cipher_free(
    SeosCryptoApi_Context*     api,
    const SeosCryptoApi_Cipher cipherHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Cipher_free(self->rpcHandle, cipherHandle);
}

seos_err_t
SeosCryptoRpcClient_Cipher_process(
    SeosCryptoApi_Context*     api,
    const SeosCryptoApi_Cipher cipherHandle,
    const void*                input,
    const size_t               inputSize,
    void*                      output,
    size_t*                    outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable ||
        NULL == input || NULL == output || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, input, inputSize);
    if ((retval = SeosCryptoRpcServer_Cipher_process(self->rpcHandle, cipherHandle,
                                                     inputSize, outputSize)) == SEOS_SUCCESS)
    {
        if (*outputSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(output, self->clientDataport, *outputSize);
    }

    return retval;
}

seos_err_t
SeosCryptoRpcClient_Cipher_start(
    SeosCryptoApi_Context*     api,
    const SeosCryptoApi_Cipher cipherHandle,
    const void*                data,
    const size_t               dataLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL != data)
    {
        if (dataLen > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(self->clientDataport, data, dataLen);
    }

    return SeosCryptoRpcServer_Cipher_start(self->rpcHandle, cipherHandle, dataLen);
}

seos_err_t
SeosCryptoRpcClient_Cipher_finalize(
    SeosCryptoApi_Context*     api,
    const SeosCryptoApi_Cipher cipherHandle,
    void*                      tag,
    size_t*                    tagSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable
        || NULL == tag || NULL == tagSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*tagSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, tag, *tagSize);
    if ((retval = SeosCryptoRpcServer_Cipher_finalize(self->rpcHandle, cipherHandle,
                                                      tagSize)) == SEOS_SUCCESS)
    {
        if (*tagSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(tag, self->clientDataport, *tagSize);
    }

    return retval;
}