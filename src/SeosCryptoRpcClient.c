/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoRpcClient.h"
#include "SeosCryptoRpcServer.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <sys/user.h>

// -------------------------------- RNG API ------------------------------------

static seos_err_t
Rng_getBytes(
    SeosCryptoApi_Context*       api,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == buf)
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

static seos_err_t
Rng_reseed(
    SeosCryptoApi_Context* api,
    const void*            seed,
    const size_t           seedLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == seed)
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

static seos_err_t
Mac_init(
    SeosCryptoApi_Context*      api,
    SeosCryptoLib_Mac**         pMacHandle,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == pMacHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Mac_init(self->rpcHandle, pMacHandle, algorithm);
}

static seos_err_t
Mac_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Mac_free(self->rpcHandle, macHandle);
}

static seos_err_t
Mac_start(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macHandle,
    const void*            secret,
    const size_t           secretSize)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == secret || 0 == secretSize)
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

static seos_err_t
Mac_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macHandle,
    const void*            data,
    const size_t           dataLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == data || 0 == dataLen)
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

static seos_err_t
Mac_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macHandle,
    void*                  mac,
    size_t*                macSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == mac || NULL == macSize)
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

static seos_err_t
Digest_init(
    SeosCryptoApi_Context*         api,
    SeosCryptoLib_Digest**         pDigestHandle,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == pDigestHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Digest_init(self->rpcHandle, pDigestHandle,
                                           algorithm);
}

static seos_err_t
Digest_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digestHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Digest_free(self->rpcHandle, digestHandle);
}

static seos_err_t
Digest_clone(
    SeosCryptoApi_Context*      api,
    SeosCryptoLib_Digest*       dstDigHandle,
    const SeosCryptoLib_Digest* srcDigHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Digest_clone(self->rpcHandle, dstDigHandle,
                                            srcDigHandle);
}

static seos_err_t
Digest_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digestHandle,
    const void*            data,
    const size_t           dataLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == data || 0 == dataLen)
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

static seos_err_t
Digest_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digestHandle,
    void*                  digest,
    size_t*                digestSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == digest || NULL == digestSize)
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

static seos_err_t
Signature_init(
    SeosCryptoApi_Context*            api,
    SeosCryptoLib_Signature**         pSigObj,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == pSigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Signature_init(self->rpcHandle, pSigObj, algorithm,
                                              digest,
                                              prvKey,
                                              pubKey);
}

static seos_err_t
Signature_free(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Signature* sigObj)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Signature_free(self->rpcHandle, sigObj);
}

static seos_err_t
Signature_sign(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == hash || NULL == signature || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, hash, hashSize);
    if ((retval = SeosCryptoRpcServer_Signature_sign(self->rpcHandle, sigObj,
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

static seos_err_t
Signature_verify(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == hash || NULL == signature)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize + signatureSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, hash, hashSize);
    memcpy(self->clientDataport + hashSize, signature, signatureSize);
    return SeosCryptoRpcServer_Signature_verify(self->rpcHandle, sigObj, hashSize,
                                                signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static seos_err_t
Agreement_init(
    SeosCryptoApi_Context*            api,
    SeosCryptoLib_Agreement**         pAgrObj,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == pAgrObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Agreement_init(self->rpcHandle, pAgrObj,
                                              algorithm,  prvKey);
}

static seos_err_t
Agreement_free(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Agreement* agrObj)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Agreement_free(self->rpcHandle, agrObj);
}

static seos_err_t
Agreement_agree(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Agreement* agrObj,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Agreement_agree(self->rpcHandle, agrObj,
                                                      pubKey, sharedSize)) == SEOS_SUCCESS)
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

static seos_err_t
Key_generate(
    SeosCryptoApi_Context*        api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Spec* spec)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == pKeyObj || NULL == spec)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->clientDataport, spec, sizeof(SeosCryptoApi_Key_Spec));
    return SeosCryptoRpcServer_Key_generate(self->rpcHandle, pKeyObj);
}

static seos_err_t
Key_makePublic(
    SeosCryptoApi_Context*           api,
    SeosCryptoLib_Key**              pPubKeyHandle,
    const SeosCryptoLib_Key*         prvKeyHandle,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == pPubKeyHandle || NULL == attribs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->clientDataport, attribs, sizeof(SeosCryptoApi_Key_Attribs));
    return SeosCryptoRpcServer_Key_makePublic(self->rpcHandle, pPubKeyHandle,
                                              prvKeyHandle);
}

static seos_err_t
Key_import(
    SeosCryptoApi_Context*        api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoLib_Key*      wrapKeyObj,
    const SeosCryptoApi_Key_Data* keyData)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == pKeyObj || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->clientDataport, keyData, sizeof(SeosCryptoApi_Key_Data));
    return SeosCryptoRpcServer_Key_import(self->rpcHandle, pKeyObj,
                                          wrapKeyObj);
}

static seos_err_t
Key_export(
    SeosCryptoApi_Context*   api,
    const SeosCryptoLib_Key* keyObj,
    const SeosCryptoLib_Key* wrapKeyObj,
    SeosCryptoApi_Key_Data*  keyData)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Key_export(self->rpcHandle,
                                                 keyObj, wrapKeyObj)) == SEOS_SUCCESS)
    {
        memcpy(keyData, self->clientDataport, sizeof(SeosCryptoApi_Key_Data));
    }

    return retval;
}

static seos_err_t
Key_getParams(
    SeosCryptoApi_Context*   api,
    const SeosCryptoLib_Key* keyObj,
    void*                    keyParams,
    size_t*                  paramSize)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpcServer_Key_getParams(self->rpcHandle,  keyObj,
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

static seos_err_t
Key_loadParams(
    SeosCryptoApi_Context*        api,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyParams || NULL == paramSize)
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

static seos_err_t
Key_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Key*     keyObj)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Key_free(self->rpcHandle, keyObj);
}

// ------------------------------ Cipher API -----------------------------------

static seos_err_t
Cipher_init(
    SeosCryptoApi_Context*         api,
    SeosCryptoLib_Cipher**         pCipherObj,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       key,
    const void*                    iv,
    const size_t                   ivLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == pCipherObj)
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

    return SeosCryptoRpcServer_Cipher_init(self->rpcHandle, pCipherObj, algorithm,
                                           key, ivLen);
}

static seos_err_t
Cipher_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_Cipher_free(self->rpcHandle, cipherObj);
}

static seos_err_t
Cipher_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    const void*            input,
    const size_t           inputSize,
    void*                  output,
    size_t*                outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == input || NULL == output || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, input, inputSize);
    if ((retval = SeosCryptoRpcServer_Cipher_process(self->rpcHandle, cipherObj,
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

static seos_err_t
Cipher_start(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    const void*            data,
    const size_t           dataLen)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self)
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

    return SeosCryptoRpcServer_Cipher_start(self->rpcHandle, cipherObj, dataLen);
}

static seos_err_t
Cipher_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    void*                  tag,
    size_t*                tagSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || NULL == tag || NULL == tagSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*tagSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, tag, *tagSize);
    if ((retval = SeosCryptoRpcServer_Cipher_finalize(self->rpcHandle, cipherObj,
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

// ---------------------------- API Management ---------------------------------

static const SeosCryptoApi_Vtable SeosCryptoRpcClient_vtable =
{
    .Rng_getBytes        = Rng_getBytes,
    .Rng_reseed          = Rng_reseed,
    .Mac_init            = Mac_init,
    .Mac_free            = Mac_free,
    .Mac_start           = Mac_start,
    .Mac_process         = Mac_process,
    .Mac_finalize        = Mac_finalize,
    .Digest_init         = Digest_init,
    .Digest_free         = Digest_free,
    .Digest_clone        = Digest_clone,
    .Digest_process      = Digest_process,
    .Digest_finalize     = Digest_finalize,
    .Key_generate        = Key_generate,
    .Key_makePublic      = Key_makePublic,
    .Key_import          = Key_import,
    .Key_export          = Key_export,
    .Key_getParams       = Key_getParams,
    .Key_loadParams      = Key_loadParams,
    .Key_free            = Key_free,
    .Signature_init      = Signature_init,
    .Signature_free      = Signature_free,
    .Signature_sign      = Signature_sign,
    .Signature_verify    = Signature_verify,
    .Agreement_init      = Agreement_init,
    .Agreement_free      = Agreement_free,
    .Agreement_agree     = Agreement_agree,
    .Cipher_init         = Cipher_init,
    .Cipher_free         = Cipher_free,
    .Cipher_process      = Cipher_process,
    .Cipher_start        = Cipher_start,
    .Cipher_finalize     = Cipher_finalize,
};

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