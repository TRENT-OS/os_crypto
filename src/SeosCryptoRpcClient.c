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
    .rngGetBytes        = SeosCryptoRpcClient_rngGetBytes,
    .rngReSeed          = SeosCryptoRpcClient_rngReSeed,
    .macInit            = SeosCryptoRpcClient_macInit,
    .macFree            = SeosCryptoRpcClient_macFree,
    .macStart           = SeosCryptoRpcClient_macStart,
    .macProcess         = SeosCryptoRpcClient_macProcess,
    .macFinalize        = SeosCryptoRpcClient_macFinalize,
    .digestInit         = SeosCryptoRpcClient_digestInit,
    .digestFree         = SeosCryptoRpcClient_digestFree,
    .digestClone        = SeosCryptoRpcClient_digestClone,
    .digestProcess      = SeosCryptoRpcClient_digestProcess,
    .digestFinalize     = SeosCryptoRpcClient_digestFinalize,
    .keyGenerate        = SeosCryptoRpcClient_keyGenerate,
    .keyMakePublic      = SeosCryptoRpcClient_keyMakePublic,
    .keyImport          = SeosCryptoRpcClient_keyImport,
    .keyExport          = SeosCryptoRpcClient_keyExport,
    .keyGetParams       = SeosCryptoRpcClient_keyGetParams,
    .keyLoadParams      = SeosCryptoRpcClient_keyLoadParams,
    .keyFree            = SeosCryptoRpcClient_keyFree,
    .signatureInit      = SeosCryptoRpcClient_signatureInit,
    .signatureFree      = SeosCryptoRpcClient_signatureFree,
    .signatureSign      = SeosCryptoRpcClient_signatureSign,
    .signatureVerify    = SeosCryptoRpcClient_signatureVerify,
    .agreementInit      = SeosCryptoRpcClient_agreementInit,
    .agreementFree      = SeosCryptoRpcClient_agreementFree,
    .agreementAgree     = SeosCryptoRpcClient_agreementAgree,
    .cipherInit         = SeosCryptoRpcClient_cipherInit,
    .cipherFree         = SeosCryptoRpcClient_cipherFree,
    .cipherProcess      = SeosCryptoRpcClient_cipherProcess,
    .cipherStart        = SeosCryptoRpcClient_cipherStart,
    .cipherFinalize     = SeosCryptoRpcClient_cipherFinalize,
    .free               = SeosCryptoRpcClient_free
};

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoRpcClient_init(SeosCryptoRpcClient*    self,
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
SeosCryptoRpcClient_free(SeosCryptoApi_Context* api)
{
    return SEOS_SUCCESS;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpcClient_rngGetBytes(SeosCryptoApi_Context*       api,
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

    if ((retval = SeosCryptoRpcServer_rngGetBytes(self->rpcHandle, flags,
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
SeosCryptoRpcClient_rngReSeed(SeosCryptoApi_Context* api,
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
    return SeosCryptoRpcServer_rngReSeed(self->rpcHandle, seedLen);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
SeosCryptoRpcClient_macInit(SeosCryptoApi_Context*      api,
                            SeosCryptoApi_Mac*          pMacHandle,
                            const SeosCryptoApi_Mac_Alg algorithm)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == pMacHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_macInit(self->rpcHandle, pMacHandle, algorithm);
}

seos_err_t
SeosCryptoRpcClient_macFree(SeosCryptoApi_Context*  api,
                            const SeosCryptoApi_Mac macHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_macFree(self->rpcHandle, macHandle);
}

seos_err_t
SeosCryptoRpcClient_macStart(SeosCryptoApi_Context*  api,
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
    return SeosCryptoRpcServer_macStart(self->rpcHandle, macHandle, secretSize);
}

seos_err_t
SeosCryptoRpcClient_macProcess(SeosCryptoApi_Context*  api,
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
    return SeosCryptoRpcServer_macProcess(self->rpcHandle, macHandle, dataLen);
}

seos_err_t
SeosCryptoRpcClient_macFinalize(SeosCryptoApi_Context*  api,
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

    if ((retval = SeosCryptoRpcServer_macFinalize(self->rpcHandle, macHandle,
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
SeosCryptoRpcClient_digestInit(SeosCryptoApi_Context*         api,
                               SeosCryptoApi_Digest*          pDigestHandle,
                               const SeosCryptoApi_Digest_Alg algorithm)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable
        || NULL == pDigestHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_digestInit(self->rpcHandle, pDigestHandle,
                                          algorithm);
}

seos_err_t
SeosCryptoRpcClient_digestFree(SeosCryptoApi_Context*     api,
                               const SeosCryptoApi_Digest digestHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_digestFree(self->rpcHandle, digestHandle);
}

seos_err_t
SeosCryptoRpcClient_digestClone(SeosCryptoApi_Context*     api,
                                const SeosCryptoApi_Digest dstDigHandle,
                                const SeosCryptoApi_Digest srcDigHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_digestClone(self->rpcHandle, dstDigHandle,
                                           srcDigHandle);
}

seos_err_t
SeosCryptoRpcClient_digestProcess(SeosCryptoApi_Context*     api,
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
    return SeosCryptoRpcServer_digestProcess(self->rpcHandle, digestHandle,
                                             dataLen);
}

seos_err_t
SeosCryptoRpcClient_digestFinalize(SeosCryptoApi_Context*     api,
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

    if ((retval = SeosCryptoRpcServer_digestFinalize(self->rpcHandle, digestHandle,
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
SeosCryptoRpcClient_signatureInit(SeosCryptoApi_Context*
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

    return SeosCryptoRpcServer_signatureInit(self->rpcHandle, pSigHandle, algorithm,
                                             digest, prvHandle, pubHandle);
}

seos_err_t
SeosCryptoRpcClient_signatureFree(SeosCryptoApi_Context*        api,
                                  const SeosCryptoApi_Signature sigHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_signatureFree(self->rpcHandle, sigHandle);
}

seos_err_t
SeosCryptoRpcClient_signatureSign(SeosCryptoApi_Context*        api,
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
    if ((retval = SeosCryptoRpcServer_signatureSign(self->rpcHandle, sigHandle,
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
SeosCryptoRpcClient_signatureVerify(SeosCryptoApi_Context*
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
    return SeosCryptoRpcServer_signatureVerify(self->rpcHandle, sigHandle, hashSize,
                                               signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpcClient_agreementInit(SeosCryptoApi_Context*
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

    return SeosCryptoRpcServer_agreementInit(self->rpcHandle, pAgrHandle, algorithm,
                                             prvHandle);
}

seos_err_t
SeosCryptoRpcClient_agreementFree(SeosCryptoApi_Context*        api,
                                  const SeosCryptoApi_Agreement agrHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoRpcClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_agreementFree(self->rpcHandle, agrHandle);
}

seos_err_t
SeosCryptoRpcClient_agreementAgree(SeosCryptoApi_Context*
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

    if ((retval = SeosCryptoRpcServer_agreementAgree(self->rpcHandle, agrHandle,
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
SeosCryptoRpcClient_keyGenerate(SeosCryptoApi_Context*        api,
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
    return SeosCryptoRpcServer_keyGenerate(self->rpcHandle, pKeyHandle);
}

seos_err_t
SeosCryptoRpcClient_keyMakePublic(SeosCryptoApi_Context*           api,
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
    return SeosCryptoRpcServer_keyMakePublic(self->rpcHandle, pPubKeyHandle,
                                             prvKeyHandle);
}

seos_err_t
SeosCryptoRpcClient_keyImport(SeosCryptoApi_Context*        api,
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
    return SeosCryptoRpcServer_keyImport(self->rpcHandle, pKeyHandle,
                                         wrapKeyHandle);
}

seos_err_t
SeosCryptoRpcClient_keyExport(SeosCryptoApi_Context*  api,
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

    if ((retval = SeosCryptoRpcServer_keyExport(self->rpcHandle, keyHandle,
                                                wrapKeyHandle)) == SEOS_SUCCESS)
    {
        memcpy(keyData, self->clientDataport, sizeof(SeosCryptoApi_Key_Data));
    }

    return retval;
}

seos_err_t
SeosCryptoRpcClient_keyGetParams(SeosCryptoApi_Context*  api,
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

    if ((retval = SeosCryptoRpcServer_keyGetParams(self->rpcHandle, keyHandle,
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
SeosCryptoRpcClient_keyLoadParams(SeosCryptoApi_Context*        api,
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

    if ((retval = SeosCryptoRpcServer_keyLoadParams(self->rpcHandle, name,
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
SeosCryptoRpcClient_keyFree(SeosCryptoApi_Context*  api,
                            const SeosCryptoApi_Key keyHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_keyFree(self->rpcHandle, keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoRpcClient_cipherInit(SeosCryptoApi_Context*         api,
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

    return SeosCryptoRpcServer_cipherInit(self->rpcHandle, pCipherHandle, algorithm,
                                          key, ivLen);
}

seos_err_t
SeosCryptoRpcClient_cipherFree(SeosCryptoApi_Context*     api,
                               const SeosCryptoApi_Cipher cipherHandle)
{
    SeosCryptoRpcClient* self = (SeosCryptoRpcClient*) api;

    if (NULL == self || &SeosCryptoRpcClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpcServer_cipherFree(self->rpcHandle, cipherHandle);
}

seos_err_t
SeosCryptoRpcClient_cipherProcess(SeosCryptoApi_Context*     api,
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
    if ((retval = SeosCryptoRpcServer_cipherProcess(self->rpcHandle, cipherHandle,
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
SeosCryptoRpcClient_cipherStart(SeosCryptoApi_Context*     api,
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

    return SeosCryptoRpcServer_cipherStart(self->rpcHandle, cipherHandle, dataLen);
}

seos_err_t
SeosCryptoRpcClient_cipherFinalize(SeosCryptoApi_Context*     api,
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
    if ((retval = SeosCryptoRpcServer_cipherFinalize(self->rpcHandle, cipherHandle,
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