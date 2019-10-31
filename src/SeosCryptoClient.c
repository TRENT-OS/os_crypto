/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoClient.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <sys/user.h>

static const SeosCryptoCtx_Vtable SeosCryptoClient_vtable =
{
    .rngGetBytes          = SeosCryptoClient_rngGetBytes,
    .rngReSeed            = SeosCryptoClient_rngReSeed,
    .digestInit           = SeosCryptoClient_digestInit,
    .digestFree           = SeosCryptoClient_digestFree,
    .digestProcess        = SeosCryptoClient_digestProcess,
    .digestFinalize       = SeosCryptoClient_digestFinalize,
    .keyGenerate          = SeosCryptoClient_keyGenerate,
    .keyMakePublic        = SeosCryptoClient_keyMakePublic,
    .keyImport            = SeosCryptoClient_keyImport,
    .keyExport            = SeosCryptoClient_keyExport,
    .keyGetParams         = SeosCryptoClient_keyGetParams,
    .keyLoadParams        = SeosCryptoClient_keyLoadParams,
    .keyFree              = SeosCryptoClient_keyFree,
    .signatureInit        = SeosCryptoClient_signatureInit,
    .signatureFree        = SeosCryptoClient_signatureFree,
    .signatureSign        = SeosCryptoClient_signatureSign,
    .signatureVerify      = SeosCryptoClient_signatureVerify,
    .agreementInit        = SeosCryptoClient_agreementInit,
    .agreementFree        = SeosCryptoClient_agreementFree,
    .agreementAgree       = SeosCryptoClient_agreementAgree,
    .cipherInit           = SeosCryptoClient_cipherInit,
    .cipherFree           = SeosCryptoClient_cipherFree,
    .cipherProcess        = SeosCryptoClient_cipherProcess,
    .cipherStart          = SeosCryptoClient_cipherStart,
    .cipherFinalize       = SeosCryptoClient_cipherFinalize,
    .free                 = SeosCryptoClient_free
};

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoClient_init(SeosCryptoClient* self,
                      SeosCryptoRpc_Handle rpcHandle,
                      void* dataport)
{
    if (NULL == self || NULL == rpcHandle || NULL == dataport)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->clientDataport = dataport;
    self->rpcHandle      = rpcHandle;
    self->parent.vtable  = &SeosCryptoClient_vtable;

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoClient_free(SeosCryptoCtx* api)
{
    return SEOS_SUCCESS;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoClient_rngGetBytes(SeosCryptoCtx*             api,
                             const SeosCryptoRng_Flags  flags,
                             void*                      buf,
                             const size_t               bufLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || NULL == buf
        || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_rngGetBytes(self->rpcHandle, flags,
                                            bufLen)) == SEOS_SUCCESS)
    {
        if (bufLen > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(buf, self->clientDataport, bufLen);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_rngReSeed(SeosCryptoCtx*   api,
                           const void*      seed,
                           const size_t     seedLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || NULL == seed
        || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (seedLen > SeosCrypto_DATAPORT_SIZE)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, seed, seedLen);
    return SeosCryptoRpc_rngReSeed(self->rpcHandle, seedLen);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoClient_digestInit(SeosCryptoCtx*                      api,
                            SeosCrypto_DigestHandle*            pDigestHandle,
                            const SeosCryptoDigest_Algorithm    algorithm)
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
SeosCryptoClient_digestFree(SeosCryptoCtx*                  api,
                            const SeosCrypto_DigestHandle   digestHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_digestFree(self->rpcHandle, digestHandle);
}

seos_err_t
SeosCryptoClient_digestProcess(SeosCryptoCtx*                   api,
                               const SeosCrypto_DigestHandle    digestHandle,
                               const void*                      data,
                               const size_t                     dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == data || 0 == dataLen)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataLen > SeosCrypto_DATAPORT_SIZE)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, data, dataLen);
    return SeosCryptoRpc_digestProcess(self->rpcHandle, digestHandle, dataLen);
}

seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoCtx*                  api,
                                const SeosCrypto_DigestHandle   digestHandle,
                                void*                           digest,
                                size_t*                         digestSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == digest || NULL == digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_digestFinalize(self->rpcHandle, digestHandle,
                                               digestSize)) == SEOS_SUCCESS)
    {
        if (*digestSize > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(digest, self->clientDataport, *digestSize);
    }

    return retval;
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoClient_signatureInit(SeosCryptoCtx*                       api,
                               SeosCrypto_SignatureHandle*          pSigHandle,
                               const SeosCryptoSignature_Algorithm  algorithm,
                               const SeosCrypto_KeyHandle           prvHandle,
                               const SeosCrypto_KeyHandle           pubHandle)
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
SeosCryptoClient_signatureFree(SeosCryptoCtx*                   api,
                               const SeosCrypto_SignatureHandle sigHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_signatureFree(self->rpcHandle, sigHandle);
}

seos_err_t
SeosCryptoClient_signatureSign(SeosCryptoCtx*                   api,
                               const SeosCrypto_SignatureHandle sigHandle,
                               const void*                      hash,
                               const size_t                     hashSize,
                               void*                            signature,
                               size_t*                          signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == hash || NULL == signature || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > SeosCrypto_DATAPORT_SIZE)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, hash, hashSize);
    if ((retval = SeosCryptoRpc_signatureSign(self->rpcHandle, sigHandle,
                                              hashSize, signatureSize)) == SEOS_SUCCESS)
    {
        if (*signatureSize > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(signature, self->clientDataport, *signatureSize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_signatureVerify(SeosCryptoCtx*                     api,
                                 const SeosCrypto_SignatureHandle   sigHandle,
                                 const void*                        hash,
                                 const size_t                       hashSize,
                                 const void*                        signature,
                                 const size_t                       signatureSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == hash || NULL == signature)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize + signatureSize > SeosCrypto_DATAPORT_SIZE)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, hash, hashSize);
    memcpy(self->clientDataport + hashSize, signature, signatureSize);
    return SeosCryptoRpc_signatureVerify(self->rpcHandle, sigHandle, hashSize,
                                         signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoClient_agreementInit(SeosCryptoCtx*                       api,
                               SeosCrypto_AgreementHandle*          pAgrHandle,
                               const SeosCryptoAgreement_Algorithm  algorithm,
                               const SeosCrypto_KeyHandle           prvHandle)
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
SeosCryptoClient_agreementFree(SeosCryptoCtx*                   api,
                               const SeosCrypto_AgreementHandle agrHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_agreementFree(self->rpcHandle, agrHandle);
}

seos_err_t
SeosCryptoClient_agreementAgree(SeosCryptoCtx*                      api,
                                const SeosCrypto_AgreementHandle    agrHandle,
                                const SeosCrypto_KeyHandle          pubHandle,
                                void*                               shared,
                                size_t*                             sharedSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoClient_vtable
        || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_agreementAgree(self->rpcHandle, agrHandle,
                                               pubHandle, sharedSize)) == SEOS_SUCCESS)
    {
        if (*sharedSize > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(shared, self->clientDataport, *sharedSize);
    }

    return retval;
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoClient_keyGenerate(SeosCryptoCtx*             api,
                             SeosCrypto_KeyHandle*      pKeyHandle,
                             const SeosCryptoKey_Spec*  spec)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || NULL == pKeyHandle || NULL == spec
        || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    Debug_ASSERT(sizeof(SeosCryptoKey_Spec) <= SeosCrypto_DATAPORT_SIZE);
    memcpy(self->clientDataport, spec, sizeof(SeosCryptoKey_Spec));
    return SeosCryptoRpc_keyGenerate(self->rpcHandle, pKeyHandle);
}

seos_err_t
SeosCryptoClient_keyMakePublic(SeosCryptoCtx*               api,
                               SeosCrypto_KeyHandle*        pPubKeyHandle,
                               const SeosCrypto_KeyHandle   prvKeyHandle,
                               const SeosCryptoKey_Attribs* attribs)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || NULL == pPubKeyHandle || NULL == attribs
        || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    Debug_ASSERT(sizeof(SeosCryptoKey_Attribs) <= SeosCrypto_DATAPORT_SIZE);
    memcpy(self->clientDataport, attribs, sizeof(SeosCryptoKey_Attribs));
    return SeosCryptoRpc_keyMakePublic(self->rpcHandle, pPubKeyHandle,
                                       prvKeyHandle);
}

seos_err_t
SeosCryptoClient_keyImport(SeosCryptoCtx*               api,
                           SeosCrypto_KeyHandle*        pKeyHandle,
                           const SeosCrypto_KeyHandle   wrapKeyHandle,
                           const SeosCryptoKey_Data*    keyData)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || NULL == pKeyHandle || NULL == keyData
        || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    Debug_ASSERT(sizeof(SeosCryptoKey_Data) <= SeosCrypto_DATAPORT_SIZE);
    memcpy(self->clientDataport, keyData, sizeof(SeosCryptoKey_Data));
    return SeosCryptoRpc_keyImport(self->rpcHandle, pKeyHandle, wrapKeyHandle);
}

seos_err_t
SeosCryptoClient_keyExport(SeosCryptoCtx*               api,
                           const SeosCrypto_KeyHandle   keyHandle,
                           const SeosCrypto_KeyHandle   wrapKeyHandle,
                           SeosCryptoKey_Data*          keyData)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_keyExport(self->rpcHandle, keyHandle,
                                          wrapKeyHandle)) == SEOS_SUCCESS)
    {
        Debug_ASSERT(sizeof(SeosCryptoKey_Data) <= SeosCrypto_DATAPORT_SIZE);
        memcpy(keyData, self->clientDataport, sizeof(SeosCryptoKey_Data));
    }

    return retval;
}

seos_err_t
SeosCryptoClient_keyGetParams(SeosCryptoCtx*                api,
                              const SeosCrypto_KeyHandle    keyHandle,
                              void*                         keyParams,
                              size_t*                       paramSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_keyGetParams(self->rpcHandle, keyHandle,
                                             paramSize)) == SEOS_SUCCESS)
    {
        if (*paramSize > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(keyParams, self->clientDataport, *paramSize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_keyLoadParams(SeosCryptoCtx*              api,
                               const SeosCryptoKey_Param   name,
                               void*                       keyParams,
                               size_t*                     paramSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = SeosCryptoRpc_keyLoadParams(self->rpcHandle, name,
                                              paramSize)) == SEOS_SUCCESS)
    {
        if (*paramSize > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(keyParams, self->clientDataport, *paramSize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_keyFree(SeosCryptoCtx*             api,
                         const SeosCrypto_KeyHandle keyHandle)
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
SeosCryptoClient_cipherInit(SeosCryptoCtx*                      api,
                            SeosCrypto_CipherHandle*            pCipherHandle,
                            const SeosCryptoCipher_Algorithm    algorithm,
                            const SeosCrypto_KeyHandle          key,
                            const void*                         iv,
                            const size_t                        ivLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == pCipherHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (iv != NULL)
    {
        if (ivLen > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(self->clientDataport, iv, ivLen);
    }

    return SeosCryptoRpc_cipherInit(self->rpcHandle, pCipherHandle, algorithm,
                                    key, ivLen);
}

seos_err_t
SeosCryptoClient_cipherFree(SeosCryptoCtx*                  api,
                            const SeosCrypto_CipherHandle   cipherHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_cipherFree(self->rpcHandle, cipherHandle);
}

seos_err_t
SeosCryptoClient_cipherProcess(SeosCryptoCtx*                   api,
                               const SeosCrypto_CipherHandle    cipherHandle,
                               const void*                      input,
                               const size_t                     inputSize,
                               void*                            output,
                               size_t*                          outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable ||
        NULL == input || NULL == output || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > SeosCrypto_DATAPORT_SIZE)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, input, inputSize);
    if ((retval = SeosCryptoRpc_cipherProcess(self->rpcHandle, cipherHandle,
                                              inputSize, outputSize)) == SEOS_SUCCESS)
    {
        if (*outputSize > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(output, self->clientDataport, *outputSize);
    }

    return retval;
}

seos_err_t
SeosCryptoClient_cipherStart(SeosCryptoCtx*                 api,
                             const SeosCrypto_CipherHandle  cipherHandle,
                             const void*                    data,
                             const size_t                   dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL != data)
    {
        if (dataLen > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(self->clientDataport, data, dataLen);
    }

    return SeosCryptoRpc_cipherStart(self->rpcHandle, cipherHandle, dataLen);
}

seos_err_t
SeosCryptoClient_cipherFinalize(SeosCryptoCtx*                  api,
                                const SeosCrypto_CipherHandle   cipherHandle,
                                void*                           tag,
                                size_t*                         tagSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    if (NULL == self || &SeosCryptoClient_vtable != self->parent.vtable
        || NULL == tag || NULL == tagSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*tagSize > SeosCrypto_DATAPORT_SIZE)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->clientDataport, tag, *tagSize);
    if ((retval = SeosCryptoRpc_cipherFinalize(self->rpcHandle, cipherHandle,
                                               tagSize)) == SEOS_SUCCESS)
    {
        if (*tagSize > SeosCrypto_DATAPORT_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(tag, self->clientDataport, *tagSize);
    }

    return retval;
}