/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)

#include "SeosCryptoRpcServer.h"

#include "SeosCryptoVtable.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <stdlib.h>

// We call a function from a VTABLE; part of this may not be implemented, so we
// want to make sure we only call a function pointer if it is not NULL.
#define CALL_SAFE(w, func, ...)                             \
    (NULL == w) ? SEOS_ERROR_INVALID_PARAMETER :            \
    (NULL == w->vtable->func) ? SEOS_ERROR_NOT_SUPPORTED :  \
    w->vtable->func(w->context, __VA_ARGS__)                \

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpcServer_Rng_getBytes(
    SeosCryptoApi_Ptr api,
    unsigned int      flags,
    size_t            bufSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Rng_getBytes, flags, self->dataPort, bufSize);
}

seos_err_t
SeosCryptoRpcServer_Rng_reseed(
    SeosCryptoApi_Ptr api,
    size_t            seedLen)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Rng_reseed, self->dataPort, seedLen);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcServer_Mac_init(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Mac_Ptr* pMacObj,
    SeosCryptoApi_Mac_Alg  algorithm)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Mac_init, pMacObj, algorithm);
}

seos_err_t
SeosCryptoRpcServer_Mac_free(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macObj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Mac_free, macObj);
}

seos_err_t
SeosCryptoRpcServer_Mac_start(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t                secretSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Mac_start, macObj, self->dataPort, secretSize);
}

seos_err_t
SeosCryptoRpcServer_Mac_process(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t                dataSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Mac_process, macObj, self->dataPort, dataSize);
}

seos_err_t
SeosCryptoRpcServer_Mac_finalize(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t*               macSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    *macSize = (*macSize <= SeosCryptoApi_SIZE_DATAPORT) ? *macSize :
               SeosCryptoApi_SIZE_DATAPORT;
    return CALL_SAFE(self, Mac_finalize, macObj, self->dataPort, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcServer_Digest_init(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_Ptr* pDigestObj,
    SeosCryptoApi_Digest_Alg  algorithm)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Digest_init, pDigestObj, algorithm);
}

seos_err_t
SeosCryptoRpcServer_Digest_free(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digestObj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Digest_free, digestObj);
}

seos_err_t
SeosCryptoRpcServer_Digest_clone(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_Ptr  dstDigHandle,
    SeosCryptoLib_Digest_CPtr srcDigHandle)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Digest_clone, dstDigHandle, srcDigHandle);
}

seos_err_t
SeosCryptoRpcServer_Digest_process(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digestObj,
    size_t                   inLen)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Digest_process, digestObj, self->dataPort, inLen);
}

seos_err_t
SeosCryptoRpcServer_Digest_finalize(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digestObj,
    size_t*                  digestSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    *digestSize = (*digestSize <= SeosCryptoApi_SIZE_DATAPORT) ? *digestSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return CALL_SAFE(self, Digest_finalize, digestObj, self->dataPort, digestSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpcServer_Key_generate(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pKeyObj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Key_generate, pKeyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpcServer_Key_makePublic(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pPubKeyHandle,
    SeosCryptoLib_Key_CPtr prvKeyHandle)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Key_makePublic, pPubKeyHandle, prvKeyHandle,
                     self->dataPort);
}

seos_err_t
SeosCryptoRpcServer_Key_import(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pKeyObj,
    SeosCryptoLib_Key_CPtr wrapKeyObj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Key_import, pKeyObj, wrapKeyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpcServer_Key_export(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyObj,
    SeosCryptoLib_Key_CPtr wrapKeyObj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Key_export, keyObj, wrapKeyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpcServer_Key_getParams(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyObj,
    size_t*                paramSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;
    return CALL_SAFE(self, Key_getParams, keyObj, self->dataPort, paramSize);
}

seos_err_t
SeosCryptoRpcServer_Key_loadParams(
    SeosCryptoApi_Ptr       api,
    SeosCryptoApi_Key_Param name,
    size_t*                 paramSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;
    return CALL_SAFE(self, Key_loadParams, name, self->dataPort, paramSize);
}

seos_err_t
SeosCryptoRpcServer_Key_free(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Key_Ptr keyObj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Key_free, keyObj);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpcServer_Agreement_init(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Agreement_Ptr* pAgrObj,
    SeosCryptoApi_Agreement_Alg  algorithm,
    SeosCryptoLib_Key_CPtr       prvKey)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Agreement_init, pAgrObj, algorithm, prvKey);
}

seos_err_t
SeosCryptoRpcServer_Agreement_agree(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Agreement_Ptr agrObj,
    SeosCryptoLib_Key_CPtr      pubKey,
    size_t*                     sharedSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    *sharedSize = (*sharedSize <= SeosCryptoApi_SIZE_DATAPORT) ? *sharedSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return CALL_SAFE(self, Agreement_agree, agrObj, pubKey, self->dataPort,
                     sharedSize);
}

seos_err_t
SeosCryptoRpcServer_Agreement_free(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Agreement_Ptr agrObj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Agreement_free, agrObj);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpcServer_Signature_init(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Signature_Ptr* pObj,
    SeosCryptoApi_Signature_Alg  algorithm,
    SeosCryptoApi_Digest_Alg     digest,
    SeosCryptoLib_Key_CPtr       prvKey,
    SeosCryptoLib_Key_CPtr       pubKey)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Signature_init, pObj, algorithm, digest, prvKey, pubKey);
}

seos_err_t
SeosCryptoRpcServer_Signature_verify(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr obj,
    size_t                      hashSize,
    size_t                      signatureSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Signature_verify, obj, self->dataPort, hashSize,
                     self->dataPort + hashSize, signatureSize);
}

seos_err_t
SeosCryptoRpcServer_Signature_sign(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr obj,
    size_t                      hashSize,
    size_t*                     signatureSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    *signatureSize = (*signatureSize <= SeosCryptoApi_SIZE_DATAPORT) ?
                     *signatureSize : SeosCryptoApi_SIZE_DATAPORT;
    return CALL_SAFE(self, Signature_sign, obj, self->dataPort,  hashSize,
                     self->dataPort, signatureSize);
}

seos_err_t
SeosCryptoRpcServer_Signature_free(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr obj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Signature_free, obj);
}

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoRpcServer_Cipher_init(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Cipher_Ptr* pCipherObj,
    SeosCryptoApi_Cipher_Alg  algorithm,
    SeosCryptoLib_Key_CPtr    key,
    size_t                    ivLen)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Cipher_init, pCipherObj, algorithm, key, self->dataPort,
                     ivLen);
}

seos_err_t
SeosCryptoRpcServer_Cipher_free(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherObj)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Cipher_free, cipherObj);
}

seos_err_t
SeosCryptoRpcServer_Cipher_process(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t                   inputLen,
    size_t*                  outputSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    *outputSize = (*outputSize <= SeosCryptoApi_SIZE_DATAPORT) ? *outputSize :
                  SeosCryptoApi_SIZE_DATAPORT;
    return CALL_SAFE(self, Cipher_process, cipherObj, self->dataPort, inputLen,
                     self->dataPort, outputSize);
}

seos_err_t
SeosCryptoRpcServer_Cipher_start(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t                   len)
{
    SeosCryptoRpcServer* self = api->server.context;
    return CALL_SAFE(self, Cipher_start, cipherObj, self->dataPort, len);
}

seos_err_t
SeosCryptoRpcServer_Cipher_finalize(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t*                  tagSize)
{
    SeosCryptoRpcServer* self = api->server.context;
    *tagSize = (*tagSize <= SeosCryptoApi_SIZE_DATAPORT) ? *tagSize :
               SeosCryptoApi_SIZE_DATAPORT;
    return CALL_SAFE(self, Cipher_finalize, cipherObj, self->dataPort, tagSize);
}

// ------------------------------- init/free -----------------------------------

seos_err_t
SeosCryptoRpcServer_init(
    SeosCryptoRpcServer*                  self,
    const SeosCryptoApi_Impl*             impl,
    const SeosCryptoApi_RpcServer_Config* cfg)
{
    if (NULL == self || NULL == impl || NULL == cfg || NULL == cfg->dataPort)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->dataPort = cfg->dataPort;
    self->vtable   = impl->vtable;
    self->context  = impl->context;

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoRpcServer_free(
    SeosCryptoRpcServer* self)
{
    return SEOS_SUCCESS;
}

#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */