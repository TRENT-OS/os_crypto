/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)

#include "SeosCryptoRpc_Server.h"

#include "SeosCryptoVtable.h"

#include <string.h>
#include <stdlib.h>

/*
 * The usual procedure to do RPC communication is for the client to tell the
 * server the address where an initilized API RPC-server context is found.
 * However, in the context of the CryptoServer we would like to avoid that,
 * so that an attacker cannot access the API contexts of other clients by
 * trying out other addresses.
 *
 * To protect against such an attack, we instead use a callback to ask the host
 * component of the Crypto RPC server (i.e., the CryptoServer) to look up the
 * correct context, ignoring any addresses given by the client. The CryptoServer
 * keeps track of all contexts and knows how to map them based on the sender ID
 * passed when using a CAMKES interface.
 */
extern SeosCryptoApi*
SeosCryptoRpc_Server_getSeosCryptoApi(
    void) __attribute__((weak));

// Get the SeosCryptoRpc_Server pointer from the API pointer and make sure it is
// actually non-NULL. Please note that here the API pointer (passed by the RpcClient)
// is overwritten, whenever SeosCryptoRpc_Server_getSeosCryptoApi() is defined!!
#define GET_SELF(s, a) {                                        \
        if (NULL != SeosCryptoRpc_Server_getSeosCryptoApi) {    \
            a = SeosCryptoRpc_Server_getSeosCryptoApi();        \
        }                                                       \
        if(NULL != a) {                                         \
            s = ((SeosCryptoRpc_Server*) a->server.context);    \
        } else {                                                \
            return SEOS_ERROR_INVALID_PARAMETER;                \
        }                                                       \
}

// Call function pointer to LIB, make sure it is defined
#define CALL(s, f, ...)                         \
    (NULL == s->vtable->f) ?                    \
        SEOS_ERROR_NOT_SUPPORTED :              \
        s->vtable->f(s->context, __VA_ARGS__)

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpc_Server_Rng_getBytes(
    SeosCryptoApi_Ptr api,
    unsigned int      flags,
    size_t            bufSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Rng_getBytes, flags, self->dataPort, bufSize);
}

seos_err_t
SeosCryptoRpc_Server_Rng_reseed(
    SeosCryptoApi_Ptr api,
    size_t            seedSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Rng_reseed, self->dataPort, seedSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpc_Server_Mac_init(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Mac_Ptr* pMacObj,
    SeosCryptoApi_Mac_Alg  algorithm)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Mac_init, pMacObj, algorithm);
}

seos_err_t
SeosCryptoRpc_Server_Mac_exists(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Mac_CPtr macObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Mac_exists, macObj);
}

seos_err_t
SeosCryptoRpc_Server_Mac_free(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Mac_free, macObj);
}

seos_err_t
SeosCryptoRpc_Server_Mac_start(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t                secretSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Mac_start, macObj, self->dataPort, secretSize);
}

seos_err_t
SeosCryptoRpc_Server_Mac_process(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t                dataSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Mac_process, macObj, self->dataPort, dataSize);
}

seos_err_t
SeosCryptoRpc_Server_Mac_finalize(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macObj,
    size_t*               macSize)
{
    SeosCryptoRpc_Server* self;

    *macSize = (*macSize <= SeosCryptoApi_SIZE_DATAPORT) ? *macSize :
               SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self, api);
    return CALL(self, Mac_finalize, macObj, self->dataPort, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpc_Server_Digest_init(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_Ptr* pDigestObj,
    SeosCryptoApi_Digest_Alg  algorithm)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Digest_init, pDigestObj, algorithm);
}

seos_err_t
SeosCryptoRpc_Server_Digest_exists(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_CPtr digestObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Digest_exists, digestObj);
}

seos_err_t
SeosCryptoRpc_Server_Digest_free(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digestObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Digest_free, digestObj);
}

seos_err_t
SeosCryptoRpc_Server_Digest_clone(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_Ptr  dstDigHandle,
    SeosCryptoLib_Digest_CPtr srcDigHandle)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Digest_clone, dstDigHandle, srcDigHandle);
}

seos_err_t
SeosCryptoRpc_Server_Digest_process(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digestObj,
    size_t                   inSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Digest_process, digestObj, self->dataPort, inSize);
}

seos_err_t
SeosCryptoRpc_Server_Digest_finalize(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digestObj,
    size_t*                  digestSize)
{
    SeosCryptoRpc_Server* self;

    *digestSize = (*digestSize <= SeosCryptoApi_SIZE_DATAPORT) ? *digestSize :
                  SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self, api);
    return CALL(self, Digest_finalize, digestObj, self->dataPort, digestSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpc_Server_Key_generate(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pKeyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Key_generate, pKeyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_makePublic(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pPubKeyHandle,
    SeosCryptoLib_Key_CPtr prvKeyHandle)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Key_makePublic, pPubKeyHandle, prvKeyHandle, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_import(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pKeyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Key_import, pKeyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_export(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyObj)
{
    seos_err_t err;
    SeosCryptoApi_Key_Attribs attribs;
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);

    /*
     * The 'exportable' attribute of a key is only meaningful with relation to
     * an attempt of sending key material out of the component. For this, the
     * only way is to use this RPC call so this is where this attribute is
     * checked.
     */
    if ((err = CALL(self, Key_getAttribs, keyObj, &attribs)) != SEOS_SUCCESS)
    {
        return err;
    }

    return !attribs.exportable ?
           SEOS_ERROR_OPERATION_DENIED :
           CALL(self, Key_export, keyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_getParams(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyObj,
    size_t*                paramSize)
{
    SeosCryptoRpc_Server* self;

    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self, api);
    return CALL(self, Key_getParams, keyObj, self->dataPort, paramSize);
}

seos_err_t
SeosCryptoRpc_Server_Key_getAttribs(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Key_getAttribs, keyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_loadParams(
    SeosCryptoApi_Ptr       api,
    SeosCryptoApi_Key_Param name,
    size_t*                 paramSize)
{
    SeosCryptoRpc_Server* self;

    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self, api);
    return CALL(self, Key_loadParams, name, self->dataPort, paramSize);
}

seos_err_t
SeosCryptoRpc_Server_Key_exists(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Key_exists, keyObj);
}

seos_err_t
SeosCryptoRpc_Server_Key_free(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Key_Ptr keyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Key_free, keyObj);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpc_Server_Agreement_init(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Agreement_Ptr* pAgrObj,
    SeosCryptoApi_Agreement_Alg  algorithm,
    SeosCryptoLib_Key_CPtr       prvKey)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Agreement_init, pAgrObj, algorithm, prvKey);
}

seos_err_t
SeosCryptoRpc_Server_Agreement_agree(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Agreement_Ptr agrObj,
    SeosCryptoLib_Key_CPtr      pubKey,
    size_t*                     sharedSize)
{
    SeosCryptoRpc_Server* self;

    *sharedSize = (*sharedSize <= SeosCryptoApi_SIZE_DATAPORT) ? *sharedSize :
                  SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self, api);
    return CALL(self, Agreement_agree, agrObj, pubKey, self->dataPort, sharedSize);
}

seos_err_t
SeosCryptoRpc_Server_Agreement_exists(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Agreement_CPtr agrObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Agreement_exists, agrObj);
}

seos_err_t
SeosCryptoRpc_Server_Agreement_free(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Agreement_Ptr agrObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Agreement_free, agrObj);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpc_Server_Signature_init(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Signature_Ptr* pObj,
    SeosCryptoApi_Signature_Alg  algorithm,
    SeosCryptoApi_Digest_Alg     digest,
    SeosCryptoLib_Key_CPtr       prvKey,
    SeosCryptoLib_Key_CPtr       pubKey)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Signature_init, pObj, algorithm, digest, prvKey, pubKey);
}

seos_err_t
SeosCryptoRpc_Server_Signature_verify(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr obj,
    size_t                      hashSize,
    size_t                      signatureSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Signature_verify, obj, self->dataPort, hashSize,
                self->dataPort + hashSize, signatureSize);
}

seos_err_t
SeosCryptoRpc_Server_Signature_sign(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr obj,
    size_t                      hashSize,
    size_t*                     signatureSize)
{
    SeosCryptoRpc_Server* self;

    *signatureSize = (*signatureSize <= SeosCryptoApi_SIZE_DATAPORT) ?
                     *signatureSize : SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self, api);
    return CALL(self, Signature_sign, obj, self->dataPort,  hashSize,
                self->dataPort, signatureSize);
}

seos_err_t
SeosCryptoRpc_Server_Signature_exists(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Signature_CPtr obj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Signature_exists, obj);
}

seos_err_t
SeosCryptoRpc_Server_Signature_free(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr obj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Signature_free, obj);
}

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoRpc_Server_Cipher_init(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Cipher_Ptr* pCipherObj,
    SeosCryptoApi_Cipher_Alg  algorithm,
    SeosCryptoLib_Key_CPtr    key,
    size_t                    ivSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Cipher_init, pCipherObj, algorithm, key, self->dataPort,
                ivSize);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_exists(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Cipher_CPtr cipherObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Cipher_exists, cipherObj);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_free(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Cipher_free, cipherObj);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_process(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t                   inputSize,
    size_t*                  outputSize)
{
    SeosCryptoRpc_Server* self;

    *outputSize = (*outputSize <= SeosCryptoApi_SIZE_DATAPORT) ? *outputSize :
                  SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self, api);
    return CALL(self, Cipher_process, cipherObj, self->dataPort, inputSize,
                self->dataPort, outputSize);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_start(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t                   len)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self, api);
    return CALL(self, Cipher_start, cipherObj, self->dataPort, len);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_finalize(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t*                  tagSize)
{
    SeosCryptoRpc_Server* self;

    *tagSize = (*tagSize <= SeosCryptoApi_SIZE_DATAPORT) ? *tagSize :
               SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self, api);
    return CALL(self, Cipher_finalize, cipherObj, self->dataPort, tagSize);
}

// ------------------------------- init/free -----------------------------------

seos_err_t
SeosCryptoRpc_Server_init(
    SeosCryptoRpc_Server*                 self,
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
SeosCryptoRpc_Server_free(
    SeosCryptoRpc_Server* self)
{
    return SEOS_SUCCESS;
}

#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */