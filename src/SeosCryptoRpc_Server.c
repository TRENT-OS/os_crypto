/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)

#include "SeosCryptoApi.h"

#include "SeosCryptoRpc_Server.h"

#include <string.h>
#include <stdlib.h>

// -------------------------- defines/types/variables --------------------------

/*
 * Host of SEOS Crypto API RPC server has to provide a client's RPC context.
 * This way, it is up to the host (e.g., the CryptoServer) to implement its own
 * way of handling multiple clients and their respective contextx.
 */
extern SeosCryptoApiH
SeosCryptoRpc_Server_getSeosCryptoApi(
    void);

// This is not exposed via header intentionally
void*
SeosCryptoApi_getServer(
    const SeosCryptoApiH self);

// Get SeosTlsRpc_Server context from API
#define GET_SELF(s) {                                               \
    SeosCryptoApi *a;                                               \
    if (((a = SeosCryptoRpc_Server_getSeosCryptoApi()) == NULL) ||  \
        ((s = SeosCryptoApi_getServer(a)) == NULL) )                \
    {                                                               \
        return SEOS_ERROR_INVALID_PARAMETER;                        \
    }                                                               \
}

// Call function pointer to LIB, make sure it is defined
#define CALL(s, f, ...)                                     \
    (NULL == s->client.vtable->f) ?                         \
        SEOS_ERROR_NOT_SUPPORTED :                          \
        s->client.vtable->f(s->client.context, __VA_ARGS__)

struct SeosCryptoRpc_Server
{
    /**
     * The server's address of the dataport shared with the client
     */
    void* dataPort;
    /**
     * Context and function pointers of CLIENT implementation
     */
    SeosCryptoImpl client;
    SeosCryptoApi_MemIf memIf;
};

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpc_Server_Rng_getBytes(
    unsigned int flags,
    size_t       bufSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Rng_getBytes, flags, self->dataPort, bufSize);
}

seos_err_t
SeosCryptoRpc_Server_Rng_reseed(
    size_t seedSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Rng_reseed, self->dataPort, seedSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpc_Server_Mac_init(
    SeosCryptoLib_Mac_Ptr* pMacObj,
    SeosCryptoApi_Mac_Alg  algorithm)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Mac_init, pMacObj, algorithm);
}

seos_err_t
SeosCryptoRpc_Server_Mac_exists(
    SeosCryptoLib_Mac_CPtr macObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Mac_exists, macObj);
}

seos_err_t
SeosCryptoRpc_Server_Mac_free(
    SeosCryptoLib_Mac_Ptr macObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Mac_free, macObj);
}

seos_err_t
SeosCryptoRpc_Server_Mac_start(
    SeosCryptoLib_Mac_Ptr macObj,
    size_t                secretSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Mac_start, macObj, self->dataPort, secretSize);
}

seos_err_t
SeosCryptoRpc_Server_Mac_process(
    SeosCryptoLib_Mac_Ptr macObj,
    size_t                dataSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Mac_process, macObj, self->dataPort, dataSize);
}

seos_err_t
SeosCryptoRpc_Server_Mac_finalize(
    SeosCryptoLib_Mac_Ptr macObj,
    size_t*               macSize)
{
    SeosCryptoRpc_Server* self;

    *macSize = (*macSize <= SeosCryptoApi_SIZE_DATAPORT) ? *macSize :
               SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Mac_finalize, macObj, self->dataPort, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpc_Server_Digest_init(
    SeosCryptoLib_Digest_Ptr* pDigestObj,
    SeosCryptoApi_Digest_Alg  algorithm)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Digest_init, pDigestObj, algorithm);
}

seos_err_t
SeosCryptoRpc_Server_Digest_exists(
    SeosCryptoLib_Digest_CPtr digestObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Digest_exists, digestObj);
}

seos_err_t
SeosCryptoRpc_Server_Digest_free(
    SeosCryptoLib_Digest_Ptr digestObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Digest_free, digestObj);
}

seos_err_t
SeosCryptoRpc_Server_Digest_clone(
    SeosCryptoLib_Digest_Ptr  dstDigHandle,
    SeosCryptoLib_Digest_CPtr srcDigHandle)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Digest_clone, dstDigHandle, srcDigHandle);
}

seos_err_t
SeosCryptoRpc_Server_Digest_process(
    SeosCryptoLib_Digest_Ptr digestObj,
    size_t                   inSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Digest_process, digestObj, self->dataPort, inSize);
}

seos_err_t
SeosCryptoRpc_Server_Digest_finalize(
    SeosCryptoLib_Digest_Ptr digestObj,
    size_t*                  digestSize)
{
    SeosCryptoRpc_Server* self;

    *digestSize = (*digestSize <= SeosCryptoApi_SIZE_DATAPORT) ? *digestSize :
                  SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Digest_finalize, digestObj, self->dataPort, digestSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpc_Server_Key_generate(
    SeosCryptoLib_Key_Ptr* pKeyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Key_generate, pKeyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_makePublic(
    SeosCryptoLib_Key_Ptr* pPubKeyHandle,
    SeosCryptoLib_Key_CPtr prvKeyHandle)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Key_makePublic, pPubKeyHandle, prvKeyHandle, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_import(
    SeosCryptoLib_Key_Ptr* pKeyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Key_import, pKeyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_export(
    SeosCryptoLib_Key_CPtr keyObj)
{
    seos_err_t err;
    SeosCryptoApi_Key_Attribs attribs;
    SeosCryptoRpc_Server* self;

    GET_SELF(self);

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
    SeosCryptoLib_Key_CPtr keyObj,
    size_t*                paramSize)
{
    SeosCryptoRpc_Server* self;

    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Key_getParams, keyObj, self->dataPort, paramSize);
}

seos_err_t
SeosCryptoRpc_Server_Key_getAttribs(
    SeosCryptoLib_Key_CPtr keyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Key_getAttribs, keyObj, self->dataPort);
}

seos_err_t
SeosCryptoRpc_Server_Key_loadParams(
    SeosCryptoApi_Key_Param name,
    size_t*                 paramSize)
{
    SeosCryptoRpc_Server* self;

    *paramSize = (*paramSize <= SeosCryptoApi_SIZE_DATAPORT) ? *paramSize :
                 SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Key_loadParams, name, self->dataPort, paramSize);
}

seos_err_t
SeosCryptoRpc_Server_Key_exists(
    SeosCryptoLib_Key_CPtr keyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Key_exists, keyObj);
}

seos_err_t
SeosCryptoRpc_Server_Key_free(
    SeosCryptoLib_Key_Ptr keyObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Key_free, keyObj);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpc_Server_Agreement_init(
    SeosCryptoLib_Agreement_Ptr* pAgrObj,
    SeosCryptoApi_Agreement_Alg  algorithm,
    SeosCryptoLib_Key_CPtr       prvKey)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Agreement_init, pAgrObj, algorithm, prvKey);
}

seos_err_t
SeosCryptoRpc_Server_Agreement_agree(
    SeosCryptoLib_Agreement_Ptr agrObj,
    SeosCryptoLib_Key_CPtr      pubKey,
    size_t*                     sharedSize)
{
    SeosCryptoRpc_Server* self;

    *sharedSize = (*sharedSize <= SeosCryptoApi_SIZE_DATAPORT) ? *sharedSize :
                  SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Agreement_agree, agrObj, pubKey, self->dataPort, sharedSize);
}

seos_err_t
SeosCryptoRpc_Server_Agreement_exists(
    SeosCryptoLib_Agreement_CPtr agrObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Agreement_exists, agrObj);
}

seos_err_t
SeosCryptoRpc_Server_Agreement_free(
    SeosCryptoLib_Agreement_Ptr agrObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Agreement_free, agrObj);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpc_Server_Signature_init(
    SeosCryptoLib_Signature_Ptr* pObj,
    SeosCryptoApi_Signature_Alg  algorithm,
    SeosCryptoApi_Digest_Alg     digest,
    SeosCryptoLib_Key_CPtr       prvKey,
    SeosCryptoLib_Key_CPtr       pubKey)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Signature_init, pObj, algorithm, digest, prvKey, pubKey);
}

seos_err_t
SeosCryptoRpc_Server_Signature_verify(
    SeosCryptoLib_Signature_Ptr obj,
    size_t                      hashSize,
    size_t                      signatureSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Signature_verify, obj, self->dataPort, hashSize,
                self->dataPort + hashSize, signatureSize);
}

seos_err_t
SeosCryptoRpc_Server_Signature_sign(
    SeosCryptoLib_Signature_Ptr obj,
    size_t                      hashSize,
    size_t*                     signatureSize)
{
    SeosCryptoRpc_Server* self;

    *signatureSize = (*signatureSize <= SeosCryptoApi_SIZE_DATAPORT) ?
                     *signatureSize : SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Signature_sign, obj, self->dataPort,  hashSize,
                self->dataPort, signatureSize);
}

seos_err_t
SeosCryptoRpc_Server_Signature_exists(
    SeosCryptoLib_Signature_CPtr obj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Signature_exists, obj);
}

seos_err_t
SeosCryptoRpc_Server_Signature_free(
    SeosCryptoLib_Signature_Ptr obj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Signature_free, obj);
}

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoRpc_Server_Cipher_init(
    SeosCryptoLib_Cipher_Ptr* pCipherObj,
    SeosCryptoApi_Cipher_Alg  algorithm,
    SeosCryptoLib_Key_CPtr    key,
    size_t                    ivSize)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Cipher_init, pCipherObj, algorithm, key, self->dataPort,
                ivSize);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_exists(
    SeosCryptoLib_Cipher_CPtr cipherObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Cipher_exists, cipherObj);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_free(
    SeosCryptoLib_Cipher_Ptr cipherObj)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Cipher_free, cipherObj);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_process(
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t                   inputSize,
    size_t*                  outputSize)
{
    SeosCryptoRpc_Server* self;

    *outputSize = (*outputSize <= SeosCryptoApi_SIZE_DATAPORT) ? *outputSize :
                  SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Cipher_process, cipherObj, self->dataPort, inputSize,
                self->dataPort, outputSize);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_start(
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t                   len)
{
    SeosCryptoRpc_Server* self;

    GET_SELF(self);
    return CALL(self, Cipher_start, cipherObj, self->dataPort, len);
}

seos_err_t
SeosCryptoRpc_Server_Cipher_finalize(
    SeosCryptoLib_Cipher_Ptr cipherObj,
    size_t*                  tagSize)
{
    SeosCryptoRpc_Server* self;

    *tagSize = (*tagSize <= SeosCryptoApi_SIZE_DATAPORT) ? *tagSize :
               SeosCryptoApi_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Cipher_finalize, cipherObj, self->dataPort, tagSize);
}

// ------------------------------- init/free -----------------------------------

seos_err_t
SeosCryptoRpc_Server_init(
    SeosCryptoRpc_Server**            ctx,
    const SeosCryptoImpl*             client,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoRpcServer_Config* cfg)
{
    SeosCryptoRpc_Server* svr;

    if (NULL == ctx || NULL == client || NULL == memIf || NULL == cfg
        || NULL == cfg->dataPort)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = memIf->malloc(sizeof(SeosCryptoRpc_Server))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *ctx = svr;

    svr->dataPort = cfg->dataPort;
    svr->memIf    = *memIf;
    svr->client   = *client;

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoRpc_Server_free(
    SeosCryptoRpc_Server* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    self->memIf.free(self);

    return SEOS_SUCCESS;
}

#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */