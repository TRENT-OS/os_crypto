/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(OS_CRYPTO_WITH_RPC_SERVER)

#include "OS_Crypto.h"

#include "rpc/CryptoLibServer.h"

#include <string.h>
#include <stdlib.h>

// -------------------------- defines/types/variables --------------------------

/*
 * Host of OS Crypto API RPC server has to provide an implementation's RPC
 * context. This way, it is up to the host (e.g., the CryptoServer) to implement
 * its own way of handling multiple clients and their respective contextx.
 */
extern OS_Crypto_Handle_t
crypto_rpc_getCrypto(
    void);

// This is not exposed via header intentionally
void*
OS_Crypto_getServer(
    const OS_Crypto_Handle_t self);

// Get Crypto API context host of Crypto API in RPC_SERVER mode
#define GET_SELF(s) {                                   \
    OS_Crypto_t *a;                                     \
    if (((a = crypto_rpc_getCrypto()) == NULL) ||       \
        ((s = OS_Crypto_getServer(a)) == NULL) )        \
    {                                                   \
        return OS_ERROR_INVALID_PARAMETER;              \
    }                                                   \
}

// Call function pointer to LIB, make sure it is defined
#define CALL(s, f, ...)                                 \
    (NULL == s->impl.vtable->f) ?                       \
        OS_ERROR_NOT_SUPPORTED :                        \
        s->impl.vtable->f(s->impl.context, __VA_ARGS__)

struct CryptoLibServer
{
    /**
     * The server's address of the dataport shared with the client
     */
    OS_Dataport_t dataport;
    /**
     * Context and function pointers of implementation
     */
    Crypto_Impl_t impl;
    OS_Crypto_Memory_t memory;
};

// -------------------------------- RNG API ------------------------------------

OS_Error_t
crypto_rpc_Rng_getBytes(
    unsigned int flags,
    size_t       bufSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Rng_getBytes, flags, OS_Dataport_getBuf(self->dataport),
                bufSize);
}

OS_Error_t
crypto_rpc_Rng_reseed(
    size_t seedSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Rng_reseed, OS_Dataport_getBuf(self->dataport), seedSize);
}

// ------------------------------- MAC API -------------------------------------

OS_Error_t
crypto_rpc_Mac_init(
    CryptoLibMac_ptr*  pMacObj,
    CryptoLibKey_cptr  keyObj,
    OS_CryptoMac_Alg_t algorithm)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_init, pMacObj, keyObj, algorithm);
}

OS_Error_t
crypto_rpc_Mac_free(
    CryptoLibMac_ptr macObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_free, macObj);
}

OS_Error_t
crypto_rpc_Mac_process(
    CryptoLibMac_ptr macObj,
    size_t           dataSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_process, macObj, OS_Dataport_getBuf(self->dataport),
                dataSize);
}

OS_Error_t
crypto_rpc_Mac_finalize(
    CryptoLibMac_ptr macObj,
    size_t*          macSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    *macSize = (*macSize <= OS_Dataport_getSize(self->dataport)) ?
               *macSize : OS_Dataport_getSize(self->dataport);
    return CALL(self, Mac_finalize, macObj, OS_Dataport_getBuf(self->dataport),
                macSize);
}

// ------------------------------ Digest API -----------------------------------

OS_Error_t
crypto_rpc_Digest_init(
    CryptoLibDigest_ptr*  pDigestObj,
    OS_CryptoDigest_Alg_t algorithm)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_init, pDigestObj, algorithm);
}

OS_Error_t
crypto_rpc_Digest_free(
    CryptoLibDigest_ptr digestObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_free, digestObj);
}

OS_Error_t
crypto_rpc_Digest_clone(
    CryptoLibDigest_ptr* pDigestObj,
    CryptoLibDigest_cptr srcDigestObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_clone, pDigestObj, srcDigestObj);
}

OS_Error_t
crypto_rpc_Digest_process(
    CryptoLibDigest_ptr digestObj,
    size_t              inSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_process, digestObj,
                OS_Dataport_getBuf(self->dataport), inSize);
}

OS_Error_t
crypto_rpc_Digest_finalize(
    CryptoLibDigest_ptr digestObj,
    size_t*             digestSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    *digestSize = (*digestSize <= OS_Dataport_getSize(self->dataport)) ?
                  *digestSize : OS_Dataport_getSize(self->dataport);
    return CALL(self, Digest_finalize, digestObj,
                OS_Dataport_getBuf(self->dataport), digestSize);
}

// -------------------------------- Key API ------------------------------------

OS_Error_t
crypto_rpc_Key_generate(
    CryptoLibKey_ptr* pKeyObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_generate, pKeyObj, OS_Dataport_getBuf(self->dataport));
}

OS_Error_t
crypto_rpc_Key_makePublic(
    CryptoLibKey_ptr* pPubKeyHandle,
    CryptoLibKey_cptr prvKeyHandle)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_makePublic, pPubKeyHandle, prvKeyHandle,
                OS_Dataport_getBuf(self->dataport));
}

OS_Error_t
crypto_rpc_Key_import(
    CryptoLibKey_ptr* pKeyObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_import, pKeyObj, OS_Dataport_getBuf(self->dataport));
}

OS_Error_t
crypto_rpc_Key_export(
    CryptoLibKey_cptr keyObj)
{
    OS_Error_t err;
    OS_CryptoKey_Attrib_t attribs;
    CryptoLibServer_t* self;

    GET_SELF(self);

    /*
     * The 'exportable' attribute of a key is only meaningful with relation to
     * an attempt of sending key material out of the component. For this, the
     * only way is to use this RPC call so this is where this attribute is
     * checked.
     */
    if ((err = CALL(self, Key_getAttribs, keyObj, &attribs)) != OS_SUCCESS)
    {
        return err;
    }

    return !attribs.exportable ?
           OS_ERROR_OPERATION_DENIED :
           CALL(self, Key_export, keyObj, OS_Dataport_getBuf(self->dataport));
}

OS_Error_t
crypto_rpc_Key_getParams(
    CryptoLibKey_cptr keyObj,
    size_t*           paramSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    *paramSize = (*paramSize <= OS_Dataport_getSize(self->dataport)) ?
                 *paramSize : OS_Dataport_getSize(self->dataport);
    return CALL(self, Key_getParams, keyObj, OS_Dataport_getBuf(self->dataport),
                paramSize);
}

OS_Error_t
crypto_rpc_Key_getAttribs(
    CryptoLibKey_cptr keyObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_getAttribs, keyObj, OS_Dataport_getBuf(self->dataport));
}

OS_Error_t
crypto_rpc_Key_loadParams(
    OS_CryptoKey_Param_t name,
    size_t*              paramSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    *paramSize = (*paramSize <= OS_Dataport_getSize(self->dataport)) ?
                 *paramSize : OS_Dataport_getSize(self->dataport);
    return CALL(self, Key_loadParams, name, OS_Dataport_getBuf(self->dataport),
                paramSize);
}

OS_Error_t
crypto_rpc_Key_free(
    CryptoLibKey_ptr keyObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_free, keyObj);
}

// ----------------------------- Agreement API ---------------------------------

OS_Error_t
crypto_rpc_Agreement_init(
    CryptoLibAgreement_ptr*  pAgrObj,
    CryptoLibKey_cptr        prvKey,
    OS_CryptoAgreement_Alg_t algorithm)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Agreement_init, pAgrObj, prvKey, algorithm);
}

OS_Error_t
crypto_rpc_Agreement_agree(
    CryptoLibAgreement_ptr agrObj,
    CryptoLibKey_cptr      pubKey,
    size_t*                sharedSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    *sharedSize = (*sharedSize <= OS_Dataport_getSize(self->dataport)) ?
                  *sharedSize : OS_Dataport_getSize(self->dataport);
    return CALL(self, Agreement_agree, agrObj, pubKey,
                OS_Dataport_getBuf(self->dataport), sharedSize);
}

OS_Error_t
crypto_rpc_Agreement_free(
    CryptoLibAgreement_ptr agrObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Agreement_free, agrObj);
}

// ----------------------------- Signature API ---------------------------------

OS_Error_t
crypto_rpc_Signature_init(
    CryptoLibSignature_ptr*  pObj,
    CryptoLibKey_cptr        prvKey,
    CryptoLibKey_cptr        pubKey,
    OS_CryptoSignature_Alg_t algorithm,
    OS_CryptoDigest_Alg_t    digest)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_init, pObj, prvKey, pubKey, algorithm, digest);
}

OS_Error_t
crypto_rpc_Signature_verify(
    CryptoLibSignature_ptr obj,
    size_t                 hashSize,
    size_t                 signatureSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_verify, obj, OS_Dataport_getBuf(self->dataport),
                hashSize, OS_Dataport_getBuf(self->dataport) + hashSize, signatureSize);
}

OS_Error_t
crypto_rpc_Signature_sign(
    CryptoLibSignature_ptr obj,
    size_t                 hashSize,
    size_t*                signatureSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    *signatureSize = (*signatureSize <= OS_Dataport_getSize(self->dataport)) ?
                     *signatureSize : OS_Dataport_getSize(self->dataport);
    return CALL(self, Signature_sign, obj, OS_Dataport_getBuf(self->dataport),
                hashSize, OS_Dataport_getBuf(self->dataport), signatureSize);
}

OS_Error_t
crypto_rpc_Signature_free(
    CryptoLibSignature_ptr obj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_free, obj);
}

// ------------------------------- Cipher API ----------------------------------

OS_Error_t
crypto_rpc_Cipher_init(
    CryptoLibCipher_ptr*  pCipherObj,
    CryptoLibKey_cptr     key,
    OS_CryptoCipher_Alg_t algorithm,
    size_t                ivSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_init, pCipherObj, key, algorithm,
                OS_Dataport_getBuf(self->dataport), ivSize);
}

OS_Error_t
crypto_rpc_Cipher_free(
    CryptoLibCipher_ptr cipherObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_free, cipherObj);
}

OS_Error_t
crypto_rpc_Cipher_process(
    CryptoLibCipher_ptr cipherObj,
    size_t              inputSize,
    size_t*             outputSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    *outputSize = (*outputSize <= OS_Dataport_getSize(self->dataport)) ?
                  *outputSize : OS_Dataport_getSize(self->dataport);
    return CALL(self, Cipher_process, cipherObj,
                OS_Dataport_getBuf(self->dataport), inputSize,
                OS_Dataport_getBuf(self->dataport), outputSize);
}

OS_Error_t
crypto_rpc_Cipher_start(
    CryptoLibCipher_ptr cipherObj,
    size_t              len)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_start, cipherObj, OS_Dataport_getBuf(self->dataport),
                len);
}

OS_Error_t
crypto_rpc_Cipher_finalize(
    CryptoLibCipher_ptr cipherObj,
    size_t*             tagSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    *tagSize = (*tagSize <= OS_Dataport_getSize(self->dataport)) ?
               *tagSize : OS_Dataport_getSize(self->dataport);
    return CALL(self, Cipher_finalize, cipherObj,
                OS_Dataport_getBuf(self->dataport), tagSize);
}

// ------------------------------- init/free -----------------------------------

OS_Error_t
CryptoLibServer_init(
    CryptoLibServer_t**       ctx,
    const Crypto_Impl_t*      impl,
    const OS_Crypto_Memory_t* memory,
    const OS_Dataport_t*      dataport)
{
    CryptoLibServer_t* svr;

    if (NULL == ctx || NULL == impl || NULL == memory || NULL == dataport
        || OS_Dataport_isUnset(*dataport))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = memory->calloc(1, sizeof(CryptoLibServer_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    *ctx = svr;

    svr->dataport = *dataport;
    svr->memory   = *memory;
    svr->impl     = *impl;

    return OS_SUCCESS;
}

OS_Error_t
CryptoLibServer_free(
    CryptoLibServer_t* self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    self->memory.free(self);

    return OS_SUCCESS;
}

#endif /* OS_CRYPTO_WITH_RPC_SERVER */