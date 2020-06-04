/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(OS_CRYPTO_WITH_RPC_SERVER)

#include "OS_Crypto.h"

#include "rpc/CryptoLibServer.h"

#include <string.h>
#include <stdlib.h>

// -------------------------- defines/types/variables --------------------------

/*
 * Host of OS Crypto API RPC server has to provide a client's RPC context.
 * This way, it is up to the host (e.g., the CryptoServer) to implement its own
 * way of handling multiple clients and their respective contextx.
 */
extern OS_Crypto_Handle_t
CryptoLibServer_getCrypto(
    void);

// This is not exposed via header intentionally
void*
OS_Crypto_getServer(
    const OS_Crypto_Handle_t self);

// Get Crypto API context host of Crypto API in RPC_SERVER mode
#define GET_SELF(s) {                                   \
    OS_Crypto_t *a;                                     \
    if (((a = CryptoLibServer_getCrypto()) == NULL) ||  \
        ((s = OS_Crypto_getServer(a)) == NULL) )        \
    {                                                   \
        return OS_ERROR_INVALID_PARAMETER;            \
    }                                                   \
}

// Call function pointer to LIB, make sure it is defined
#define CALL(s, f, ...)                                 \
    (NULL == s->client.vtable->f) ?                     \
    OS_ERROR_NOT_SUPPORTED :                          \
    s->client.vtable->f(s->client.context, __VA_ARGS__)

struct CryptoLibServer
{
    /**
     * The server's address of the dataport shared with the client
     */
    void* dataPort;
    /**
     * Context and function pointers of CLIENT implementation
     */
    Crypto_Impl_t client;
    OS_Crypto_Memory_t memory;
};

// -------------------------------- RNG API ------------------------------------

OS_Error_t
CryptoLibServer_Rng_getBytes(
    unsigned int flags,
    size_t       bufSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Rng_getBytes, flags, self->dataPort, bufSize);
}

OS_Error_t
CryptoLibServer_Rng_reseed(
    size_t seedSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Rng_reseed, self->dataPort, seedSize);
}

// ------------------------------- MAC API -------------------------------------

OS_Error_t
CryptoLibServer_Mac_init(
    CryptoLibMac_ptr*  pMacObj,
    OS_CryptoMac_Alg_t algorithm)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_init, pMacObj, algorithm);
}

OS_Error_t
CryptoLibServer_Mac_free(
    CryptoLibMac_ptr macObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_free, macObj);
}

OS_Error_t
CryptoLibServer_Mac_start(
    CryptoLibMac_ptr macObj,
    size_t           secretSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_start, macObj, self->dataPort, secretSize);
}

OS_Error_t
CryptoLibServer_Mac_process(
    CryptoLibMac_ptr macObj,
    size_t           dataSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_process, macObj, self->dataPort, dataSize);
}

OS_Error_t
CryptoLibServer_Mac_finalize(
    CryptoLibMac_ptr macObj,
    size_t*          macSize)
{
    CryptoLibServer_t* self;

    *macSize = (*macSize <= OS_Crypto_SIZE_DATAPORT) ? *macSize :
               OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Mac_finalize, macObj, self->dataPort, macSize);
}

// ------------------------------ Digest API -----------------------------------

OS_Error_t
CryptoLibServer_Digest_init(
    CryptoLibDigest_ptr*  pDigestObj,
    OS_CryptoDigest_Alg_t algorithm)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_init, pDigestObj, algorithm);
}

OS_Error_t
CryptoLibServer_Digest_free(
    CryptoLibDigest_ptr digestObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_free, digestObj);
}

OS_Error_t
CryptoLibServer_Digest_clone(
    CryptoLibDigest_ptr* pDigestObj,
    CryptoLibDigest_cptr srcDigestObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_clone, pDigestObj, srcDigestObj);
}

OS_Error_t
CryptoLibServer_Digest_process(
    CryptoLibDigest_ptr digestObj,
    size_t              inSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_process, digestObj, self->dataPort, inSize);
}

OS_Error_t
CryptoLibServer_Digest_finalize(
    CryptoLibDigest_ptr digestObj,
    size_t*             digestSize)
{
    CryptoLibServer_t* self;

    *digestSize = (*digestSize <= OS_Crypto_SIZE_DATAPORT) ? *digestSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Digest_finalize, digestObj, self->dataPort, digestSize);
}

// -------------------------------- Key API ------------------------------------

OS_Error_t
CryptoLibServer_Key_generate(
    CryptoLibKey_ptr* pKeyObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_generate, pKeyObj, self->dataPort);
}

OS_Error_t
CryptoLibServer_Key_makePublic(
    CryptoLibKey_ptr* pPubKeyHandle,
    CryptoLibKey_cptr prvKeyHandle)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_makePublic, pPubKeyHandle, prvKeyHandle, self->dataPort);
}

OS_Error_t
CryptoLibServer_Key_import(
    CryptoLibKey_ptr* pKeyObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_import, pKeyObj, self->dataPort);
}

OS_Error_t
CryptoLibServer_Key_export(
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
           CALL(self, Key_export, keyObj, self->dataPort);
}

OS_Error_t
CryptoLibServer_Key_getParams(
    CryptoLibKey_cptr keyObj,
    size_t*           paramSize)
{
    CryptoLibServer_t* self;

    *paramSize = (*paramSize <= OS_Crypto_SIZE_DATAPORT) ? *paramSize :
                 OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Key_getParams, keyObj, self->dataPort, paramSize);
}

OS_Error_t
CryptoLibServer_Key_getAttribs(
    CryptoLibKey_cptr keyObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_getAttribs, keyObj, self->dataPort);
}

OS_Error_t
CryptoLibServer_Key_loadParams(
    OS_CryptoKey_Param_t name,
    size_t*              paramSize)
{
    CryptoLibServer_t* self;

    *paramSize = (*paramSize <= OS_Crypto_SIZE_DATAPORT) ? *paramSize :
                 OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Key_loadParams, name, self->dataPort, paramSize);
}

OS_Error_t
CryptoLibServer_Key_free(
    CryptoLibKey_ptr keyObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_free, keyObj);
}

// ----------------------------- Agreement API ---------------------------------

OS_Error_t
CryptoLibServer_Agreement_init(
    CryptoLibAgreement_ptr*  pAgrObj,
    CryptoLibKey_cptr        prvKey,
    OS_CryptoAgreement_Alg_t algorithm)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Agreement_init, pAgrObj, prvKey, algorithm);
}

OS_Error_t
CryptoLibServer_Agreement_agree(
    CryptoLibAgreement_ptr agrObj,
    CryptoLibKey_cptr      pubKey,
    size_t*                sharedSize)
{
    CryptoLibServer_t* self;

    *sharedSize = (*sharedSize <= OS_Crypto_SIZE_DATAPORT) ? *sharedSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Agreement_agree, agrObj, pubKey, self->dataPort, sharedSize);
}

OS_Error_t
CryptoLibServer_Agreement_free(
    CryptoLibAgreement_ptr agrObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Agreement_free, agrObj);
}

// ----------------------------- Signature API ---------------------------------

OS_Error_t
CryptoLibServer_Signature_init(
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
CryptoLibServer_Signature_verify(
    CryptoLibSignature_ptr obj,
    size_t                 hashSize,
    size_t                 signatureSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_verify, obj, self->dataPort, hashSize,
                self->dataPort + hashSize, signatureSize);
}

OS_Error_t
CryptoLibServer_Signature_sign(
    CryptoLibSignature_ptr obj,
    size_t                 hashSize,
    size_t*                signatureSize)
{
    CryptoLibServer_t* self;

    *signatureSize = (*signatureSize <= OS_Crypto_SIZE_DATAPORT) ?
                     *signatureSize : OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Signature_sign, obj, self->dataPort,  hashSize,
                self->dataPort, signatureSize);
}

OS_Error_t
CryptoLibServer_Signature_free(
    CryptoLibSignature_ptr obj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_free, obj);
}

// ------------------------------- Cipher API ----------------------------------

OS_Error_t
CryptoLibServer_Cipher_init(
    CryptoLibCipher_ptr*  pCipherObj,
    CryptoLibKey_cptr     key,
    OS_CryptoCipher_Alg_t algorithm,
    size_t                ivSize)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_init, pCipherObj, key, algorithm, self->dataPort,
                ivSize);
}

OS_Error_t
CryptoLibServer_Cipher_free(
    CryptoLibCipher_ptr cipherObj)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_free, cipherObj);
}

OS_Error_t
CryptoLibServer_Cipher_process(
    CryptoLibCipher_ptr cipherObj,
    size_t              inputSize,
    size_t*             outputSize)
{
    CryptoLibServer_t* self;

    *outputSize = (*outputSize <= OS_Crypto_SIZE_DATAPORT) ? *outputSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Cipher_process, cipherObj, self->dataPort, inputSize,
                self->dataPort, outputSize);
}

OS_Error_t
CryptoLibServer_Cipher_start(
    CryptoLibCipher_ptr cipherObj,
    size_t              len)
{
    CryptoLibServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_start, cipherObj, self->dataPort, len);
}

OS_Error_t
CryptoLibServer_Cipher_finalize(
    CryptoLibCipher_ptr cipherObj,
    size_t*             tagSize)
{
    CryptoLibServer_t* self;

    *tagSize = (*tagSize <= OS_Crypto_SIZE_DATAPORT) ? *tagSize :
               OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Cipher_finalize, cipherObj, self->dataPort, tagSize);
}

// ------------------------------- init/free -----------------------------------

OS_Error_t
CryptoLibServer_init(
    CryptoLibServer_t**             ctx,
    const Crypto_Impl_t*            client,
    const OS_Crypto_Memory_t*       memory,
    const CryptoLibServer_Config_t* cfg)
{
    CryptoLibServer_t* svr;

    if (NULL == ctx || NULL == client || NULL == memory || NULL == cfg
        || NULL == cfg->dataPort)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = memory->calloc(1, sizeof(CryptoLibServer_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    *ctx = svr;

    svr->dataPort = cfg->dataPort;
    svr->memory    = *memory;
    svr->client   = *client;

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