/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)

#include "OS_Crypto.h"

#include "OS_CryptoRpcServer.h"

#include <string.h>
#include <stdlib.h>

// -------------------------- defines/types/variables --------------------------

/*
 * Host of SEOS Crypto API RPC server has to provide a client's RPC context.
 * This way, it is up to the host (e.g., the CryptoServer) to implement its own
 * way of handling multiple clients and their respective contextx.
 */
extern OS_Crypto_Handle_t
OS_CryptoRpcServer_getCrypto(
    void);

// This is not exposed via header intentionally
void*
OS_Crypto_getServer(
    const OS_Crypto_Handle_t self);

// Get Crypto API context host of Crypto API in RPC_SERVER mode
#define GET_SELF(s) {                                       \
    OS_Crypto_t *a;                                         \
    if (((a = OS_CryptoRpcServer_getCrypto()) == NULL) ||   \
        ((s = OS_Crypto_getServer(a)) == NULL) )            \
    {                                                       \
        return SEOS_ERROR_INVALID_PARAMETER;                \
    }                                                       \
}

// Call function pointer to LIB, make sure it is defined
#define CALL(s, f, ...)                                     \
    (NULL == s->client.vtable->f) ?                         \
        SEOS_ERROR_NOT_SUPPORTED :                          \
        s->client.vtable->f(s->client.context, __VA_ARGS__)

struct OS_CryptoRpcServer
{
    /**
     * The server's address of the dataport shared with the client
     */
    void* dataPort;
    /**
     * Context and function pointers of CLIENT implementation
     */
    OS_CryptoImpl_t client;
    OS_Crypto_Memory_t memIf;
};

// -------------------------------- RNG API ------------------------------------

seos_err_t
OS_CryptoRpcServer_Rng_getBytes(
    unsigned int flags,
    size_t       bufSize)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Rng_getBytes, flags, self->dataPort, bufSize);
}

seos_err_t
OS_CryptoRpcServer_Rng_reseed(
    size_t seedSize)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Rng_reseed, self->dataPort, seedSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
OS_CryptoRpcServer_Mac_init(
    CryptoLibMac_ptr*  pMacObj,
    OS_CryptoMac_Alg_t algorithm)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_init, pMacObj, algorithm);
}

seos_err_t
OS_CryptoRpcServer_Mac_exists(
    CryptoLibMac_cptr macObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_exists, macObj);
}

seos_err_t
OS_CryptoRpcServer_Mac_free(
    CryptoLibMac_ptr macObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_free, macObj);
}

seos_err_t
OS_CryptoRpcServer_Mac_start(
    CryptoLibMac_ptr macObj,
    size_t           secretSize)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_start, macObj, self->dataPort, secretSize);
}

seos_err_t
OS_CryptoRpcServer_Mac_process(
    CryptoLibMac_ptr macObj,
    size_t           dataSize)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Mac_process, macObj, self->dataPort, dataSize);
}

seos_err_t
OS_CryptoRpcServer_Mac_finalize(
    CryptoLibMac_ptr macObj,
    size_t*          macSize)
{
    OS_CryptoRpcServer_t* self;

    *macSize = (*macSize <= OS_Crypto_SIZE_DATAPORT) ? *macSize :
               OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Mac_finalize, macObj, self->dataPort, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
OS_CryptoRpcServer_Digest_init(
    CryptoLibDigest_ptr*  pDigestObj,
    OS_CryptoDigest_Alg_t algorithm)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_init, pDigestObj, algorithm);
}

seos_err_t
OS_CryptoRpcServer_Digest_exists(
    CryptoLibDigest_cptr digestObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_exists, digestObj);
}

seos_err_t
OS_CryptoRpcServer_Digest_free(
    CryptoLibDigest_ptr digestObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_free, digestObj);
}

seos_err_t
OS_CryptoRpcServer_Digest_clone(
    CryptoLibDigest_ptr  dstDigHandle,
    CryptoLibDigest_cptr srcDigHandle)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_clone, dstDigHandle, srcDigHandle);
}

seos_err_t
OS_CryptoRpcServer_Digest_process(
    CryptoLibDigest_ptr digestObj,
    size_t              inSize)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Digest_process, digestObj, self->dataPort, inSize);
}

seos_err_t
OS_CryptoRpcServer_Digest_finalize(
    CryptoLibDigest_ptr digestObj,
    size_t*             digestSize)
{
    OS_CryptoRpcServer_t* self;

    *digestSize = (*digestSize <= OS_Crypto_SIZE_DATAPORT) ? *digestSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Digest_finalize, digestObj, self->dataPort, digestSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
OS_CryptoRpcServer_Key_generate(
    CryptoLibKey_ptr* pKeyObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_generate, pKeyObj, self->dataPort);
}

seos_err_t
OS_CryptoRpcServer_Key_makePublic(
    CryptoLibKey_ptr* pPubKeyHandle,
    CryptoLibKey_cptr prvKeyHandle)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_makePublic, pPubKeyHandle, prvKeyHandle, self->dataPort);
}

seos_err_t
OS_CryptoRpcServer_Key_import(
    CryptoLibKey_ptr* pKeyObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_import, pKeyObj, self->dataPort);
}

seos_err_t
OS_CryptoRpcServer_Key_export(
    CryptoLibKey_cptr keyObj)
{
    seos_err_t err;
    OS_CryptoKey_Attrib_t attribs;
    OS_CryptoRpcServer_t* self;

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
OS_CryptoRpcServer_Key_getParams(
    CryptoLibKey_cptr keyObj,
    size_t*           paramSize)
{
    OS_CryptoRpcServer_t* self;

    *paramSize = (*paramSize <= OS_Crypto_SIZE_DATAPORT) ? *paramSize :
                 OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Key_getParams, keyObj, self->dataPort, paramSize);
}

seos_err_t
OS_CryptoRpcServer_Key_getAttribs(
    CryptoLibKey_cptr keyObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_getAttribs, keyObj, self->dataPort);
}

seos_err_t
OS_CryptoRpcServer_Key_loadParams(
    OS_CryptoKey_Param_t name,
    size_t*              paramSize)
{
    OS_CryptoRpcServer_t* self;

    *paramSize = (*paramSize <= OS_Crypto_SIZE_DATAPORT) ? *paramSize :
                 OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Key_loadParams, name, self->dataPort, paramSize);
}

seos_err_t
OS_CryptoRpcServer_Key_exists(
    CryptoLibKey_cptr keyObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_exists, keyObj);
}

seos_err_t
OS_CryptoRpcServer_Key_free(
    CryptoLibKey_ptr keyObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Key_free, keyObj);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
OS_CryptoRpcServer_Agreement_init(
    CryptoLibAgreement_ptr*  pAgrObj,
    OS_CryptoAgreement_Alg_t algorithm,
    CryptoLibKey_cptr        prvKey)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Agreement_init, pAgrObj, algorithm, prvKey);
}

seos_err_t
OS_CryptoRpcServer_Agreement_agree(
    CryptoLibAgreement_ptr agrObj,
    CryptoLibKey_cptr      pubKey,
    size_t*                sharedSize)
{
    OS_CryptoRpcServer_t* self;

    *sharedSize = (*sharedSize <= OS_Crypto_SIZE_DATAPORT) ? *sharedSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Agreement_agree, agrObj, pubKey, self->dataPort, sharedSize);
}

seos_err_t
OS_CryptoRpcServer_Agreement_exists(
    CryptoLibAgreement_cptr agrObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Agreement_exists, agrObj);
}

seos_err_t
OS_CryptoRpcServer_Agreement_free(
    CryptoLibAgreement_ptr agrObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Agreement_free, agrObj);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
OS_CryptoRpcServer_Signature_init(
    CryptoLibSignature_ptr*  pObj,
    OS_CryptoSignature_Alg_t algorithm,
    OS_CryptoDigest_Alg_t    digest,
    CryptoLibKey_cptr        prvKey,
    CryptoLibKey_cptr        pubKey)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_init, pObj, algorithm, digest, prvKey, pubKey);
}

seos_err_t
OS_CryptoRpcServer_Signature_verify(
    CryptoLibSignature_ptr obj,
    size_t                 hashSize,
    size_t                 signatureSize)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_verify, obj, self->dataPort, hashSize,
                self->dataPort + hashSize, signatureSize);
}

seos_err_t
OS_CryptoRpcServer_Signature_sign(
    CryptoLibSignature_ptr obj,
    size_t                 hashSize,
    size_t*                signatureSize)
{
    OS_CryptoRpcServer_t* self;

    *signatureSize = (*signatureSize <= OS_Crypto_SIZE_DATAPORT) ?
                     *signatureSize : OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Signature_sign, obj, self->dataPort,  hashSize,
                self->dataPort, signatureSize);
}

seos_err_t
OS_CryptoRpcServer_Signature_exists(
    CryptoLibSignature_cptr obj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_exists, obj);
}

seos_err_t
OS_CryptoRpcServer_Signature_free(
    CryptoLibSignature_ptr obj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Signature_free, obj);
}

// ------------------------------- Cipher API ----------------------------------

seos_err_t
OS_CryptoRpcServer_Cipher_init(
    CryptoLibCipher_ptr*  pCipherObj,
    OS_CryptoCipher_Alg_t algorithm,
    CryptoLibKey_cptr     key,
    size_t                ivSize)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_init, pCipherObj, algorithm, key, self->dataPort,
                ivSize);
}

seos_err_t
OS_CryptoRpcServer_Cipher_exists(
    CryptoLibCipher_cptr cipherObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_exists, cipherObj);
}

seos_err_t
OS_CryptoRpcServer_Cipher_free(
    CryptoLibCipher_ptr cipherObj)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_free, cipherObj);
}

seos_err_t
OS_CryptoRpcServer_Cipher_process(
    CryptoLibCipher_ptr cipherObj,
    size_t              inputSize,
    size_t*             outputSize)
{
    OS_CryptoRpcServer_t* self;

    *outputSize = (*outputSize <= OS_Crypto_SIZE_DATAPORT) ? *outputSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Cipher_process, cipherObj, self->dataPort, inputSize,
                self->dataPort, outputSize);
}

seos_err_t
OS_CryptoRpcServer_Cipher_start(
    CryptoLibCipher_ptr cipherObj,
    size_t              len)
{
    OS_CryptoRpcServer_t* self;

    GET_SELF(self);
    return CALL(self, Cipher_start, cipherObj, self->dataPort, len);
}

seos_err_t
OS_CryptoRpcServer_Cipher_finalize(
    CryptoLibCipher_ptr cipherObj,
    size_t*             tagSize)
{
    OS_CryptoRpcServer_t* self;

    *tagSize = (*tagSize <= OS_Crypto_SIZE_DATAPORT) ? *tagSize :
               OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Cipher_finalize, cipherObj, self->dataPort, tagSize);
}

// ------------------------------- init/free -----------------------------------

seos_err_t
OS_CryptoRpcServer_init(
    OS_CryptoRpcServer_t**             ctx,
    const OS_CryptoImpl_t*             client,
    const OS_Crypto_Memory_t*          memIf,
    const OS_CryptoRpcServer_Config_t* cfg)
{
    OS_CryptoRpcServer_t* svr;

    if (NULL == ctx || NULL == client || NULL == memIf || NULL == cfg
        || NULL == cfg->dataPort)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = memIf->malloc(sizeof(OS_CryptoRpcServer_t))) == NULL)
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
OS_CryptoRpcServer_free(
    OS_CryptoRpcServer_t* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    self->memIf.free(self);

    return SEOS_SUCCESS;
}

#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */