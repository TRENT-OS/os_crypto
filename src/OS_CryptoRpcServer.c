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
extern OS_CryptoH
OS_CryptoRpcServer_getCrypto(
    void);

// This is not exposed via header intentionally
void*
OS_Crypto_getServer(
    const OS_CryptoH self);

// Get Crypto API context host of Crypto API in RPC_SERVER mode
#define GET_SELF(s) {                                       \
    OS_Crypto *a;                                           \
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
    OS_CryptoImpl client;
    OS_Crypto_Memory memIf;
};

// -------------------------------- RNG API ------------------------------------

seos_err_t
OS_CryptoRpcServer_Rng_getBytes(
    unsigned int flags,
    size_t       bufSize)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Rng_getBytes, flags, self->dataPort, bufSize);
}

seos_err_t
OS_CryptoRpcServer_Rng_reseed(
    size_t seedSize)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Rng_reseed, self->dataPort, seedSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
OS_CryptoRpcServer_Mac_init(
    OS_CryptoLibMac_Ptr* pMacObj,
    OS_CryptoMac_Alg     algorithm)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Mac_init, pMacObj, algorithm);
}

seos_err_t
OS_CryptoRpcServer_Mac_exists(
    OS_CryptoLibMac_CPtr macObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Mac_exists, macObj);
}

seos_err_t
OS_CryptoRpcServer_Mac_free(
    OS_CryptoLibMac_Ptr macObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Mac_free, macObj);
}

seos_err_t
OS_CryptoRpcServer_Mac_start(
    OS_CryptoLibMac_Ptr macObj,
    size_t              secretSize)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Mac_start, macObj, self->dataPort, secretSize);
}

seos_err_t
OS_CryptoRpcServer_Mac_process(
    OS_CryptoLibMac_Ptr macObj,
    size_t              dataSize)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Mac_process, macObj, self->dataPort, dataSize);
}

seos_err_t
OS_CryptoRpcServer_Mac_finalize(
    OS_CryptoLibMac_Ptr macObj,
    size_t*             macSize)
{
    OS_CryptoRpcServer* self;

    *macSize = (*macSize <= OS_Crypto_SIZE_DATAPORT) ? *macSize :
               OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Mac_finalize, macObj, self->dataPort, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
OS_CryptoRpcServer_Digest_init(
    OS_CryptoLibDigest_Ptr* pDigestObj,
    OS_CryptoDigest_Alg     algorithm)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Digest_init, pDigestObj, algorithm);
}

seos_err_t
OS_CryptoRpcServer_Digest_exists(
    OS_CryptoLibDigest_CPtr digestObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Digest_exists, digestObj);
}

seos_err_t
OS_CryptoRpcServer_Digest_free(
    OS_CryptoLibDigest_Ptr digestObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Digest_free, digestObj);
}

seos_err_t
OS_CryptoRpcServer_Digest_clone(
    OS_CryptoLibDigest_Ptr  dstDigHandle,
    OS_CryptoLibDigest_CPtr srcDigHandle)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Digest_clone, dstDigHandle, srcDigHandle);
}

seos_err_t
OS_CryptoRpcServer_Digest_process(
    OS_CryptoLibDigest_Ptr digestObj,
    size_t                 inSize)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Digest_process, digestObj, self->dataPort, inSize);
}

seos_err_t
OS_CryptoRpcServer_Digest_finalize(
    OS_CryptoLibDigest_Ptr digestObj,
    size_t*                digestSize)
{
    OS_CryptoRpcServer* self;

    *digestSize = (*digestSize <= OS_Crypto_SIZE_DATAPORT) ? *digestSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Digest_finalize, digestObj, self->dataPort, digestSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
OS_CryptoRpcServer_Key_generate(
    OS_CryptoLibKey_Ptr* pKeyObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Key_generate, pKeyObj, self->dataPort);
}

seos_err_t
OS_CryptoRpcServer_Key_makePublic(
    OS_CryptoLibKey_Ptr* pPubKeyHandle,
    OS_CryptoLibKey_CPtr prvKeyHandle)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Key_makePublic, pPubKeyHandle, prvKeyHandle, self->dataPort);
}

seos_err_t
OS_CryptoRpcServer_Key_import(
    OS_CryptoLibKey_Ptr* pKeyObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Key_import, pKeyObj, self->dataPort);
}

seos_err_t
OS_CryptoRpcServer_Key_export(
    OS_CryptoLibKey_CPtr keyObj)
{
    seos_err_t err;
    OS_CryptoKey_Attribs attribs;
    OS_CryptoRpcServer* self;

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
    OS_CryptoLibKey_CPtr keyObj,
    size_t*              paramSize)
{
    OS_CryptoRpcServer* self;

    *paramSize = (*paramSize <= OS_Crypto_SIZE_DATAPORT) ? *paramSize :
                 OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Key_getParams, keyObj, self->dataPort, paramSize);
}

seos_err_t
OS_CryptoRpcServer_Key_getAttribs(
    OS_CryptoLibKey_CPtr keyObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Key_getAttribs, keyObj, self->dataPort);
}

seos_err_t
OS_CryptoRpcServer_Key_loadParams(
    OS_CryptoKey_Param name,
    size_t*            paramSize)
{
    OS_CryptoRpcServer* self;

    *paramSize = (*paramSize <= OS_Crypto_SIZE_DATAPORT) ? *paramSize :
                 OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Key_loadParams, name, self->dataPort, paramSize);
}

seos_err_t
OS_CryptoRpcServer_Key_exists(
    OS_CryptoLibKey_CPtr keyObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Key_exists, keyObj);
}

seos_err_t
OS_CryptoRpcServer_Key_free(
    OS_CryptoLibKey_Ptr keyObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Key_free, keyObj);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
OS_CryptoRpcServer_Agreement_init(
    OS_CryptoLibAgreement_Ptr* pAgrObj,
    OS_CryptoAgreement_Alg     algorithm,
    OS_CryptoLibKey_CPtr       prvKey)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Agreement_init, pAgrObj, algorithm, prvKey);
}

seos_err_t
OS_CryptoRpcServer_Agreement_agree(
    OS_CryptoLibAgreement_Ptr agrObj,
    OS_CryptoLibKey_CPtr      pubKey,
    size_t*                   sharedSize)
{
    OS_CryptoRpcServer* self;

    *sharedSize = (*sharedSize <= OS_Crypto_SIZE_DATAPORT) ? *sharedSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Agreement_agree, agrObj, pubKey, self->dataPort, sharedSize);
}

seos_err_t
OS_CryptoRpcServer_Agreement_exists(
    OS_CryptoLibAgreement_CPtr agrObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Agreement_exists, agrObj);
}

seos_err_t
OS_CryptoRpcServer_Agreement_free(
    OS_CryptoLibAgreement_Ptr agrObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Agreement_free, agrObj);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
OS_CryptoRpcServer_Signature_init(
    OS_CryptoLibSignature_Ptr* pObj,
    OS_CryptoSignature_Alg     algorithm,
    OS_CryptoDigest_Alg        digest,
    OS_CryptoLibKey_CPtr       prvKey,
    OS_CryptoLibKey_CPtr       pubKey)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Signature_init, pObj, algorithm, digest, prvKey, pubKey);
}

seos_err_t
OS_CryptoRpcServer_Signature_verify(
    OS_CryptoLibSignature_Ptr obj,
    size_t                    hashSize,
    size_t                    signatureSize)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Signature_verify, obj, self->dataPort, hashSize,
                self->dataPort + hashSize, signatureSize);
}

seos_err_t
OS_CryptoRpcServer_Signature_sign(
    OS_CryptoLibSignature_Ptr obj,
    size_t                    hashSize,
    size_t*                   signatureSize)
{
    OS_CryptoRpcServer* self;

    *signatureSize = (*signatureSize <= OS_Crypto_SIZE_DATAPORT) ?
                     *signatureSize : OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Signature_sign, obj, self->dataPort,  hashSize,
                self->dataPort, signatureSize);
}

seos_err_t
OS_CryptoRpcServer_Signature_exists(
    OS_CryptoLibSignature_CPtr obj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Signature_exists, obj);
}

seos_err_t
OS_CryptoRpcServer_Signature_free(
    OS_CryptoLibSignature_Ptr obj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Signature_free, obj);
}

// ------------------------------- Cipher API ----------------------------------

seos_err_t
OS_CryptoRpcServer_Cipher_init(
    OS_CryptoLibCipher_Ptr* pCipherObj,
    OS_CryptoCipher_Alg     algorithm,
    OS_CryptoLibKey_CPtr    key,
    size_t                  ivSize)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Cipher_init, pCipherObj, algorithm, key, self->dataPort,
                ivSize);
}

seos_err_t
OS_CryptoRpcServer_Cipher_exists(
    OS_CryptoLibCipher_CPtr cipherObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Cipher_exists, cipherObj);
}

seos_err_t
OS_CryptoRpcServer_Cipher_free(
    OS_CryptoLibCipher_Ptr cipherObj)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Cipher_free, cipherObj);
}

seos_err_t
OS_CryptoRpcServer_Cipher_process(
    OS_CryptoLibCipher_Ptr cipherObj,
    size_t                 inputSize,
    size_t*                outputSize)
{
    OS_CryptoRpcServer* self;

    *outputSize = (*outputSize <= OS_Crypto_SIZE_DATAPORT) ? *outputSize :
                  OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Cipher_process, cipherObj, self->dataPort, inputSize,
                self->dataPort, outputSize);
}

seos_err_t
OS_CryptoRpcServer_Cipher_start(
    OS_CryptoLibCipher_Ptr cipherObj,
    size_t                 len)
{
    OS_CryptoRpcServer* self;

    GET_SELF(self);
    return CALL(self, Cipher_start, cipherObj, self->dataPort, len);
}

seos_err_t
OS_CryptoRpcServer_Cipher_finalize(
    OS_CryptoLibCipher_Ptr cipherObj,
    size_t*                tagSize)
{
    OS_CryptoRpcServer* self;

    *tagSize = (*tagSize <= OS_Crypto_SIZE_DATAPORT) ? *tagSize :
               OS_Crypto_SIZE_DATAPORT;

    GET_SELF(self);
    return CALL(self, Cipher_finalize, cipherObj, self->dataPort, tagSize);
}

// ------------------------------- init/free -----------------------------------

seos_err_t
OS_CryptoRpcServer_init(
    OS_CryptoRpcServer**             ctx,
    const OS_CryptoImpl*             client,
    const OS_Crypto_Memory*          memIf,
    const OS_CryptoRpcServer_Config* cfg)
{
    OS_CryptoRpcServer* svr;

    if (NULL == ctx || NULL == client || NULL == memIf || NULL == cfg
        || NULL == cfg->dataPort)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = memIf->malloc(sizeof(OS_CryptoRpcServer))) == NULL)
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
    OS_CryptoRpcServer* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    self->memIf.free(self);

    return SEOS_SUCCESS;
}

#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */