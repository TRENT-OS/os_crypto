/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(OS_CRYPTO_WITH_RPC_CLIENT)

#include "rpc/CryptoLibClient.h"
#include "rpc/CryptoLibServer.h"

#include "compiler.h"

#include <string.h>
#include <sys/user.h>

// -------------------------- defines/types/variables --------------------------

struct CryptoLibClient
{
    OS_Crypto_Memory_t memory;
    /**
     * The client's address of the dataport shared with the server
     */
    OS_Dataport_t dataport;
};

// -------------------------------- RNG API ------------------------------------

static OS_Error_t
Rng_getBytes(
    void*                     ctx,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == buf)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (bufSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = CryptoLibServer_Rng_getBytes(flags, bufSize)) == OS_SUCCESS)
    {
        memcpy(buf, OS_Dataport_getBuf(self->dataport), bufSize);
    }

    return err;
}

static OS_Error_t
Rng_reseed(
    void*        ctx,
    const void*  seed,
    const size_t seedSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == seed)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (seedSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), seed, seedSize);
    return CryptoLibServer_Rng_reseed(seedSize);
}

// ------------------------------- MAC API -------------------------------------

static OS_Error_t
Mac_init(
    void*                    ctx,
    CryptoLibMac_t**         pMacObj,
    const CryptoLibKey_t*    keyObj,
    const OS_CryptoMac_Alg_t algorithm)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Mac_init(pMacObj, keyObj, algorithm);
}

static OS_Error_t
Mac_free(
    void*           ctx,
    CryptoLibMac_t* macObj)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Mac_free(macObj);
}

static OS_Error_t
Mac_process(
    void*           ctx,
    CryptoLibMac_t* macObj,
    const void*     data,
    const size_t    dataSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == data)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (dataSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), data, dataSize);
    return CryptoLibServer_Mac_process(macObj, dataSize);
}

static OS_Error_t
Mac_finalize(
    void*           ctx,
    CryptoLibMac_t* macObj,
    void*           mac,
    size_t*         macSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == mac || NULL == macSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (*macSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = CryptoLibServer_Mac_finalize(macObj, macSize)) == OS_SUCCESS)
    {
        memcpy(mac, OS_Dataport_getBuf(self->dataport), *macSize);
    }

    return err;
}

// ------------------------------ Digest API -----------------------------------

static OS_Error_t
Digest_init(
    void*                       ctx,
    CryptoLibDigest_t**         pDigestObj,
    const OS_CryptoDigest_Alg_t algorithm)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Digest_init(pDigestObj, algorithm);
}

static OS_Error_t
Digest_clone(
    void*                    ctx,
    CryptoLibDigest_t**      pDigestObj,
    const CryptoLibDigest_t* srcDigObj)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Digest_clone(pDigestObj, srcDigObj);
}

static OS_Error_t
Digest_free(
    void*              ctx,
    CryptoLibDigest_t* digestObj)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Digest_free(digestObj);
}

static OS_Error_t
Digest_process(
    void*              ctx,
    CryptoLibDigest_t* digestObj,
    const void*        data,
    const size_t       dataSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == data)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (dataSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), data, dataSize);
    return CryptoLibServer_Digest_process(digestObj, dataSize);
}

static OS_Error_t
Digest_finalize(
    void*              ctx,
    CryptoLibDigest_t* digestObj,
    void*              digest,
    size_t*            digestSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == digest || NULL == digestSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (*digestSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = CryptoLibServer_Digest_finalize(digestObj,
                                               digestSize)) == OS_SUCCESS)
    {
        memcpy(digest, OS_Dataport_getBuf(self->dataport), *digestSize);
    }

    return err;
}

// ----------------------------- Signature API ---------------------------------

static OS_Error_t
Signature_init(
    void*                          ctx,
    CryptoLibSignature_t**         pSigObj,
    const CryptoLibKey_t*          prvKey,
    const CryptoLibKey_t*          pubKey,
    const OS_CryptoSignature_Alg_t algorithm,
    const OS_CryptoDigest_Alg_t    digest)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Signature_init(pSigObj, prvKey, pubKey, algorithm,
                                          digest);
}

static OS_Error_t
Signature_free(
    void*                 ctx,
    CryptoLibSignature_t* sigObj)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Signature_free(sigObj);
}

static OS_Error_t
Signature_sign(
    void*                 ctx,
    CryptoLibSignature_t* sigObj,
    const void*           hash,
    const size_t          hashSize,
    void*                 signature,
    size_t*               signatureSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == hash || NULL == signature || NULL == signatureSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (hashSize > OS_Dataport_getSize(self->dataport) ||
        *signatureSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), hash, hashSize);
    if ((err = CryptoLibServer_Signature_sign(sigObj, hashSize,
                                              signatureSize)) == OS_SUCCESS)
    {
        memcpy(signature, OS_Dataport_getBuf(self->dataport), *signatureSize);
    }

    return err;
}

static OS_Error_t
Signature_verify(
    void*                 ctx,
    CryptoLibSignature_t* sigObj,
    const void*           hash,
    const size_t          hashSize,
    const void*           signature,
    const size_t          signatureSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == ctx || NULL == hash || NULL == signature)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (hashSize + signatureSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), hash, hashSize);
    memcpy(OS_Dataport_getBuf(self->dataport) + hashSize, signature,
           signatureSize);
    return CryptoLibServer_Signature_verify(sigObj, hashSize, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static OS_Error_t
Agreement_init(
    void*                          ctx,
    CryptoLibAgreement_t**         pAgrObj,
    const CryptoLibKey_t*          prvKey,
    const OS_CryptoAgreement_Alg_t algorithm)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Agreement_init(pAgrObj, prvKey, algorithm);
}

static OS_Error_t
Agreement_free(
    void*                 ctx,
    CryptoLibAgreement_t* agrObj)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Agreement_free(agrObj);
}

static OS_Error_t
Agreement_agree(
    void*                 ctx,
    CryptoLibAgreement_t* agrObj,
    const CryptoLibKey_t* pubKey,
    void*                 shared,
    size_t*               sharedSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == shared || NULL == sharedSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (*sharedSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = CryptoLibServer_Agreement_agree(agrObj, pubKey,
                                               sharedSize)) == OS_SUCCESS)
    {
        memcpy(shared, OS_Dataport_getBuf(self->dataport), *sharedSize);
    }

    return err;
}

// -------------------------------- Key API ------------------------------------

static OS_Error_t
Key_generate(
    void*                      ctx,
    CryptoLibKey_t**           pKeyObj,
    const OS_CryptoKey_Spec_t* spec)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == pKeyObj || NULL == spec)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (sizeof(OS_CryptoKey_Spec_t) > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), spec, sizeof(OS_CryptoKey_Spec_t));
    return CryptoLibServer_Key_generate(pKeyObj);
}

static OS_Error_t
Key_makePublic(
    void*                        ctx,
    CryptoLibKey_t**             pPubKeyObj,
    const CryptoLibKey_t*        prvKeyObj,
    const OS_CryptoKey_Attrib_t* attribs)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == pPubKeyObj || NULL == attribs)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), attribs,
           sizeof(OS_CryptoKey_Attrib_t));
    return CryptoLibServer_Key_makePublic(pPubKeyObj, prvKeyObj);
}

static OS_Error_t
Key_import(
    void*                      ctx,
    CryptoLibKey_t**           pKeyObj,
    const OS_CryptoKey_Data_t* keyData)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == pKeyObj || NULL == keyData)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (sizeof(OS_CryptoKey_Data_t) > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), keyData,
           sizeof(OS_CryptoKey_Data_t));
    return CryptoLibServer_Key_import(pKeyObj);
}

static OS_Error_t
Key_export(
    void*                 ctx,
    const CryptoLibKey_t* keyObj,
    OS_CryptoKey_Data_t*  keyData)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    OS_Error_t err = OS_ERROR_GENERIC;

    if (NULL == self || NULL == keyData)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (sizeof(OS_CryptoKey_Data_t) > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = CryptoLibServer_Key_export(keyObj)) == OS_SUCCESS)
    {
        memcpy(keyData, OS_Dataport_getBuf(self->dataport),
               sizeof(OS_CryptoKey_Data_t));
    }

    return err;
}

static OS_Error_t
Key_getParams(
    void*                 ctx,
    const CryptoLibKey_t* keyObj,
    void*                 keyParams,
    size_t*               paramSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    OS_Error_t err = OS_ERROR_GENERIC;

    if (NULL == self || NULL == keyParams || NULL == paramSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (*paramSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = CryptoLibServer_Key_getParams(keyObj, paramSize)) == OS_SUCCESS)
    {
        memcpy(keyParams, OS_Dataport_getBuf(self->dataport), *paramSize);
    }

    return err;
}

static OS_Error_t
Key_getAttribs(
    void*                  ctx,
    const CryptoLibKey_t*  keyObj,
    OS_CryptoKey_Attrib_t* attribs)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    OS_Error_t err = OS_ERROR_GENERIC;

    if (NULL == self || NULL == attribs)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (sizeof(OS_CryptoKey_Attrib_t) > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = CryptoLibServer_Key_getAttribs(keyObj)) == OS_SUCCESS)
    {
        memcpy(attribs, OS_Dataport_getBuf(self->dataport),
               sizeof(OS_CryptoKey_Attrib_t));
    }

    return err;
}

static OS_Error_t
Key_loadParams(
    void*                      ctx,
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    OS_Error_t err = OS_ERROR_GENERIC;

    if (NULL == self || NULL == keyParams || NULL == paramSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (*paramSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = CryptoLibServer_Key_loadParams(name,
                                              paramSize)) == OS_SUCCESS)
    {
        memcpy(keyParams, OS_Dataport_getBuf(self->dataport), *paramSize);
    }

    return err;
}

static OS_Error_t
Key_free(
    void*           ctx,
    CryptoLibKey_t* keyObj)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Key_free(keyObj);
}

// ------------------------------ Cipher API -----------------------------------

static OS_Error_t
Cipher_init(
    void*                       ctx,
    CryptoLibCipher_t**         pCipherObj,
    const CryptoLibKey_t*       key,
    const OS_CryptoCipher_Alg_t algorithm,
    const void*                 iv,
    const size_t                ivSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == pCipherObj)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (iv != NULL)
    {
        if (ivSize > OS_Dataport_getSize(self->dataport))
        {
            return OS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(OS_Dataport_getBuf(self->dataport), iv, ivSize);
    }

    return CryptoLibServer_Cipher_init(pCipherObj, key, algorithm, ivSize);
}

static OS_Error_t
Cipher_free(
    void*              ctx,
    CryptoLibCipher_t* cipherObj)
{
    UNUSED_VAR(ctx);
    return CryptoLibServer_Cipher_free(cipherObj);
}

static OS_Error_t
Cipher_process(
    void*              ctx,
    CryptoLibCipher_t* cipherObj,
    const void*        input,
    const size_t       inputSize,
    void*              output,
    size_t*            outputSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == input || NULL == output || NULL == outputSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (inputSize > OS_Dataport_getSize(self->dataport) ||
        *outputSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), input, inputSize);
    if ((err = CryptoLibServer_Cipher_process(cipherObj, inputSize,
                                              outputSize)) == OS_SUCCESS)
    {
        memcpy(output, OS_Dataport_getBuf(self->dataport), *outputSize);
    }

    return err;
}

static OS_Error_t
Cipher_start(
    void*              ctx,
    CryptoLibCipher_t* cipherObj,
    const void*        data,
    const size_t       dataSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (NULL != data)
    {
        if (dataSize > OS_Dataport_getSize(self->dataport))
        {
            return OS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(OS_Dataport_getBuf(self->dataport), data, dataSize);
    }

    return CryptoLibServer_Cipher_start(cipherObj, dataSize);
}

static OS_Error_t
Cipher_finalize(
    void*              ctx,
    CryptoLibCipher_t* cipherObj,
    void*              tag,
    size_t*            tagSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    if (NULL == self || NULL == tag || NULL == tagSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (*tagSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), tag, *tagSize);
    if ((err = CryptoLibServer_Cipher_finalize(cipherObj,
                                               tagSize)) == OS_SUCCESS)
    {
        memcpy(tag, OS_Dataport_getBuf(self->dataport), *tagSize);
    }

    return err;
}

// ------------------------------- init/free -----------------------------------

static const Crypto_Vtable_t CryptoLibClient_vtable =
{
    .Rng_getBytes        = Rng_getBytes,
    .Rng_reseed          = Rng_reseed,
    .Mac_init            = Mac_init,
    .Mac_free            = Mac_free,
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
    .Key_getAttribs      = Key_getAttribs,
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

OS_Error_t
CryptoLibClient_init(
    Crypto_Impl_t*            impl,
    const OS_Crypto_Memory_t* memory,
    const OS_Dataport_t*      dataport)
{
    CryptoLibClient_t* self;

    if (NULL == impl || NULL == memory || NULL == dataport
        || OS_Dataport_isUnset(*dataport))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((self = memory->calloc(1, sizeof(CryptoLibClient_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    impl->context  = self;
    impl->vtable   = &CryptoLibClient_vtable;
    self->dataport = *dataport;
    self->memory   = *memory;

    return OS_SUCCESS;
}

OS_Error_t
CryptoLibClient_free(
    CryptoLibClient_t* self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    self->memory.free(self);

    return OS_SUCCESS;
}

#endif /* OS_CRYPTO_WITH_RPC_CLIENT */