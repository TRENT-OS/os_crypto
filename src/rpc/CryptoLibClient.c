/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "rpc/CryptoLibClient.h"

#include "compiler.h"

#include <string.h>
#include <sys/user.h>

// -------------------------- defines/types/variables --------------------------

struct CryptoLibClient
{
    OS_Crypto_Memory_t memory;
    if_OS_Crypto_t rpc;
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
    if (bufSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = self->rpc.Rng_getBytes(flags, bufSize)) == OS_SUCCESS)
    {
        memcpy(buf, OS_Dataport_getBuf(self->rpc.dataport), bufSize);
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
    if (seedSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), seed, seedSize);
    return self->rpc.Rng_reseed(seedSize);
}

// ------------------------------- MAC API -------------------------------------

static OS_Error_t
Mac_init(
    void*                    ctx,
    CryptoLibMac_t**         pMacObj,
    const CryptoLibKey_t*    keyObj,
    const OS_CryptoMac_Alg_t algorithm)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Mac_init(
               (OS_CryptoMac_Handle_t*)pMacObj,
               (OS_CryptoKey_Handle_t)keyObj,
               algorithm);
}

static OS_Error_t
Mac_free(
    void*           ctx,
    CryptoLibMac_t* macObj)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Mac_free(
               (OS_CryptoMac_Handle_t)macObj);
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
    if (dataSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, dataSize);
    return self->rpc.Mac_process(
               (OS_CryptoMac_Handle_t)macObj,
               dataSize);
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
    if (*macSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = self->rpc.Mac_finalize(
                   (OS_CryptoMac_Handle_t)macObj,
                   macSize)) == OS_SUCCESS)
    {
        memcpy(mac, OS_Dataport_getBuf(self->rpc.dataport), *macSize);
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
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Digest_init(
               (OS_CryptoDigest_Handle_t*)pDigestObj,
               algorithm);
}

static OS_Error_t
Digest_clone(
    void*                    ctx,
    CryptoLibDigest_t**      pDigestObj,
    const CryptoLibDigest_t* srcDigObj)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Digest_clone(
               (OS_CryptoDigest_Handle_t*)pDigestObj,
               (OS_CryptoDigest_Handle_t)srcDigObj);
}

static OS_Error_t
Digest_free(
    void*              ctx,
    CryptoLibDigest_t* digestObj)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Digest_free(
               (OS_CryptoDigest_Handle_t)digestObj);
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
    if (dataSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, dataSize);
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Digest_process(
               (OS_CryptoDigest_Handle_t)digestObj,
               dataSize);
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
    if (*digestSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = self->rpc.Digest_finalize(
                   (OS_CryptoDigest_Handle_t)digestObj,
                   digestSize)) == OS_SUCCESS)
    {
        memcpy(digest, OS_Dataport_getBuf(self->rpc.dataport), *digestSize);
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
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Signature_init(
               (OS_CryptoSignature_Handle_t*)pSigObj,
               (OS_CryptoKey_Handle_t)prvKey,
               (OS_CryptoKey_Handle_t)pubKey,
               algorithm,
               digest);
}

static OS_Error_t
Signature_free(
    void*                 ctx,
    CryptoLibSignature_t* sigObj)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Signature_free(
               (OS_CryptoSignature_Handle_t)sigObj);
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
    if (hashSize > OS_Dataport_getSize(self->rpc.dataport) ||
        *signatureSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), hash, hashSize);
    if ((err = self->rpc.Signature_sign(
                   (OS_CryptoSignature_Handle_t)sigObj,
                   hashSize,
                   signatureSize)) == OS_SUCCESS)
    {
        memcpy(signature, OS_Dataport_getBuf(self->rpc.dataport), *signatureSize);
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
    if (hashSize + signatureSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), hash, hashSize);
    memcpy(OS_Dataport_getBuf(self->rpc.dataport) + hashSize, signature,
           signatureSize);
    return self->rpc.Signature_verify(
               (OS_CryptoSignature_Handle_t)sigObj,
               hashSize,
               signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static OS_Error_t
Agreement_init(
    void*                          ctx,
    CryptoLibAgreement_t**         pAgrObj,
    const CryptoLibKey_t*          prvKey,
    const OS_CryptoAgreement_Alg_t algorithm)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Agreement_init(
               (OS_CryptoAgreement_Handle_t*)pAgrObj,
               (OS_CryptoKey_Handle_t)prvKey,
               algorithm);
}

static OS_Error_t
Agreement_free(
    void*                 ctx,
    CryptoLibAgreement_t* agrObj)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Agreement_free(
               (OS_CryptoAgreement_Handle_t)agrObj);
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
    if (*sharedSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = self->rpc.Agreement_agree(
                   (OS_CryptoAgreement_Handle_t)agrObj,
                   (OS_CryptoKey_Handle_t)pubKey,
                   sharedSize)) == OS_SUCCESS)
    {
        memcpy(shared, OS_Dataport_getBuf(self->rpc.dataport), *sharedSize);
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
    if (sizeof(OS_CryptoKey_Spec_t) > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), spec,
           sizeof(OS_CryptoKey_Spec_t));
    return self->rpc.Key_generate(
               (OS_CryptoKey_Handle_t*)pKeyObj);
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

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), attribs,
           sizeof(OS_CryptoKey_Attrib_t));
    return self->rpc.Key_makePublic(
               (OS_CryptoKey_Handle_t*)pPubKeyObj,
               (OS_CryptoKey_Handle_t)prvKeyObj);
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
    if (sizeof(OS_CryptoKey_Data_t) > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), keyData,
           sizeof(OS_CryptoKey_Data_t));
    return self->rpc.Key_import(
               (OS_CryptoKey_Handle_t*)pKeyObj);
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
    if (sizeof(OS_CryptoKey_Data_t) > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = self->rpc.Key_export(
                   (OS_CryptoKey_Handle_t)keyObj)) == OS_SUCCESS)
    {
        memcpy(keyData, OS_Dataport_getBuf(self->rpc.dataport),
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
    if (*paramSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = self->rpc.Key_getParams(
                   (OS_CryptoKey_Handle_t)keyObj,
                   paramSize)) == OS_SUCCESS)
    {
        memcpy(keyParams, OS_Dataport_getBuf(self->rpc.dataport), *paramSize);
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
    if (sizeof(OS_CryptoKey_Attrib_t) > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = self->rpc.Key_getAttribs(
                   (OS_CryptoKey_Handle_t)keyObj)) == OS_SUCCESS)
    {
        memcpy(attribs, OS_Dataport_getBuf(self->rpc.dataport),
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
    if (*paramSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = self->rpc.Key_loadParams(name, paramSize)) == OS_SUCCESS)
    {
        memcpy(keyParams, OS_Dataport_getBuf(self->rpc.dataport), *paramSize);
    }

    return err;
}

static OS_Error_t
Key_free(
    void*           ctx,
    CryptoLibKey_t* keyObj)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Key_free(
               (OS_CryptoKey_Handle_t)keyObj);
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
        if (ivSize > OS_Dataport_getSize(self->rpc.dataport))
        {
            return OS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(OS_Dataport_getBuf(self->rpc.dataport), iv, ivSize);
    }

    return self->rpc.Cipher_init(
               (OS_CryptoCipher_Handle_t*)pCipherObj,
               (OS_CryptoKey_Handle_t)key,
               algorithm,
               ivSize);
}

static OS_Error_t
Cipher_free(
    void*              ctx,
    CryptoLibCipher_t* cipherObj)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Cipher_free(
               (OS_CryptoCipher_Handle_t)cipherObj);
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
    if (inputSize > OS_Dataport_getSize(self->rpc.dataport) ||
        *outputSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), input, inputSize);
    if ((err = self->rpc.Cipher_process(
                   (OS_CryptoCipher_Handle_t)cipherObj,
                   inputSize,
                   outputSize)) == OS_SUCCESS)
    {
        memcpy(output, OS_Dataport_getBuf(self->rpc.dataport), *outputSize);
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
        if (dataSize > OS_Dataport_getSize(self->rpc.dataport))
        {
            return OS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, dataSize);
    }

    return NULL == self ? OS_ERROR_INVALID_PARAMETER :
           self->rpc.Cipher_start(
               (OS_CryptoCipher_Handle_t)cipherObj,
               dataSize);
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
    if (*tagSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), tag, *tagSize);
    if ((err = self->rpc.Cipher_finalize(
                   (OS_CryptoCipher_Handle_t)cipherObj,
                   tagSize)) == OS_SUCCESS)
    {
        memcpy(tag, OS_Dataport_getBuf(self->rpc.dataport), *tagSize);
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
    const if_OS_Crypto_t*     rpc)
{
    CryptoLibClient_t* self;

    if (NULL == impl || NULL == memory || NULL == rpc
        || OS_Dataport_isUnset(rpc->dataport))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((self = memory->calloc(1, sizeof(CryptoLibClient_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    impl->context  = self;
    impl->vtable   = &CryptoLibClient_vtable;
    self->rpc      = *rpc;
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