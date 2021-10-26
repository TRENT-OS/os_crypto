/**
 * Copyright (C) 2019-2020, HENSOLDT Cyber GmbH
 */

#include "rpc/CryptoLibClient.h"

#include "lib_macros/Check.h"

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

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(buf);
    CHECK_VALUE_IN_CLOSED_INTERVAL(bufSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

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

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(seed);
    CHECK_VALUE_IN_CLOSED_INTERVAL(seedSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), seed, seedSize);

    return self->rpc.Rng_reseed(seedSize);
}

// ------------------------------- MAC API -------------------------------------

static OS_Error_t
Mac_init(
    void*                    ctx,
    void**                   pMacHandle,
    const void*              keyHandle,
    const OS_CryptoMac_Alg_t algorithm)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Mac_init(
               (OS_CryptoMac_Handle_t*)pMacHandle,
               (OS_CryptoKey_Handle_t)keyHandle,
               algorithm);
}

static OS_Error_t
Mac_free(
    void* ctx,
    void* macHandle)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Mac_free(
               (OS_CryptoMac_Handle_t)macHandle);
}

static OS_Error_t
Mac_process(
    void*        ctx,
    void*        macHandle,
    const void*  data,
    const size_t dataSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(data);
    CHECK_VALUE_IN_CLOSED_INTERVAL(dataSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, dataSize);

    return self->rpc.Mac_process(
               (OS_CryptoMac_Handle_t)macHandle,
               dataSize);
}

static OS_Error_t
Mac_finalize(
    void*   ctx,
    void*   macHandle,
    void*   mac,
    size_t* macSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(mac);
    CHECK_PTR_NOT_NULL(macSize);
    CHECK_VALUE_IN_CLOSED_INTERVAL(*macSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    if ((err = self->rpc.Mac_finalize(
                   (OS_CryptoMac_Handle_t)macHandle,
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
    void**                      pDigestHandle,
    const OS_CryptoDigest_Alg_t algorithm)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Digest_init(
               (OS_CryptoDigest_Handle_t*)pDigestHandle,
               algorithm);
}

static OS_Error_t
Digest_clone(
    void*       ctx,
    void**      pDigestHandle,
    const void* srcDigHandle)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Digest_clone(
               (OS_CryptoDigest_Handle_t*)pDigestHandle,
               (OS_CryptoDigest_Handle_t)srcDigHandle);
}

static OS_Error_t
Digest_free(
    void* ctx,
    void* digestHandle)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Digest_free(
               (OS_CryptoDigest_Handle_t)digestHandle);
}

static OS_Error_t
Digest_process(
    void*        ctx,
    void*        digestHandle,
    const void*  data,
    const size_t dataSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(data);
    CHECK_VALUE_IN_CLOSED_INTERVAL(dataSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, dataSize);

    return self->rpc.Digest_process(
               (OS_CryptoDigest_Handle_t)digestHandle,
               dataSize);
}

static OS_Error_t
Digest_finalize(
    void*   ctx,
    void*   digestHandle,
    void*   digest,
    size_t* digestSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(digest);
    CHECK_PTR_NOT_NULL(digestSize);
    CHECK_VALUE_IN_CLOSED_INTERVAL(*digestSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    if ((err = self->rpc.Digest_finalize(
                   (OS_CryptoDigest_Handle_t)digestHandle,
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
    void**                         pSigHandle,
    const void*                    prvKeyHandle,
    const void*                    pubKeyHandle,
    const OS_CryptoSignature_Alg_t algorithm,
    const OS_CryptoDigest_Alg_t    digest)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Signature_init(
               (OS_CryptoSignature_Handle_t*)pSigHandle,
               (OS_CryptoKey_Handle_t)prvKeyHandle,
               (OS_CryptoKey_Handle_t)pubKeyHandle,
               algorithm,
               digest);
}

static OS_Error_t
Signature_free(
    void* ctx,
    void* sigHandle)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Signature_free(
               (OS_CryptoSignature_Handle_t)sigHandle);
}

static OS_Error_t
Signature_sign(
    void*        ctx,
    void*        sigHandle,
    const void*  hash,
    const size_t hashSize,
    void*        signature,
    size_t*      signatureSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(hash);
    CHECK_PTR_NOT_NULL(signature);
    CHECK_PTR_NOT_NULL(signatureSize);
    CHECK_VALUE_IN_CLOSED_INTERVAL(hashSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));
    CHECK_VALUE_IN_CLOSED_INTERVAL(*signatureSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), hash, hashSize);

    if ((err = self->rpc.Signature_sign(
                   (OS_CryptoSignature_Handle_t)sigHandle,
                   hashSize,
                   signatureSize)) == OS_SUCCESS)
    {
        memcpy(signature, OS_Dataport_getBuf(self->rpc.dataport), *signatureSize);
    }

    return err;
}

static OS_Error_t
Signature_verify(
    void*        ctx,
    void*        sigHandle,
    const void*  hash,
    const size_t hashSize,
    const void*  signature,
    const size_t signatureSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(hash);
    CHECK_PTR_NOT_NULL(signature);
    CHECK_VALUE_IN_CLOSED_INTERVAL(hashSize + signatureSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), hash, hashSize);
    memcpy(OS_Dataport_getBuf(self->rpc.dataport) + hashSize, signature,
           signatureSize);

    return self->rpc.Signature_verify(
               (OS_CryptoSignature_Handle_t)sigHandle,
               hashSize,
               signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static OS_Error_t
Agreement_init(
    void*                          ctx,
    void**                         pAgrHandle,
    const void*                    prvKeyHandle,
    const OS_CryptoAgreement_Alg_t algorithm)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Agreement_init(
               (OS_CryptoAgreement_Handle_t*)pAgrHandle,
               (OS_CryptoKey_Handle_t)prvKeyHandle,
               algorithm);
}

static OS_Error_t
Agreement_free(
    void* ctx,
    void* agrHandle)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Agreement_free(
               (OS_CryptoAgreement_Handle_t)agrHandle);
}

static OS_Error_t
Agreement_agree(
    void*       ctx,
    void*       agrHandle,
    const void* pubKeyHandle,
    void*       shared,
    size_t*     sharedSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(shared);
    CHECK_PTR_NOT_NULL(sharedSize);
    CHECK_VALUE_IN_CLOSED_INTERVAL(*sharedSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    if ((err = self->rpc.Agreement_agree(
                   (OS_CryptoAgreement_Handle_t)agrHandle,
                   (OS_CryptoKey_Handle_t)pubKeyHandle,
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
    void**                     pKeyHandle,
    const OS_CryptoKey_Spec_t* spec)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(spec);

    Debug_ASSERT(sizeof(OS_CryptoKey_Spec_t) <= OS_Dataport_getSize(
                     self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), spec,
           sizeof(OS_CryptoKey_Spec_t));

    return self->rpc.Key_generate(
               (OS_CryptoKey_Handle_t*)pKeyHandle);
}

static OS_Error_t
Key_makePublic(
    void*                        ctx,
    void**                       pPubKeyHandle,
    const void*                  prvKeyHandle,
    const OS_CryptoKey_Attrib_t* attribs)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(attribs);

    Debug_ASSERT(sizeof(OS_CryptoKey_Attrib_t) <= OS_Dataport_getSize(
                     self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), attribs,
           sizeof(OS_CryptoKey_Attrib_t));

    return self->rpc.Key_makePublic(
               (OS_CryptoKey_Handle_t*)pPubKeyHandle,
               (OS_CryptoKey_Handle_t)prvKeyHandle);
}

static OS_Error_t
Key_import(
    void*                      ctx,
    void**                     pKeyHandle,
    const OS_CryptoKey_Data_t* keyData)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(keyData);

    Debug_ASSERT(sizeof(OS_CryptoKey_Data_t) <= OS_Dataport_getSize(
                     self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), keyData,
           sizeof(OS_CryptoKey_Data_t));

    return self->rpc.Key_import(
               (OS_CryptoKey_Handle_t*)pKeyHandle);
}

static OS_Error_t
Key_export(
    void*                ctx,
    const void*          keyHandle,
    OS_CryptoKey_Data_t* keyData)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    OS_Error_t err = OS_ERROR_GENERIC;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(keyData);

    Debug_ASSERT(sizeof(OS_CryptoKey_Data_t) <= OS_Dataport_getSize(
                     self->rpc.dataport));

    if ((err = self->rpc.Key_export(
                   (OS_CryptoKey_Handle_t)keyHandle)) == OS_SUCCESS)
    {
        memcpy(keyData, OS_Dataport_getBuf(self->rpc.dataport),
               sizeof(OS_CryptoKey_Data_t));
    }

    return err;
}

static OS_Error_t
Key_getParams(
    void*       ctx,
    const void* keyHandle,
    void*       keyParams,
    size_t*     paramSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    OS_Error_t err = OS_ERROR_GENERIC;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(keyParams);
    CHECK_PTR_NOT_NULL(paramSize);
    CHECK_VALUE_IN_CLOSED_INTERVAL(*paramSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    if ((err = self->rpc.Key_getParams(
                   (OS_CryptoKey_Handle_t)keyHandle,
                   paramSize)) == OS_SUCCESS)
    {
        memcpy(keyParams, OS_Dataport_getBuf(self->rpc.dataport), *paramSize);
    }

    return err;
}

static OS_Error_t
Key_getAttribs(
    void*                  ctx,
    const void*            keyHandle,
    OS_CryptoKey_Attrib_t* attribs)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;
    OS_Error_t err = OS_ERROR_GENERIC;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(attribs);

    Debug_ASSERT(sizeof(OS_CryptoKey_Attrib_t) <= OS_Dataport_getSize(
                     self->rpc.dataport));

    if ((err = self->rpc.Key_getAttribs(
                   (OS_CryptoKey_Handle_t)keyHandle)) == OS_SUCCESS)
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

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(keyParams);
    CHECK_PTR_NOT_NULL(paramSize);
    CHECK_VALUE_IN_CLOSED_INTERVAL(*paramSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    if ((err = self->rpc.Key_loadParams(name, paramSize)) == OS_SUCCESS)
    {
        memcpy(keyParams, OS_Dataport_getBuf(self->rpc.dataport), *paramSize);
    }

    return err;
}

static OS_Error_t
Key_free(
    void* ctx,
    void* keyHandle)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Key_free(
               (OS_CryptoKey_Handle_t)keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

static OS_Error_t
Cipher_init(
    void*                       ctx,
    void**                      pCipherHandle,
    const void*                 keyHandle,
    const OS_CryptoCipher_Alg_t algorithm,
    const void*                 iv,
    const size_t                ivSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    if (iv != NULL)
    {
        CHECK_VALUE_IN_CLOSED_INTERVAL(ivSize, 0,
                                       OS_Dataport_getSize(self->rpc.dataport));
        memcpy(OS_Dataport_getBuf(self->rpc.dataport), iv, ivSize);
    }

    return self->rpc.Cipher_init(
               (OS_CryptoCipher_Handle_t*)pCipherHandle,
               (OS_CryptoKey_Handle_t)keyHandle,
               algorithm,
               ivSize);
}

static OS_Error_t
Cipher_free(
    void* ctx,
    void* cipherHandle)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return self->rpc.Cipher_free(
               (OS_CryptoCipher_Handle_t)cipherHandle);
}

static OS_Error_t
Cipher_process(
    void*        ctx,
    void*        cipherHandle,
    const void*  input,
    const size_t inputSize,
    void*        output,
    size_t*      outputSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(input);
    CHECK_PTR_NOT_NULL(output);
    CHECK_PTR_NOT_NULL(outputSize);
    CHECK_VALUE_IN_CLOSED_INTERVAL(inputSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));
    CHECK_VALUE_IN_CLOSED_INTERVAL(*outputSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), input, inputSize);

    if ((err = self->rpc.Cipher_process(
                   (OS_CryptoCipher_Handle_t)cipherHandle,
                   inputSize,
                   outputSize)) == OS_SUCCESS)
    {
        memcpy(output, OS_Dataport_getBuf(self->rpc.dataport), *outputSize);
    }

    return err;
}

static OS_Error_t
Cipher_start(
    void*        ctx,
    void*        cipherHandle,
    const void*  data,
    const size_t dataSize)
{
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    if (NULL != data)
    {
        CHECK_VALUE_IN_CLOSED_INTERVAL(dataSize, 0,
                                       OS_Dataport_getSize(self->rpc.dataport));
        memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, dataSize);
    }

    return self->rpc.Cipher_start(
               (OS_CryptoCipher_Handle_t)cipherHandle,
               dataSize);
}

static OS_Error_t
Cipher_finalize(
    void*   ctx,
    void*   cipherHandle,
    void*   tag,
    size_t* tagSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibClient_t* self = (CryptoLibClient_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(tag);
    CHECK_PTR_NOT_NULL(tagSize);
    CHECK_VALUE_IN_CLOSED_INTERVAL(*tagSize, 0,
                                   OS_Dataport_getSize(self->rpc.dataport));

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), tag, *tagSize);

    if ((err = self->rpc.Cipher_finalize(
                   (OS_CryptoCipher_Handle_t)cipherHandle,
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

    CHECK_PTR_NOT_NULL(impl);
    CHECK_PTR_NOT_NULL(memory);
    CHECK_PTR_NOT_NULL(rpc);
    CHECK_DATAPORT_SET(rpc->dataport);

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
    CHECK_PTR_NOT_NULL(self);

    self->memory.free(self);

    return OS_SUCCESS;
}