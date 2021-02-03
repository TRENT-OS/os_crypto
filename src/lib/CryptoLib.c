/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLib.h"

#include "mbedtls/platform.h"

#include "lib_macros/Check.h"

#include <string.h>

// -------------------------- defines/types/variables --------------------------

/*
 * For the API to behave similarly in all modes (RPC and local), this buffer size
 * needs to be equal to the size of a dataport, which currently is PAGE_SIZE.
 */
#define CryptoLib_SIZE_BUFFER OS_DATAPORT_DEFAULT_SIZE

struct CryptoLib
{
    OS_Crypto_Memory_t memory;
    CryptoLibRng_t* rng;
    /**
     * When we have a function that takes an input buffer and produces an output
     * buffer, we copy the inputs to this buffer internally, so the caller can
     * use the identical buffer as input/output.
     */
    uint8_t buffer[CryptoLib_SIZE_BUFFER];
};

// -------------------------------- RNG API ------------------------------------

static OS_Error_t
Rng_getBytes(
    void*                     ctx,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibRng_getBytes(self->rng, flags, buf, bufSize);
}

static OS_Error_t
Rng_reseed(
    void*        ctx,
    const void*  seed,
    const size_t seedSize)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibRng_reSeed(self->rng, seed, seedSize);
}

// -------------------------------- MAC API ------------------------------------

static OS_Error_t
Mac_init(
    void*                    ctx,
    void**                   pMacObj,
    const void*              keyObj,
    const OS_CryptoMac_Alg_t algorithm)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibMac_init(
               (CryptoLibMac_t**)pMacObj,
               (CryptoLibKey_t*)keyObj,
               algorithm,
               &self->memory);
}

static OS_Error_t
Mac_free(
    void* ctx,
    void* macObj)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibMac_free(
               (CryptoLibMac_t*)macObj,
               &self->memory);
}

static OS_Error_t
Mac_process(
    void*        ctx,
    void*        macObj,
    const void*  data,
    const size_t dataSize)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibMac_process(
               (CryptoLibMac_t*)macObj,
               data,
               dataSize);
}

static OS_Error_t
Mac_finalize(
    void*   ctx,
    void*   macObj,
    void*   mac,
    size_t* macSize)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibMac_finalize(
               (CryptoLibMac_t*)macObj,
               mac,
               macSize);
}

// ------------------------------ Digest API -----------------------------------

static OS_Error_t
Digest_init(
    void*                       ctx,
    void**                      pDigObj,
    const OS_CryptoDigest_Alg_t algorithm)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibDigest_init(
               (CryptoLibDigest_t**)pDigObj,
               algorithm,
               &self->memory);
}

static OS_Error_t
Digest_free(
    void* ctx,
    void* digObj)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibDigest_free(
               (CryptoLibDigest_t*)digObj,
               &self->memory);
}

static OS_Error_t
Digest_clone(
    void*       ctx,
    void**      pDigObj,
    const void* srcDigObj)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibDigest_clone(
               (CryptoLibDigest_t**)pDigObj,
               (CryptoLibDigest_t*)srcDigObj,
               &self->memory);
}

static OS_Error_t
Digest_process(
    void*        ctx,
    void*        digObj,
    const void*  data,
    const size_t dataSize)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibDigest_process(
               (CryptoLibDigest_t*)digObj,
               data,
               dataSize);
}

static OS_Error_t
Digest_finalize(
    void*   ctx,
    void*   digObj,
    void*   digest,
    size_t* digestSize)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibDigest_finalize(
               (CryptoLibDigest_t*)digObj,
               digest,
               digestSize);
}

// ----------------------------- Signature API ---------------------------------

static OS_Error_t
Signature_init(
    void*                          ctx,
    void**                         pSigObj,
    const void*                    prvKey,
    const void*                    pubKey,
    const OS_CryptoSignature_Alg_t algorithm,
    const OS_CryptoDigest_Alg_t    digest)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibSignature_init(
               (CryptoLibSignature_t**)pSigObj,
               (CryptoLibKey_t*)prvKey,
               (CryptoLibKey_t*)pubKey,
               algorithm,
               digest,
               &self->memory);
}

static OS_Error_t
Signature_free(
    void* ctx,
    void* sigObj)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibSignature_free(
               (CryptoLibSignature_t*)sigObj,
               &self->memory);
}

static OS_Error_t
Signature_sign(
    void*        ctx,
    void*        sigObj,
    const void*  hash,
    const size_t hashSize,
    void*        signature,
    size_t*      signatureSize)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(hash);
    CHECK_VALUE_IN_CLOSED_INTERVAL(hashSize, 0, CryptoLib_SIZE_BUFFER);

    // Make local copy of input buffer, to allow overlapping hash/signature buffers
    memcpy(self->buffer, hash, hashSize);

    return CryptoLibSignature_sign(
               (CryptoLibSignature_t*)sigObj,
               self->buffer,
               hashSize,
               signature,
               signatureSize,
               self->rng);
}

static OS_Error_t
Signature_verify(
    void*        ctx,
    void*        sigObj,
    const void*  hash,
    const size_t hashSize,
    const void*  signature,
    const size_t signatureSize)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibSignature_verify(
               (CryptoLibSignature_t*)sigObj,
               hash,
               hashSize,
               signature,
               signatureSize,
               self->rng);
}

// ----------------------------- Agreement API ---------------------------------

static OS_Error_t
Agreement_init(
    void*                          ctx,
    void**                         pAgrObj,
    const void*                    prvKey,
    const OS_CryptoAgreement_Alg_t algorithm)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibAgreement_init(
               (CryptoLibAgreement_t**)pAgrObj,
               (CryptoLibKey_t*)prvKey,
               algorithm,
               &self->memory);
}

static OS_Error_t
Agreement_free(
    void* ctx,
    void* agrObj)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibAgreement_free(
               (CryptoLibAgreement_t*)agrObj,
               &self->memory);
}

static OS_Error_t
Agreement_agree(
    void*       ctx,
    void*       agrObj,
    const void* pubKey,
    void*       shared,
    size_t*     sharedSize)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibAgreement_agree(
               (CryptoLibAgreement_t*)agrObj,
               (CryptoLibKey_t*)pubKey,
               shared,
               sharedSize,
               self->rng);
}

// -------------------------------- Key API ------------------------------------

static OS_Error_t
Key_generate(
    void*                      ctx,
    void**                     pKeyObj,
    const OS_CryptoKey_Spec_t* spec)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibKey_generate(
               (CryptoLibKey_t**)pKeyObj,
               spec,
               &self->memory,
               self->rng);
}

static OS_Error_t
Key_import(
    void*                      ctx,
    void**                     pKeyObj,
    const OS_CryptoKey_Data_t* keyData)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibKey_import(
               (CryptoLibKey_t**)pKeyObj,
               keyData,
               &self->memory);
}

static OS_Error_t
Key_makePublic(
    void*                        ctx,
    void**                       pPubKeyObj,
    const void*                  prvKeyObj,
    const OS_CryptoKey_Attrib_t* attribs)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibKey_makePublic(
               (CryptoLibKey_t**)pPubKeyObj,
               (CryptoLibKey_t*)prvKeyObj,
               attribs,
               &self->memory,
               self->rng);
}

static OS_Error_t
Key_free(
    void* ctx,
    void* keyObj)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibKey_free(
               (CryptoLibKey_t*)keyObj,
               &self->memory);
}

static OS_Error_t
Key_export(
    void*                ctx,
    const void*          keyObj,
    OS_CryptoKey_Data_t* keyData)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibKey_export(
               (CryptoLibKey_t*)keyObj,
               keyData);
}

static OS_Error_t
Key_getParams(
    void*       ctx,
    const void* keyObj,
    void*       keyParams,
    size_t*     paramSize)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibKey_getParams(
               (CryptoLibKey_t*)keyObj,
               keyParams,
               paramSize);
}

static OS_Error_t
Key_getAttribs(
    void*                  ctx,
    const void*            keyObj,
    OS_CryptoKey_Attrib_t* attribs)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibKey_getAttribs(
               (CryptoLibKey_t*)keyObj,
               attribs);
}

static OS_Error_t
Key_loadParams(
    void*                      ctx,
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibKey_loadParams(name, keyParams, paramSize);
}

// ------------------------------ Cipher API -----------------------------------

static OS_Error_t
Cipher_init(
    void*                       ctx,
    void**                      pCipherObj,
    const void*                 key,
    const OS_CryptoCipher_Alg_t algorithm,
    const void*                 iv,
    const size_t                ivSize)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibCipher_init(
               (CryptoLibCipher_t**)pCipherObj,
               (CryptoLibKey_t*)key,
               algorithm,
               iv,
               ivSize,
               &self->memory);

}

static OS_Error_t
Cipher_free(
    void* ctx,
    void* cipherObj)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibCipher_free(
               (CryptoLibCipher_t*)cipherObj,
               &self->memory);
}

static OS_Error_t
Cipher_process(
    void*        ctx,
    void*        cipherObj,
    const void*  input,
    const size_t inputSize,
    void*        output,
    size_t*      outputSize)
{
    CryptoLib_t* self = (CryptoLib_t*) ctx;

    CHECK_PTR_NOT_NULL(ctx);
    CHECK_PTR_NOT_NULL(input);
    CHECK_VALUE_IN_CLOSED_INTERVAL(inputSize, 0, CryptoLib_SIZE_BUFFER);

    // Make local copy of input buffer, to allow overlapping input/output buffers
    memcpy(self->buffer, input, inputSize);

    return CryptoLibCipher_process(
               (CryptoLibCipher_t*)cipherObj,
               self->buffer,
               inputSize,
               output,
               outputSize);
}

static OS_Error_t
Cipher_start(
    void*        ctx,
    void*        cipherObj,
    const void*  ad,
    const size_t adSize)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibCipher_start(
               (CryptoLibCipher_t*)cipherObj,
               ad,
               adSize);
}

static OS_Error_t
Cipher_finalize(
    void*   ctx,
    void*   cipherObj,
    void*   output,
    size_t* outputSize)
{
    CHECK_PTR_NOT_NULL(ctx);

    return CryptoLibCipher_finalize(
               (CryptoLibCipher_t*)cipherObj,
               output,
               outputSize);
}

// ------------------------------- init/free -----------------------------------

static const Crypto_Vtable_t CryptoLib_vtable =
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
CryptoLib_init(
    Crypto_Impl_t*            impl,
    const OS_Crypto_Memory_t* memory,
    const if_OS_Entropy_t*    entropy)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLib_t* self;

    CHECK_PTR_NOT_NULL(impl);
    CHECK_PTR_NOT_NULL(memory);
    CHECK_PTR_NOT_NULL(entropy->read);
    CHECK_DATAPORT_SET(entropy->dataport);

    // Make sure mbedtls uses our own calloc/free functions; this can be set
    // multiple times (e.g., in case we have several parallel instances of the
    // Crypto API).
    if (mbedtls_platform_set_calloc_free(memory->calloc, memory->free) != 0)
    {
        return OS_ERROR_ABORTED;
    }

    if ((self = memory->calloc(1, sizeof(CryptoLib_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    impl->context = self;
    impl->vtable  = &CryptoLib_vtable;
    self->memory  = *memory;

    if ((err = CryptoLibRng_init(&self->rng, entropy, &self->memory)) != OS_SUCCESS)
    {
        goto err;
    }

    return OS_SUCCESS;

err:
    memory->free(self);

    return err;
}

OS_Error_t
CryptoLib_free(
    CryptoLib_t* self)
{
    CHECK_PTR_NOT_NULL(self);

    CryptoLibRng_free(self->rng, &self->memory);

    self->memory.free(self);

    return OS_SUCCESS;
}
