/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoCtx.h"
#include "SeosCryptoApi.h"
#include "SeosCryptoLib.h"

seos_err_t
SeosCryptoApi_free(
    SeosCryptoApi_Context* ctx)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER : ctx->vtable->free(ctx);
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoApi_Rng_getBytes(
    SeosCryptoApi_Context*       ctx,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize)
{
    if (bufSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Rng_getBytes(ctx, flags, buf, bufSize);
}

seos_err_t
SeosCryptoApi_Rng_reseed(
    SeosCryptoApi_Context* ctx,
    const void*            seed,
    const size_t           seedLen)
{
    if (seedLen > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Rng_reseed(ctx, seed, seedLen);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
SeosCryptoApi_Mac_init(
    SeosCryptoApi_Context*      ctx,
    SeosCryptoApi_Mac*          pMacHandle,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Mac_init(ctx, pMacHandle, algorithm);
}

seos_err_t
SeosCryptoApi_Mac_free(
    SeosCryptoApi_Context*  ctx,
    const SeosCryptoApi_Mac macHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Mac_free(ctx, macHandle);
}

seos_err_t
SeosCryptoApi_Mac_start(
    SeosCryptoApi_Context*  ctx,
    const SeosCryptoApi_Mac macHandle,
    const void*             secret,
    const size_t            secretSize)
{
    if (secretSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Mac_start(ctx, macHandle, secret, secretSize);
}

seos_err_t
SeosCryptoApi_Mac_process(
    SeosCryptoApi_Context*  ctx,
    const SeosCryptoApi_Mac macHandle,
    const void*             data,
    const size_t            dataSize)
{
    if (dataSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Mac_process(ctx, macHandle, data, dataSize);
}

seos_err_t
SeosCryptoApi_Mac_finalize(
    SeosCryptoApi_Context*  ctx,
    const SeosCryptoApi_Mac macHandle,
    void*                   mac,
    size_t*                 macSize)
{
    if (NULL != macSize && *macSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Mac_finalize(ctx, macHandle, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoApi_Digest_init(
    SeosCryptoApi_Context*         ctx,
    SeosCryptoApi_Digest*          pDigestHandle,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Digest_init(ctx, pDigestHandle, algorithm);
}

seos_err_t
SeosCryptoApi_Digest_free(
    SeosCryptoApi_Context*     ctx,
    const SeosCryptoApi_Digest digestHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Digest_free(ctx, digestHandle);
}

seos_err_t
SeosCryptoApi_Digest_clone(
    SeosCryptoApi_Context*     ctx,
    const SeosCryptoApi_Digest dstDigHandle,
    const SeosCryptoApi_Digest srcDigHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Digest_clone(ctx, dstDigHandle, srcDigHandle);
}

seos_err_t
SeosCryptoApi_Digest_process(
    SeosCryptoApi_Context*     ctx,
    const SeosCryptoApi_Digest digestHandle,
    const void*                data,
    const size_t               dataLen)
{
    if (dataLen > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Digest_process(ctx, digestHandle, data, dataLen);
}

seos_err_t
SeosCryptoApi_Digest_finalize(
    SeosCryptoApi_Context*     ctx,
    const SeosCryptoApi_Digest digestHandle,
    void*                      digest,
    size_t*                    digestSize)
{
    if (NULL != digestSize && *digestSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Digest_finalize(ctx, digestHandle, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoApi_Signature_init(
    SeosCryptoApi_Context*            ctx,
    SeosCryptoApi_Signature*          pSigHandle,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoApi_Key           prvHandle,
    const SeosCryptoApi_Key           pubHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Signature_init(ctx, pSigHandle, algorithm, digest, prvHandle,
                                       pubHandle);
}

seos_err_t
SeosCryptoApi_Signature_free(
    SeosCryptoApi_Context*        ctx,
    const SeosCryptoApi_Signature sigHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Signature_free(ctx, sigHandle);
}

seos_err_t
SeosCryptoApi_Signature_sign(
    SeosCryptoApi_Context*        ctx,
    const SeosCryptoApi_Signature sigHandle,
    const void*                   hash,
    const size_t                  hashSize,
    void*                         signature,
    size_t*                       signatureSize)
{
    // They use the same buffer, but sequentially
    if (hashSize > SeosCryptoLib_SIZE_BUFFER
        || (NULL != signatureSize && *signatureSize > SeosCryptoLib_SIZE_BUFFER))
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Signature_sign(ctx, sigHandle, hash, hashSize, signature,
                                       signatureSize);
}

seos_err_t
SeosCryptoApi_Signature_verify(
    SeosCryptoApi_Context*        ctx,
    const SeosCryptoApi_Signature sigHandle,
    const void*                   hash,
    const size_t                  hashSize,
    const void*                   signature,
    const size_t                  signatureSize)
{
    // They use the same buffer, but in parallel
    if (hashSize + signatureSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Signature_verify(ctx, sigHandle, hash, hashSize, signature,
                                         signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoApi_Agreement_init(
    SeosCryptoApi_Context*            ctx,
    SeosCryptoApi_Agreement*          pAgrHandle,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoApi_Key           prvHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Agreement_init(ctx, pAgrHandle, algorithm, prvHandle);
}

seos_err_t
SeosCryptoApi_Agreement_free(
    SeosCryptoApi_Context*        ctx,
    const SeosCryptoApi_Agreement agrHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Agreement_free(ctx, agrHandle);
}

seos_err_t
SeosCryptoApi_Agreement_agree(
    SeosCryptoApi_Context*        ctx,
    const SeosCryptoApi_Agreement agrHandle,
    const SeosCryptoApi_Key       pubHandle,
    void*                         shared,
    size_t*                       sharedSize)
{
    if (NULL != sharedSize && *sharedSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Agreement_agree(ctx, agrHandle, pubHandle, shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoApi_Key_generate(
    SeosCryptoApi_Context*        ctx,
    SeosCryptoApi_Key*            pKeyHandle,
    const SeosCryptoApi_Key_Spec* spec)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Key_generate(ctx, pKeyHandle, spec);
}

seos_err_t
SeosCryptoApi_Key_makePublic(
    SeosCryptoApi_Context*           ctx,
    SeosCryptoApi_Key*               pPubHandle,
    const SeosCryptoApi_Key          prvKeyHandle,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Key_makePublic(ctx, pPubHandle, prvKeyHandle, attribs);
}

seos_err_t
SeosCryptoApi_Key_import(
    SeosCryptoApi_Context*        ctx,
    SeosCryptoApi_Key*            pKeyHandle,
    const SeosCryptoApi_Key       wrapKeyHandle,
    const SeosCryptoApi_Key_Data* keyData)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Key_import(ctx, pKeyHandle, wrapKeyHandle, keyData);
}

seos_err_t
SeosCryptoApi_Key_export(
    SeosCryptoApi_Context*  ctx,
    const SeosCryptoApi_Key keyHandle,
    const SeosCryptoApi_Key wrapKeyHandle,
    SeosCryptoApi_Key_Data* keyData)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Key_export(ctx, keyHandle, wrapKeyHandle, keyData);
}

seos_err_t
SeosCryptoApi_Key_getParams(
    SeosCryptoApi_Context*  ctx,
    const SeosCryptoApi_Key keyHandle,
    void*                   keyParams,
    size_t*                 paramSize)
{
    if (NULL != paramSize && *paramSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Key_getParams(ctx, keyHandle, keyParams, paramSize);
}

seos_err_t
SeosCryptoApi_Key_loadParams(
    SeosCryptoApi_Context*        ctx,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize)
{
    if (NULL != paramSize && *paramSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Key_loadParams(ctx, name, keyParams, paramSize);
}

seos_err_t
SeosCryptoApi_Key_free(
    SeosCryptoApi_Context*  ctx,
    const SeosCryptoApi_Key keyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Key_free(ctx, keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoApi_Cipher_init(
    SeosCryptoApi_Context*         ctx,
    SeosCryptoApi_Cipher*          pCipherHandle,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoApi_Key        keyHandle,
    const void*                    iv,
    const size_t                   ivLen)
{
    if (ivLen > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Cipher_init(ctx, pCipherHandle, algorithm, keyHandle, iv, ivLen);
}

seos_err_t
SeosCryptoApi_Cipher_free(
    SeosCryptoApi_Context*     ctx,
    const SeosCryptoApi_Cipher cipherHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Cipher_free(ctx, cipherHandle);
}

seos_err_t
SeosCryptoApi_Cipher_process(
    SeosCryptoApi_Context*     ctx,
    const SeosCryptoApi_Cipher cipherHandle,
    const void*                data,
    const size_t               dataSize,
    void*                      output,
    size_t*                    outputSize)
{
    // They use the same buffer, but sequentially
    if (dataSize > SeosCryptoLib_SIZE_BUFFER ||
        (NULL != outputSize && *outputSize > SeosCryptoLib_SIZE_BUFFER))
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Cipher_process(ctx, cipherHandle, data, dataSize, output,
                                       outputSize);
}

seos_err_t
SeosCryptoApi_Cipher_start(
    SeosCryptoApi_Context*     ctx,
    const SeosCryptoApi_Cipher cipherHandle,
    const void*                ad,
    const size_t               adLen)
{
    if (adLen > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Cipher_start(ctx, cipherHandle, ad, adLen);
}

seos_err_t
SeosCryptoApi_Cipher_finalize(
    SeosCryptoApi_Context*     ctx,
    const SeosCryptoApi_Cipher cipherHandle,
    void*                      output,
    size_t*                    outputSize)
{
    if (NULL != outputSize && *outputSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->Cipher_finalize(ctx, cipherHandle, output, outputSize);
}