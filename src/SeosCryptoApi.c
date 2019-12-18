/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoCtx.h"
#include "SeosCryptoApi.h"
#include "SeosCryptoLib.h"

seos_err_t
SeosCryptoApi_free(SeosCryptoApi_Context* ctx)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER : ctx->vtable->free(ctx);
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoApi_rngGetBytes(SeosCryptoApi_Context*       ctx,
                          const SeosCryptoApi_Rng_Flag flags,
                          void*                        buf,
                          const size_t                 bufSize)
{
    if (bufSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->rngGetBytes(ctx, flags, buf, bufSize);
}

seos_err_t
SeosCryptoApi_rngReSeed(SeosCryptoApi_Context* ctx,
                        const void*            seed,
                        const size_t           seedLen)
{
    if (seedLen > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->rngReSeed(ctx, seed, seedLen);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
SeosCryptoApi_macInit(SeosCryptoApi_Context*      ctx,
                      SeosCryptoApi_Mac*          pMacHandle,
                      const SeosCryptoApi_Mac_Alg algorithm)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->macInit(ctx, pMacHandle, algorithm);
}

seos_err_t
SeosCryptoApi_macFree(SeosCryptoApi_Context*  ctx,
                      const SeosCryptoApi_Mac macHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->macFree(ctx, macHandle);
}

seos_err_t
SeosCryptoApi_macStart(SeosCryptoApi_Context*  ctx,
                       const SeosCryptoApi_Mac macHandle,
                       const void*             secret,
                       const size_t            secretSize)
{
    if (secretSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->macStart(ctx, macHandle, secret, secretSize);
}

seos_err_t
SeosCryptoApi_macProcess(SeosCryptoApi_Context*  ctx,
                         const SeosCryptoApi_Mac macHandle,
                         const void*             data,
                         const size_t            dataSize)
{
    if (dataSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->macProcess(ctx, macHandle, data, dataSize);
}

seos_err_t
SeosCryptoApi_macFinalize(SeosCryptoApi_Context*  ctx,
                          const SeosCryptoApi_Mac macHandle,
                          void*                   mac,
                          size_t*                 macSize)
{
    if (NULL != macSize && *macSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->macFinalize(ctx, macHandle, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoApi_digestInit(SeosCryptoApi_Context*         ctx,
                         SeosCryptoApi_Digest*          pDigestHandle,
                         const SeosCryptoApi_Digest_Alg algorithm)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestInit(ctx, pDigestHandle, algorithm);
}

seos_err_t
SeosCryptoApi_digestFree(SeosCryptoApi_Context*     ctx,
                         const SeosCryptoApi_Digest digestHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestFree(ctx, digestHandle);
}

seos_err_t
SeosCryptoApi_digestClone(SeosCryptoApi_Context*     ctx,
                          const SeosCryptoApi_Digest dstDigHandle,
                          const SeosCryptoApi_Digest srcDigHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestClone(ctx, dstDigHandle, srcDigHandle);
}

seos_err_t
SeosCryptoApi_digestProcess(SeosCryptoApi_Context*     ctx,
                            const SeosCryptoApi_Digest digestHandle,
                            const void*                data,
                            const size_t               dataLen)
{
    if (dataLen > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestProcess(ctx, digestHandle, data, dataLen);
}

seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoApi_Context*     ctx,
                             const SeosCryptoApi_Digest digestHandle,
                             void*                      digest,
                             size_t*                    digestSize)
{
    if (NULL != digestSize && *digestSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestFinalize(ctx, digestHandle, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoApi_signatureInit(SeosCryptoApi_Context*            ctx,
                            SeosCryptoApi_Signature*          pSigHandle,
                            const SeosCryptoApi_Signature_Alg algorithm,
                            const SeosCryptoApi_Digest_Alg    digest,
                            const SeosCryptoApi_Key           prvHandle,
                            const SeosCryptoApi_Key           pubHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->signatureInit(ctx, pSigHandle, algorithm, digest, prvHandle,
                                      pubHandle);
}

seos_err_t
SeosCryptoApi_signatureFree(SeosCryptoApi_Context*        ctx,
                            const SeosCryptoApi_Signature sigHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->signatureFree(ctx, sigHandle);
}

seos_err_t
SeosCryptoApi_signatureSign(SeosCryptoApi_Context*        ctx,
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
           ctx->vtable->signatureSign(ctx, sigHandle, hash, hashSize, signature,
                                      signatureSize);
}

seos_err_t
SeosCryptoApi_signatureVerify(SeosCryptoApi_Context*        ctx,
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
           ctx->vtable->signatureVerify(ctx, sigHandle, hash, hashSize, signature,
                                        signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoApi_agreementInit(SeosCryptoApi_Context*            ctx,
                            SeosCryptoApi_Agreement*          pAgrHandle,
                            const SeosCryptoApi_Agreement_Alg algorithm,
                            const SeosCryptoApi_Key           prvHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->agreementInit(ctx, pAgrHandle, algorithm, prvHandle);
}

seos_err_t
SeosCryptoApi_agreementFree(SeosCryptoApi_Context*        ctx,
                            const SeosCryptoApi_Agreement agrHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->agreementFree(ctx, agrHandle);
}

seos_err_t
SeosCryptoApi_agreementAgree(SeosCryptoApi_Context*        ctx,
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
           ctx->vtable->agreementAgree(ctx, agrHandle, pubHandle, shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoApi_Context*        ctx,
                          SeosCryptoApi_Key*            pKeyHandle,
                          const SeosCryptoApi_Key_Spec* spec)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyGenerate(ctx, pKeyHandle, spec);
}

seos_err_t
SeosCryptoApi_keyMakePublic(SeosCryptoApi_Context*           ctx,
                            SeosCryptoApi_Key*               pPubHandle,
                            const SeosCryptoApi_Key          prvKeyHandle,
                            const SeosCryptoApi_Key_Attribs* attribs)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyMakePublic(ctx, pPubHandle, prvKeyHandle, attribs);
}

seos_err_t
SeosCryptoApi_keyImport(SeosCryptoApi_Context*        ctx,
                        SeosCryptoApi_Key*            pKeyHandle,
                        const SeosCryptoApi_Key       wrapKeyHandle,
                        const SeosCryptoApi_Key_Data* keyData)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyImport(ctx, pKeyHandle, wrapKeyHandle, keyData);
}

seos_err_t
SeosCryptoApi_keyExport(SeosCryptoApi_Context*  ctx,
                        const SeosCryptoApi_Key keyHandle,
                        const SeosCryptoApi_Key wrapKeyHandle,
                        SeosCryptoApi_Key_Data* keyData)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyExport(ctx, keyHandle, wrapKeyHandle, keyData);
}

seos_err_t
SeosCryptoApi_keyGetParams(SeosCryptoApi_Context*  ctx,
                           const SeosCryptoApi_Key keyHandle,
                           void*                   keyParams,
                           size_t*                 paramSize)
{
    if (NULL != paramSize && *paramSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyGetParams(ctx, keyHandle, keyParams, paramSize);
}

seos_err_t
SeosCryptoApi_keyLoadParams(SeosCryptoApi_Context*        ctx,
                            const SeosCryptoApi_Key_Param name,
                            void*                         keyParams,
                            size_t*                       paramSize)
{
    if (NULL != paramSize && *paramSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyLoadParams(ctx, name, keyParams, paramSize);
}

seos_err_t
SeosCryptoApi_keyFree(SeosCryptoApi_Context*  ctx,
                      const SeosCryptoApi_Key keyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyFree(ctx, keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoApi_Context*         ctx,
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
           ctx->vtable->cipherInit(ctx, pCipherHandle, algorithm, keyHandle, iv, ivLen);
}

seos_err_t
SeosCryptoApi_cipherFree(SeosCryptoApi_Context*     ctx,
                         const SeosCryptoApi_Cipher cipherHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherFree(ctx, cipherHandle);
}

seos_err_t
SeosCryptoApi_cipherProcess(SeosCryptoApi_Context*     ctx,
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
           ctx->vtable->cipherProcess(ctx, cipherHandle, data, dataSize, output,
                                      outputSize);
}

seos_err_t
SeosCryptoApi_cipherStart(SeosCryptoApi_Context*     ctx,
                          const SeosCryptoApi_Cipher cipherHandle,
                          const void*                ad,
                          const size_t               adLen)
{
    if (adLen > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherStart(ctx, cipherHandle, ad, adLen);
}

seos_err_t
SeosCryptoApi_cipherFinalize(SeosCryptoApi_Context*     ctx,
                             const SeosCryptoApi_Cipher cipherHandle,
                             void*                      output,
                             size_t*                    outputSize)
{
    if (NULL != outputSize && *outputSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherFinalize(ctx, cipherHandle, output, outputSize);
}