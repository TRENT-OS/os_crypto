/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoCtx.h"
#include "SeosCryptoApi.h"
#include "SeosCrypto_Impl.h"

seos_err_t
SeosCryptoApi_free(SeosCryptoCtx* ctx)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER : ctx->vtable->free(ctx);
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoApi_rngGetBytes(SeosCryptoCtx*            ctx,
                          const SeosCryptoRng_Flags flags,
                          void*                     buf,
                          const size_t              bufSize)
{
    if (bufSize > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->rngGetBytes(ctx, flags, buf, bufSize);
}

seos_err_t
SeosCryptoApi_rngReSeed(SeosCryptoCtx*      ctx,
                        const void*         seed,
                        const size_t        seedLen)
{
    if (seedLen > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->rngReSeed(ctx, seed, seedLen);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
SeosCryptoApi_macInit(SeosCryptoCtx*                    ctx,
                      SeosCrypto_MacHandle*             pMacHandle,
                      const SeosCryptoMac_Algorithm     algorithm)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoApi_macFree(SeosCryptoCtx*                ctx,
                      const SeosCrypto_MacHandle    macHandle)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoApi_macStart(SeosCryptoCtx*               ctx,
                       const SeosCrypto_MacHandle   macHandle,
                       const void*                  secret,
                       const size_t                 secretSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoApi_macProcess(SeosCryptoCtx*             ctx,
                         const SeosCrypto_MacHandle macHandle,
                         const void*                data,
                         const size_t               dataSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoApi_macFinalize(SeosCryptoCtx*                ctx,
                          const SeosCrypto_MacHandle    macHandle,
                          void*                         mac,
                          size_t*                       macSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoApi_digestInit(SeosCryptoCtx*                     ctx,
                         SeosCrypto_DigestHandle*           pDigestHandle,
                         const SeosCryptoDigest_Algorithm   algorithm)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestInit(ctx, pDigestHandle, algorithm);
}

seos_err_t
SeosCryptoApi_digestFree(SeosCryptoCtx*                 ctx,
                         const SeosCrypto_DigestHandle  digestHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestFree(ctx, digestHandle);
}

seos_err_t
SeosCryptoApi_digestProcess(SeosCryptoCtx*                   ctx,
                            const SeosCrypto_DigestHandle    digestHandle,
                            const void*                      data,
                            const size_t                     dataLen)
{
    if (dataLen > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestProcess(ctx, digestHandle, data, dataLen);
}

seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoCtx*                 ctx,
                             const SeosCrypto_DigestHandle  digestHandle,
                             void*                          digest,
                             size_t*                        digestSize)
{
    if (NULL != digestSize && *digestSize > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestFinalize(ctx, digestHandle, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoApi_signatureInit(SeosCryptoCtx*                      ctx,
                            SeosCrypto_SignatureHandle*         pSigHandle,
                            const SeosCryptoSignature_Algorithm algorithm,
                            const SeosCrypto_KeyHandle          prvHandle,
                            const SeosCrypto_KeyHandle          pubHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->signatureInit(ctx, pSigHandle, algorithm, prvHandle, pubHandle);
}

seos_err_t
SeosCryptoApi_signatureFree(SeosCryptoCtx*                      ctx,
                            const SeosCrypto_SignatureHandle    sigHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->signatureFree(ctx, sigHandle);
}

seos_err_t
SeosCryptoApi_signatureSign(SeosCryptoCtx*                      ctx,
                            const SeosCrypto_SignatureHandle    sigHandle,
                            const void*                         hash,
                            const size_t                        hashSize,
                            void*                               signature,
                            size_t*                             signatureSize)
{
    // They use the same buffer, but sequentially
    if (hashSize > SeosCrypto_Size_BUFFER
        || (NULL != signatureSize && *signatureSize > SeosCrypto_Size_BUFFER))
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->signatureSign(ctx, sigHandle, hash, hashSize, signature,
                                      signatureSize);
}

seos_err_t
SeosCryptoApi_signatureVerify(SeosCryptoCtx*                    ctx,
                              const SeosCrypto_SignatureHandle  sigHandle,
                              const void*                       hash,
                              const size_t                      hashSize,
                              const void*                       signature,
                              const size_t                      signatureSize)
{
    // They use the same buffer, but in parallel
    if (hashSize + signatureSize > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->signatureVerify(ctx, sigHandle, hash, hashSize, signature,
                                        signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoApi_agreementInit(SeosCryptoCtx*                          ctx,
                            SeosCrypto_AgreementHandle*             pAgrHandle,
                            const SeosCryptoAgreement_Algorithm     algorithm,
                            const SeosCrypto_KeyHandle              prvHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->agreementInit(ctx, pAgrHandle, algorithm, prvHandle);
}

seos_err_t
SeosCryptoApi_agreementFree(SeosCryptoCtx*                      ctx,
                            const SeosCrypto_AgreementHandle    agrHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->agreementFree(ctx, agrHandle);
}

seos_err_t
SeosCryptoApi_agreementAgree(SeosCryptoCtx*                     ctx,
                             const SeosCrypto_AgreementHandle   agrHandle,
                             const SeosCrypto_KeyHandle         pubHandle,
                             void*                              shared,
                             size_t*                            sharedSize)
{
    if (NULL != sharedSize && *sharedSize > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->agreementAgree(ctx, agrHandle, pubHandle, shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoCtx*            ctx,
                          SeosCrypto_KeyHandle*     pKeyHandle,
                          const SeosCryptoKey_Spec* spec)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyGenerate(ctx, pKeyHandle, spec);
}

seos_err_t
SeosCryptoApi_keyMakePublic(SeosCryptoCtx*                  ctx,
                            SeosCrypto_KeyHandle*           pPubHandle,
                            const SeosCrypto_KeyHandle      prvKeyHandle,
                            const SeosCryptoKey_Attribs*    attribs)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyMakePublic(ctx, pPubHandle, prvKeyHandle, attribs);
}

seos_err_t
SeosCryptoApi_keyImport(SeosCryptoCtx*              ctx,
                        SeosCrypto_KeyHandle*       pKeyHandle,
                        const SeosCrypto_KeyHandle  wrapKeyHandle,
                        const SeosCryptoKey_Data*   keyData)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyImport(ctx, pKeyHandle, wrapKeyHandle, keyData);
}

seos_err_t
SeosCryptoApi_keyExport(SeosCryptoCtx*              ctx,
                        const SeosCrypto_KeyHandle  keyHandle,
                        const SeosCrypto_KeyHandle  wrapKeyHandle,
                        SeosCryptoKey_Data*         keyData)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyExport(ctx, keyHandle, wrapKeyHandle, keyData);
}

seos_err_t
SeosCryptoApi_keyGetParams(SeosCryptoCtx*               ctx,
                           const SeosCrypto_KeyHandle   keyHandle,
                           void*                        keyParams,
                           size_t*                      paramSize)
{
    if (NULL != paramSize && *paramSize > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyGetParams(ctx, keyHandle, keyParams, paramSize);
}

seos_err_t
SeosCryptoApi_keyLoadParams(SeosCryptoCtx*              ctx,
                            const SeosCryptoKey_Param   name,
                            void*                       keyParams,
                            size_t*                     paramSize)
{
    if (NULL != paramSize && *paramSize > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyLoadParams(ctx, name, keyParams, paramSize);
}

seos_err_t
SeosCryptoApi_keyFree(SeosCryptoCtx*                ctx,
                      const SeosCrypto_KeyHandle    keyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyFree(ctx, keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoCtx*                     ctx,
                         SeosCrypto_CipherHandle*           pCipherHandle,
                         const SeosCryptoCipher_Algorithm   algorithm,
                         const SeosCrypto_KeyHandle         keyHandle,
                         const void*                        iv,
                         const size_t                       ivLen)
{
    if (ivLen > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherInit(ctx, pCipherHandle, algorithm, keyHandle, iv, ivLen);
}

seos_err_t
SeosCryptoApi_cipherFree(SeosCryptoCtx*                 ctx,
                         const SeosCrypto_CipherHandle  cipherHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherFree(ctx, cipherHandle);
}

seos_err_t
SeosCryptoApi_cipherProcess(SeosCryptoCtx*                   ctx,
                            const SeosCrypto_CipherHandle    cipherHandle,
                            const void*                      data,
                            const size_t                     dataSize,
                            void*                            output,
                            size_t*                          outputSize)
{
    // They use the same buffer, but sequentially
    if (dataSize > SeosCrypto_Size_BUFFER ||
        (NULL != outputSize && *outputSize > SeosCrypto_Size_BUFFER))
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherProcess(ctx, cipherHandle, data, dataSize, output,
                                      outputSize);
}

seos_err_t
SeosCryptoApi_cipherStart(SeosCryptoCtx*                ctx,
                          const SeosCrypto_CipherHandle cipherHandle,
                          const void*                   ad,
                          const size_t                  adLen)
{
    if (adLen > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherStart(ctx, cipherHandle, ad, adLen);
}

seos_err_t
SeosCryptoApi_cipherFinalize(SeosCryptoCtx*                 ctx,
                             const SeosCrypto_CipherHandle  cipherHandle,
                             void*                          output,
                             size_t*                        outputSize)
{
    if (NULL != outputSize && *outputSize > SeosCrypto_Size_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherFinalize(ctx, cipherHandle, output, outputSize);
}