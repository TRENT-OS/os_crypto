/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoCtx.h"
#include "SeosCryptoApi.h"

void
SeosCryptoApi_free(SeosCryptoCtx* ctx)
{
    Debug_ASSERT_SELF(ctx);
    ctx->vtable->free(ctx);
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoApi_rngGetBytes(SeosCryptoCtx*    ctx,
                          unsigned int      flags,
                          void*             buf,
                          const size_t      bufSize)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->rngGetBytes(ctx, flags, buf, bufSize);
}

seos_err_t
SeosCryptoApi_rngReSeed(SeosCryptoCtx*      ctx,
                        const void*         seed,
                        const size_t        seedLen)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->rngReSeed(ctx, seed, seedLen);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoApi_digestInit(SeosCryptoCtx*              ctx,
                         SeosCrypto_DigestHandle*    pDigestHandle,
                         const unsigned int          algorithm)
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
SeosCryptoApi_digestUpdate(SeosCryptoCtx*                   ctx,
                           const SeosCrypto_DigestHandle    digestHandle,
                           const void*                      data,
                           const size_t                     dataLen)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestUpdate(ctx, digestHandle, data, dataLen);
}

seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoCtx*                 ctx,
                             const SeosCrypto_DigestHandle  digestHandle,
                             void*                          digest,
                             size_t*                        digestSize)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->digestFinalize(ctx, digestHandle, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoApi_signatureInit(SeosCryptoCtx*                ctx,
                            SeosCrypto_SignatureHandle*   pSigHandle,
                            const unsigned int            algorithm,
                            const SeosCrypto_KeyHandle    prvHandle,
                            const SeosCrypto_KeyHandle    pubHandle)
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
    return (NULL == ctx || NULL == signature) ? SEOS_ERROR_INVALID_PARAMETER :
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
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->signatureVerify(ctx, sigHandle, hash, hashSize, signature,
                                        signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoApi_agreementInit(SeosCryptoCtx*                  ctx,
                            SeosCrypto_AgreementHandle*     pAgrHandle,
                            const unsigned int              algorithm,
                            const SeosCrypto_KeyHandle      prvHandle)
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
    return (NULL == ctx || NULL == shared) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->agreementAgree(ctx, agrHandle, pubHandle, shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoApi_keyInit(SeosCryptoCtx*                   ctx,
                      SeosCrypto_KeyHandle*            keyHandle,
                      const unsigned int               type,
                      const SeosCryptoKey_Flags        flags,
                      const size_t                     bits)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyInit(ctx, keyHandle, type, flags, bits);
}

seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoCtx*               ctx,
                          const SeosCrypto_KeyHandle   keyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyGenerate(ctx, keyHandle);
}

seos_err_t
SeosCryptoApi_keyGeneratePair(SeosCryptoCtx*                ctx,
                              const SeosCrypto_KeyHandle    prvKeyHandle,
                              const SeosCrypto_KeyHandle    pubKeyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyGeneratePair(ctx, prvKeyHandle, pubKeyHandle);
}

seos_err_t
SeosCryptoApi_keyImport(SeosCryptoCtx*                 ctx,
                        const SeosCrypto_KeyHandle     keyHandle,
                        const SeosCrypto_KeyHandle     wrapKeyHandle,
                        const void*                    key,
                        const size_t                   keyLen)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyImport(ctx, keyHandle, wrapKeyHandle, key, keyLen);
}

seos_err_t
SeosCryptoApi_keyExport(SeosCryptoCtx*                 ctx,
                        const SeosCrypto_KeyHandle     keyHandle,
                        const SeosCrypto_KeyHandle     wrapKeyHandle,
                        void*                          key,
                        size_t*                        keySize)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyExport(ctx, keyHandle, wrapKeyHandle, key, keySize);
}

seos_err_t
SeosCryptoApi_keyFree(SeosCryptoCtx*                 ctx,
                      const SeosCrypto_KeyHandle     keyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyFree(ctx, keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoCtx*             ctx,
                         SeosCrypto_CipherHandle*   pCipherHandle,
                         const unsigned int         algorithm,
                         const SeosCrypto_KeyHandle keyHandle,
                         const void*                iv,
                         const size_t               ivLen)
{
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
SeosCryptoApi_cipherUpdate(SeosCryptoCtx*                   ctx,
                           const SeosCrypto_CipherHandle    cipherHandle,
                           const void*                      data,
                           const size_t                     dataLen,
                           void*                            output,
                           size_t*                          outputSize)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherUpdate(ctx, cipherHandle, data, dataLen, output, outputSize);
}

seos_err_t
SeosCryptoApi_cipherStart(SeosCryptoCtx*                ctx,
                          const SeosCrypto_CipherHandle cipherHandle,
                          const void*                   ad,
                          const size_t                  adLen)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherStart(ctx, cipherHandle, ad, adLen);
}

seos_err_t
SeosCryptoApi_cipherFinalize(SeosCryptoCtx*                 ctx,
                             const SeosCrypto_CipherHandle  cipherHandle,
                             void*                          output,
                             size_t*                        outputSize)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->cipherFinalize(ctx, cipherHandle, output, outputSize);
}