/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoCtx.h"
#include "SeosCryptoApi.h"

void
SeosCryptoApi_free(SeosCryptoCtx* cryptoCtx)
{
    Debug_ASSERT_SELF(cryptoCtx);
    cryptoCtx->vtable->free(cryptoCtx);
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoApi_rngGetBytes(SeosCryptoCtx*    cryptoCtx,
                          unsigned int      flags,
                          void*             buf,
                          size_t            bufSize)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->rngGetBytes(cryptoCtx, flags, buf, bufSize);
}

seos_err_t
SeosCryptoApi_rngReSeed(SeosCryptoCtx*      cryptoCtx,
                        const void*         seed,
                        size_t              seedLen)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->rngReSeed(cryptoCtx, seed, seedLen);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoApi_digestInit(SeosCryptoCtx*              cryptoCtx,
                         SeosCrypto_DigestHandle*    pDigestHandle,
                         unsigned int                algorithm)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->digestInit(cryptoCtx, pDigestHandle, algorithm);
}

seos_err_t
SeosCryptoApi_digestFree(SeosCryptoCtx*             cryptoCtx,
                         SeosCrypto_DigestHandle    digestHandle)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->digestFree(cryptoCtx, digestHandle);
}

seos_err_t
SeosCryptoApi_digestUpdate(SeosCryptoCtx*            cryptoCtx,
                           SeosCrypto_DigestHandle   digestHandle,
                           const void*               data,
                           size_t                    dataLen)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->digestUpdate(cryptoCtx, digestHandle, data, dataLen);
}

seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoCtx*              cryptoCtx,
                             SeosCrypto_DigestHandle     digestHandle,
                             void*                       digest,
                             size_t*                     digestSize)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->digestFinalize(cryptoCtx, digestHandle, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoApi_signatureInit(SeosCryptoCtx*                cryptoCtx,
                            SeosCrypto_SignatureHandle*   pSigHandle,
                            unsigned int                  algorithm,
                            SeosCrypto_KeyHandle          prvHandle,
                            SeosCrypto_KeyHandle          pubHandle)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->signatureInit(cryptoCtx, pSigHandle, algorithm,
                                            prvHandle, pubHandle);
}

seos_err_t
SeosCryptoApi_signatureFree(SeosCryptoCtx*               cryptoCtx,
                            SeosCrypto_SignatureHandle   sigHandle)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->signatureFree(cryptoCtx, sigHandle);
}

seos_err_t
SeosCryptoApi_signatureSign(SeosCryptoCtx*                 cryptoCtx,
                            SeosCrypto_SignatureHandle     sigHandle,
                            const void*                    hash,
                            size_t                         hashSize,
                            void*                          signature,
                            size_t*                        signatureSize)
{
    return (NULL == cryptoCtx || NULL == signature) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->signatureSign(cryptoCtx, sigHandle, hash, hashSize,
                                            signature, signatureSize);
}

seos_err_t
SeosCryptoApi_signatureVerify(SeosCryptoCtx*                 cryptoCtx,
                              SeosCrypto_SignatureHandle     sigHandle,
                              const void*                    hash,
                              size_t                         hashSize,
                              const void*                    signature,
                              size_t                         signatureSize)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->signatureVerify(cryptoCtx, sigHandle, hash, hashSize,
                                              signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoApi_agreementInit(SeosCryptoCtx*                cryptoCtx,
                            SeosCrypto_AgreementHandle*   pAgrHandle,
                            unsigned int                  algorithm,
                            SeosCrypto_KeyHandle          prvHandle)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->agreementInit(cryptoCtx, pAgrHandle, algorithm,
                                            prvHandle);
}

seos_err_t
SeosCryptoApi_agreementFree(SeosCryptoCtx*               cryptoCtx,
                            SeosCrypto_AgreementHandle   agrHandle)
{
    return (NULL == cryptoCtx) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->agreementFree(cryptoCtx, agrHandle);
}

seos_err_t
SeosCryptoApi_agreementAgree(SeosCryptoCtx*                 cryptoCtx,
                             SeosCrypto_AgreementHandle     agrHandle,
                             SeosCrypto_KeyHandle           pubHandle,
                             void*                          shared,
                             size_t*                        sharedSize)
{
    return (NULL == cryptoCtx || NULL == shared) ?
           SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->agreementAgree(cryptoCtx, agrHandle,
                                             pubHandle, shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoApi_keyInit(SeosCryptoCtx*                   ctx,
                      SeosCrypto_KeyHandle*            keyHandle,
                      unsigned int                     type,
                      SeosCryptoKey_Flags               flags,
                      size_t                           bits)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyInit(ctx, keyHandle, type, flags, bits);
}

seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoCtx*               ctx,
                          SeosCrypto_KeyHandle         keyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyGenerate(ctx, keyHandle);
}

seos_err_t
SeosCryptoApi_keyGeneratePair(SeosCryptoCtx*           ctx,
                              SeosCrypto_KeyHandle     prvKeyHandle,
                              SeosCrypto_KeyHandle     pubKeyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyGeneratePair(ctx, prvKeyHandle, pubKeyHandle);
}

seos_err_t
SeosCryptoApi_keyImport(SeosCryptoCtx*                 ctx,
                        SeosCrypto_KeyHandle           keyHandle,
                        SeosCrypto_KeyHandle           wrapKeyHandle,
                        const void*                    key,
                        size_t                         keyLen)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyImport(ctx, keyHandle, wrapKeyHandle, key, keyLen);
}

seos_err_t
SeosCryptoApi_keyExport(SeosCryptoCtx*                 ctx,
                        SeosCrypto_KeyHandle           keyHandle,
                        SeosCrypto_KeyHandle           wrapKeyHandle,
                        void*                          key,
                        size_t*                        keySize)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyExport(ctx, keyHandle, wrapKeyHandle, key, keySize);
}

seos_err_t
SeosCryptoApi_keyFree(SeosCryptoCtx*                 ctx,
                      SeosCrypto_KeyHandle           keyHandle)
{
    return (NULL == ctx) ? SEOS_ERROR_INVALID_PARAMETER :
           ctx->vtable->keyFree(ctx, keyHandle);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoCtx*             cryptoCtx,
                         SeosCrypto_CipherHandle*   pCipherHandle,
                         unsigned int               algorithm,
                         SeosCrypto_KeyHandle       keyHandle,
                         const void*                iv,
                         size_t                     ivLen)
{
    return (NULL == cryptoCtx) ? SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->cipherInit(cryptoCtx, pCipherHandle, algorithm, keyHandle,
                                         iv, ivLen);
}

seos_err_t
SeosCryptoApi_cipherFree(SeosCryptoCtx*            cryptoCtx,
                         SeosCrypto_CipherHandle   cipherHandle)
{
    return (NULL == cryptoCtx) ? SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->cipherFree(cryptoCtx, cipherHandle);
}

seos_err_t
SeosCryptoApi_cipherUpdate(SeosCryptoCtx*           cryptoCtx,
                           SeosCrypto_CipherHandle  cipherHandle,
                           const void*              data,
                           size_t                   dataLen,
                           void*                    output,
                           size_t*                  outputSize)
{
    return (NULL == cryptoCtx) ? SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->cipherUpdate(cryptoCtx, cipherHandle, data, dataLen, output,
                                           outputSize);
}

seos_err_t
SeosCryptoApi_cipherStart(SeosCryptoCtx*           cryptoCtx,
                          SeosCrypto_CipherHandle  cipherHandle,
                          const void*              ad,
                          size_t                   adLen)
{
    return (NULL == cryptoCtx) ? SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->cipherStart(cryptoCtx, cipherHandle, ad, adLen);
}

seos_err_t
SeosCryptoApi_cipherFinalize(SeosCryptoCtx*           cryptoCtx,
                             SeosCrypto_CipherHandle  cipherHandle,
                             void*                    output,
                             size_t*                  outputSize)
{
    return (NULL == cryptoCtx) ? SEOS_ERROR_INVALID_PARAMETER :
           cryptoCtx->vtable->cipherFinalize(cryptoCtx, cipherHandle, output, outputSize);
}