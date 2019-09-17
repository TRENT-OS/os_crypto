/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoCtx.h"
#include "SeosCryptoApi.h"

/***************************** Crypto functions *******************************/
seos_err_t
SeosCryptoApi_rngGetBytes(SeosCryptoCtx*    cryptoCtx,
                          void**            buffer,
                          size_t            dataLen)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->rngGetBytes(cryptoCtx,
                                          buffer,
                                          dataLen);
}

seos_err_t
SeosCryptoApi_rngReSeed(SeosCryptoCtx*      cryptoCtx,
                        const void*         seed,
                        size_t              seedLen)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->rngReSeed(cryptoCtx,
                                        seed,
                                        seedLen);
}

seos_err_t
SeosCryptoApi_digestInit(SeosCryptoCtx*              cryptoCtx,
                         SeosCrypto_DigestHandle*    pDigestHandle,
                         unsigned int                algorithm,
                         void*                       iv,
                         size_t                      ivLen)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->digestInit(cryptoCtx,
                                         pDigestHandle,
                                         algorithm,
                                         iv,
                                         ivLen);
}

seos_err_t
SeosCryptoApi_digestClose(SeosCryptoCtx*             cryptoCtx,
                          SeosCrypto_DigestHandle    digestHandle)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->digestClose(cryptoCtx,
                                          digestHandle);
}

seos_err_t
SeosCryptoApi_digestUpdate(SeosCryptoCtx*            cryptoCtx,
                           SeosCrypto_DigestHandle   digestHandle,
                           const void*               data,
                           size_t                    dataLen)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->digestUpdate(cryptoCtx,
                                           digestHandle,
                                           data,
                                           dataLen);
}

seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoCtx*              cryptoCtx,
                             SeosCrypto_DigestHandle     digestHandle,
                             const void*                 data,
                             size_t                      dataLen,
                             void**                      digest,
                             size_t*                     digestSize)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->digestFinalize(cryptoCtx,
                                             digestHandle,
                                             data,
                                             dataLen,
                                             digest,
                                             digestSize);
}

seos_err_t
SeosCryptoApi_keyInit(SeosCryptoCtx*                   ctx,
                      SeosCrypto_KeyHandle*            keyHandle,
                      unsigned int                     type,
                      SeosCryptoKey_Flag               flags,
                      size_t                           secParam)
{
    Debug_ASSERT_SELF(ctx);
    Debug_PRINTF("\n%s\n", __func__);
    return ctx->vtable->keyInit(ctx, keyHandle, type, flags, secParam);
}

seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoCtx*               ctx,
                          SeosCrypto_KeyHandle         keyHandle)
{
    Debug_ASSERT_SELF(ctx);
    Debug_PRINTF("\n%s\n", __func__);
    return ctx->vtable->keyGenerate(ctx, keyHandle);
}

seos_err_t
SeosCryptoApi_keyGeneratePair(SeosCryptoCtx*           ctx,
                              SeosCrypto_KeyHandle     prvKeyHandle,
                              SeosCrypto_KeyHandle     pubKeyHandle)
{
    Debug_ASSERT_SELF(ctx);
    Debug_PRINTF("\n%s\n", __func__);
    return ctx->vtable->keyGeneratePair(ctx, prvKeyHandle, pubKeyHandle);
}

seos_err_t
SeosCryptoApi_keyImport(SeosCryptoCtx*                 ctx,
                        SeosCrypto_KeyHandle           keyHandle,
                        const void*                    key,
                        size_t                         keyLen)
{
    Debug_ASSERT_SELF(ctx);
    Debug_PRINTF("\n%s\n", __func__);
    return ctx->vtable->keyImport(ctx, keyHandle, key, keyLen);
}

seos_err_t
SeosCryptoApi_keyExport(SeosCryptoCtx*                 ctx,
                        SeosCrypto_KeyHandle           keyHandle,
                        void**                         key,
                        size_t*                        keySize)
{
    Debug_ASSERT_SELF(ctx);
    Debug_PRINTF("\n%s\n", __func__);
    return ctx->vtable->keyExport(ctx, keyHandle, key, keySize);
}

seos_err_t
SeosCryptoApi_keyDeInit(SeosCryptoCtx*                 ctx,
                        SeosCrypto_KeyHandle           keyHandle)
{
    Debug_ASSERT_SELF(ctx);
    Debug_PRINTF("\n%s\n", __func__);
    return ctx->vtable->keyDeInit(ctx, keyHandle);
}

seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoCtx*             cryptoCtx,
                         SeosCrypto_CipherHandle*   pCipherHandle,
                         unsigned int               algorithm,
                         SeosCrypto_KeyHandle       keyHandle,
                         const void*                iv,
                         size_t                     ivLen)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->cipherInit(cryptoCtx,
                                         pCipherHandle,
                                         algorithm,
                                         keyHandle,
                                         iv,
                                         ivLen);
}

seos_err_t
SeosCryptoApi_cipherClose(SeosCryptoCtx*            cryptoCtx,
                          SeosCrypto_CipherHandle   cipherHandle)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->cipherClose(cryptoCtx,
                                          cipherHandle);
}

seos_err_t
SeosCryptoApi_cipherUpdate(SeosCryptoCtx*           cryptoCtx,
                           SeosCrypto_CipherHandle  cipherHandle,
                           const void*              data,
                           size_t                   dataLen,
                           void**                   output,
                           size_t*                  outputSize)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->cipherUpdate(cryptoCtx,
                                           cipherHandle,
                                           data,
                                           dataLen,
                                           output,
                                           outputSize);
}

seos_err_t
SeosCryptoApi_cipherUpdateAd(SeosCryptoCtx*           cryptoCtx,
                             SeosCrypto_CipherHandle  cipherHandle,
                             const void*              ad,
                             size_t                   adLen)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->cipherUpdateAd(cryptoCtx,
                                             cipherHandle,
                                             ad,
                                             adLen);
}

seos_err_t
SeosCryptoApi_cipherFinalize(SeosCryptoCtx*           cryptoCtx,
                             SeosCrypto_CipherHandle  cipherHandle,
                             void**                   output,
                             size_t*                  outputSize)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->cipherFinalize(cryptoCtx,
                                             cipherHandle,
                                             output,
                                             outputSize);

}

seos_err_t
SeosCryptoApi_cipherVerifyTag(SeosCryptoCtx*           cryptoCtx,
                              SeosCrypto_CipherHandle  cipherHandle,
                              const void*              tag,
                              size_t                   tagSize)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->cipherVerifyTag(cryptoCtx,
                                              cipherHandle,
                                              tag,
                                              tagSize);

}

void
SeosCryptoApi_deInit(SeosCryptoCtx* cryptoCtx)
{
    Debug_ASSERT_SELF(cryptoCtx);
    cryptoCtx->vtable->deInit(cryptoCtx);
}
