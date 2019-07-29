/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoCtx.h"
#include "SeosCryptoApi.h"

/***************************** Crypto functions *******************************/
seos_err_t
SeosCryptoApi_getRandomData(SeosCryptoCtx* cryptoCtx,
                            unsigned int flags,
                            void const* saltBuffer,
                            size_t saltLen,
                            void* buffer,
                            size_t dataLen)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->getRandomData(cryptoCtx,
                                            flags,
                                            saltBuffer,
                                            saltLen,
                                            buffer,
                                            dataLen);
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
SeosCryptoApi_keyGenerate(SeosCryptoCtx*           cryptoCtx,
                          SeosCrypto_KeyHandle*    pKeyHandle,
                          unsigned int             algorithm,
                          unsigned int             flags,
                          size_t                   lenBits)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->keyGenerate(cryptoCtx,
                                          pKeyHandle,
                                          algorithm,
                                          flags,
                                          lenBits);
}
seos_err_t
SeosCryptoApi_keyImport(SeosCryptoCtx*          cryptoCtx,
                        SeosCrypto_KeyHandle*   pKeyHandle,
                        unsigned int            algorithm,
                        unsigned int            flags,
                        void const*             keyImportBuffer,
                        size_t                  keyImportLenBits)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->keyImport(cryptoCtx,
                                        pKeyHandle,
                                        algorithm,
                                        flags,
                                        keyImportBuffer,
                                        keyImportLenBits);
}

seos_err_t
SeosCryptoApi_keyClose(SeosCryptoCtx*       cryptoCtx,
                       SeosCrypto_KeyHandle keyHandle)
{
    Debug_ASSERT_SELF(cryptoCtx);
    return cryptoCtx->vtable->keyClose(cryptoCtx,
                                       keyHandle);
}

seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoCtx*             cryptoCtx,
                         SeosCrypto_CipherHandle*   pCipherHandle,
                         unsigned int               algorithm,
                         SeosCrypto_KeyHandle       keyHandle,
                         void*                      iv,
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

void
SeosCryptoApi_deInit(SeosCryptoCtx* cryptoCtx)
{
    Debug_ASSERT_SELF(cryptoCtx);
    cryptoCtx->vtable->deInit(cryptoCtx);
}
