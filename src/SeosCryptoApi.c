/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoCtx.h"
#include "SeosCryptoApi.h"

/***************************** Crypto functions *******************************/
seos_err_t
SeosCryptoApi_getRandomData(SeosCryptoCtx* self,
                            unsigned int flags,
                            void const* saltBuffer,
                            size_t saltLen,
                            void* buffer,
                            size_t dataLen)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->getRandomData(self,
                                       flags,
                                       saltBuffer,
                                       saltLen,
                                       buffer,
                                       dataLen);
}

seos_err_t
SeosCryptoApi_digestInit(SeosCryptoCtx*              self,
                         SeosCrypto_DigestHandle*    pDigestHandle,
                         unsigned int                algorithm,
                         void*                       iv,
                         size_t                      ivLen)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->digestInit(self,
                                    pDigestHandle,
                                    algorithm,
                                    iv,
                                    ivLen);
}

seos_err_t
SeosCryptoApi_digestClose(SeosCryptoCtx*             self,
                          SeosCrypto_DigestHandle    digestHandle)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->digestClose(self,
                                     digestHandle);
}

seos_err_t
SeosCryptoApi_digestUpdate(SeosCryptoCtx*            self,
                           SeosCrypto_DigestHandle   digestHandle,
                           const void*               data,
                           size_t                    dataLen)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->digestUpdate(self,
                                      digestHandle,
                                      data,
                                      dataLen);
}

seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoCtx*              self,
                             SeosCrypto_DigestHandle     digestHandle,
                             const void*                 data,
                             size_t                      dataLen,
                             void**                      digest,
                             size_t*                     digestSize)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->digestFinalize(self,
                                        digestHandle,
                                        data,
                                        dataLen,
                                        digest,
                                        digestSize);
}

seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoCtx*           self,
                          SeosCrypto_KeyHandle*    pKeyHandle,
                          unsigned int             algorithm,
                          unsigned int             flags,
                          size_t                   lenBits)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->keyGenerate(self,
                                     pKeyHandle,
                                     algorithm,
                                     flags,
                                     lenBits);
}
seos_err_t
SeosCryptoApi_keyImport(SeosCryptoCtx*          self,
                        SeosCrypto_KeyHandle*   pKeyHandle,
                        unsigned int            algorithm,
                        unsigned int            flags,
                        void const*             keyImportBuffer,
                        size_t                  keyImportLenBits)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->keyImport(self,
                                   pKeyHandle,
                                   algorithm,
                                   flags,
                                   keyImportBuffer,
                                   keyImportLenBits);
}

seos_err_t
SeosCryptoApi_keyClose(SeosCryptoCtx*       self,
                       SeosCrypto_KeyHandle keyHandle)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->keyClose(self,
                                  keyHandle);
}

seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoCtx*             self,
                         SeosCrypto_CipherHandle*   pCipherHandle,
                         unsigned int               algorithm,
                         SeosCrypto_KeyHandle       keyHandle,
                         void*                      iv,
                         size_t                     ivLen)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->cipherInit(self,
                                    pCipherHandle,
                                    algorithm,
                                    keyHandle,
                                    iv,
                                    ivLen);
}

seos_err_t
SeosCryptoApi_cipherClose(SeosCryptoCtx*            self,
                          SeosCrypto_CipherHandle   cipherHandle)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->cipherClose(self,
                                     cipherHandle);
}

seos_err_t
SeosCryptoApi_cipherUpdate(SeosCryptoCtx*           self,
                           SeosCrypto_CipherHandle  cipherHandle,
                           const void*              data,
                           size_t                   dataLen,
                           void**                   output,
                           size_t*                  outputSize)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->cipherUpdate(self,
                                      cipherHandle,
                                      data,
                                      dataLen,
                                      output,
                                      outputSize);
}

void
SeosCryptoApi_deInit(SeosCryptoCtx* self)
{
    Debug_ASSERT_SELF(self);
    self->vtable->deInit(self);
}
