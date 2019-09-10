/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoCtx.h
 *
 * @brief SEOS Crypto API interface context
 *
 */

#pragma once

#include "SeosCrypto_Handles.h"

#include "compiler.h"
#include "seos_err.h"

typedef struct SeosCryptoCtx SeosCryptoCtx;

typedef seos_err_t
(*SeosCryptoCtx_rngGetBytesT)(SeosCryptoCtx*  self,
                              void**          buffer,
                              size_t          dataLen);

typedef seos_err_t
(*SeosCryptoCtx_rngReSeedT)(SeosCryptoCtx*  self,
                            const void*     seed,
                            size_t          seedLen);

typedef seos_err_t
(*SeosCryptoCtx_digestInitT)(SeosCryptoCtx*                 self,
                             SeosCrypto_DigestHandle*       pDigestHandle,
                             unsigned int                   algorithm,
                             void*                          iv,
                             size_t                         ivLen);

typedef seos_err_t
(*SeosCryptoCtx_digestCloseT)(SeosCryptoCtx*                self,
                              SeosCrypto_DigestHandle       digestHandle);

typedef seos_err_t
(*SeosCryptoCtx_digestUpdateT)(SeosCryptoCtx*               self,
                               SeosCrypto_DigestHandle      digestHandle,
                               const void*                  data,
                               size_t                       dataLen);

typedef seos_err_t
(*SeosCryptoCtx_digestFinalizeT)(SeosCryptoCtx*             self,
                                 SeosCrypto_DigestHandle    digestHandle,
                                 const void*                data,
                                 size_t                     dataLen,
                                 void**                     digest,
                                 size_t*                    digestSize);

typedef seos_err_t
(*SeosCryptoCtx_keyInitT)(SeosCryptoCtx*                   self,
                          SeosCrypto_KeyHandle*            keyHandle,
                          unsigned int                     type,
                          unsigned int                     flags,
                          size_t                           bits);

typedef seos_err_t
(*SeosCryptoCtx_keyGenerateT)(SeosCryptoCtx*               self,
                              SeosCrypto_KeyHandle         keyHandle);

typedef seos_err_t
(*SeosCryptoCtx_keyGeneratePairT)(SeosCryptoCtx*           self,
                                  SeosCrypto_KeyHandle     prvKeyHandle,
                                  SeosCrypto_KeyHandle     pubKeyHandle);

typedef seos_err_t
(*SeosCryptoCtx_keyImportT)(SeosCryptoCtx*                 self,
                            SeosCrypto_KeyHandle           keyHandle,
                            const void*                    key,
                            size_t                         keySize);

typedef seos_err_t
(*SeosCryptoCtx_keyExportT)(SeosCryptoCtx*                 self,
                            SeosCrypto_KeyHandle           keyHandle,
                            void**                         key,
                            size_t*                        keySize);

typedef seos_err_t
(*SeosCryptoCtx_keyDeInitT)(SeosCryptoCtx*                 self,
                            SeosCrypto_KeyHandle           keyHandle);

typedef seos_err_t
(*SeosCryptoCtx_cipherInitT)(SeosCryptoCtx*                 self,
                             SeosCrypto_CipherHandle*       pCipherHandle,
                             unsigned int                   algorithm,
                             SeosCrypto_KeyHandle           keyHandle,
                             const void*                    iv,
                             size_t                         ivLen);

typedef seos_err_t
(*SeosCryptoCtx_cipherCloseT)(SeosCryptoCtx*                self,
                              SeosCrypto_CipherHandle       cipherHandle);

typedef seos_err_t
(*SeosCryptoCtx_cipherUpdateT)(SeosCryptoCtx*               self,
                               SeosCrypto_CipherHandle      cipherHandle,
                               const void*                  data,
                               size_t                       dataLen,
                               void**                       output,
                               size_t*                      outputSize);

typedef seos_err_t
(*SeosCryptoCtx_cipherUpdateAdT)(SeosCryptoCtx*               self,
                                 SeosCrypto_CipherHandle      cipherHandle,
                                 const void*                  data,
                                 size_t                       dataLen);

typedef seos_err_t
(*SeosCryptoCtx_cipherFinalizeT)(SeosCryptoCtx*               self,
                                 SeosCrypto_CipherHandle      cipherHandle,
                                 void**                       output,
                                 size_t*                      outputSize);

typedef seos_err_t
(*SeosCryptoCtx_cipherVerifyTagT)(SeosCryptoCtx*               self,
                                  SeosCrypto_CipherHandle      cipherHandle,
                                  const void*                  tag,
                                  size_t                       tagSize);

typedef void
(*SeosCryptoCtx_deInitT)(SeosCryptoCtx* self);


typedef struct
{
    SeosCryptoCtx_rngGetBytesT      rngGetBytes;
    SeosCryptoCtx_rngReSeedT        rngReSeed;
    SeosCryptoCtx_digestInitT       digestInit;
    SeosCryptoCtx_digestCloseT      digestClose;
    SeosCryptoCtx_digestUpdateT     digestUpdate;
    SeosCryptoCtx_digestFinalizeT   digestFinalize;
    SeosCryptoCtx_keyInitT          keyInit;
    SeosCryptoCtx_keyGenerateT      keyGenerate;
    SeosCryptoCtx_keyGeneratePairT  keyGeneratePair;
    SeosCryptoCtx_keyImportT        keyImport;
    SeosCryptoCtx_keyExportT        keyExport;
    SeosCryptoCtx_keyDeInitT        keyDeInit;
    SeosCryptoCtx_cipherInitT       cipherInit;
    SeosCryptoCtx_cipherCloseT      cipherClose;
    SeosCryptoCtx_cipherUpdateT     cipherUpdate;
    SeosCryptoCtx_cipherUpdateAdT   cipherUpdateAd;
    SeosCryptoCtx_cipherFinalizeT   cipherFinalize;
    SeosCryptoCtx_cipherVerifyTagT  cipherVerifyTag;
    SeosCryptoCtx_deInitT           deInit;
}
SeosCryptoCtx_Vtable;

struct SeosCryptoCtx
{
    const SeosCryptoCtx_Vtable* vtable;
};

/** @} */
