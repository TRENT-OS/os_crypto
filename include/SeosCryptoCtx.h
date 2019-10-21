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

// -------------------------------- RNG API ------------------------------------

typedef seos_err_t
(*SeosCryptoCtx_rngGetBytesT)(SeosCryptoCtx*  self,
                              unsigned int    flags,
                              void*           buf,
                              size_t          bufSize);

typedef seos_err_t
(*SeosCryptoCtx_rngReSeedT)(SeosCryptoCtx*  self,
                            const void*     seed,
                            size_t          seedLen);

// ------------------------------- Digest API ----------------------------------

typedef seos_err_t
(*SeosCryptoCtx_digestInitT)(SeosCryptoCtx*                 self,
                             SeosCrypto_DigestHandle*       pDigestHandle,
                             SeosCryptoDigest_Algorithm     algorithm);

typedef seos_err_t
(*SeosCryptoCtx_digestFreeT)(SeosCryptoCtx*                self,
                             SeosCrypto_DigestHandle       digestHandle);

typedef seos_err_t
(*SeosCryptoCtx_digestProcessT)(SeosCryptoCtx*               self,
                                SeosCrypto_DigestHandle      digestHandle,
                                const void*                  data,
                                size_t                       dataLen);

typedef seos_err_t
(*SeosCryptoCtx_digestFinalizeT)(SeosCryptoCtx*             self,
                                 SeosCrypto_DigestHandle    digestHandle,
                                 void*                      digest,
                                 size_t*                    digestSize);

// -------------------------------- Key API ------------------------------------

typedef seos_err_t
(*SeosCryptoCtx_keyGenerateT)(SeosCryptoCtx*             self,
                              SeosCrypto_KeyHandle*      pKeyHandle,
                              const SeosCryptoKey_Spec*  spec);

typedef seos_err_t
(*SeosCryptoCtx_keyMakePublicT)(SeosCryptoCtx*               self,
                                SeosCrypto_KeyHandle*        pPubKeyHandle,
                                const SeosCrypto_KeyHandle   prvKeyHandle,
                                const SeosCryptoKey_Attribs* attribs);

typedef seos_err_t
(*SeosCryptoCtx_keyImportT)(SeosCryptoCtx*                  self,
                            SeosCrypto_KeyHandle*        pKeyHandle,
                            const SeosCrypto_KeyHandle   wrapKeyHandle,
                            const SeosCryptoKey_Data*    keyData);

typedef seos_err_t
(*SeosCryptoCtx_keyExportT)(SeosCryptoCtx*               self,
                            const SeosCrypto_KeyHandle   keyHandle,
                            const SeosCrypto_KeyHandle   wrapKeyHandle,
                            SeosCryptoKey_Data*          keyData);

typedef seos_err_t
(*SeosCryptoCtx_keyGetParamsT)(SeosCryptoCtx*                self,
                               const SeosCrypto_KeyHandle    keyHandle,
                               void*                         keyParams,
                               size_t*                       paramSize);

typedef seos_err_t
(*SeosCryptoCtx_keyLoadParamsT)(SeosCryptoCtx*               self,
                                const SeosCryptoKey_Param    name,
                                void*                        keyParams,
                                size_t*                      paramSize);

typedef seos_err_t
(*SeosCryptoCtx_keyFreeT)(SeosCryptoCtx*             self,
                          const SeosCrypto_KeyHandle keyHandle);

// ----------------------------- Signature API ---------------------------------

typedef seos_err_t
(*SeosCryptoCtx_signatureInitT)(SeosCryptoCtx*                self,
                                SeosCrypto_SignatureHandle*   pSigHandle,
                                unsigned int                  algorithm,
                                SeosCrypto_KeyHandle          prvHandle,
                                SeosCrypto_KeyHandle          pubHandle);

typedef seos_err_t
(*SeosCryptoCtx_signatureFreeT)(SeosCryptoCtx*               self,
                                SeosCrypto_SignatureHandle   sigHandle);

typedef seos_err_t
(*SeosCryptoCtx_signatureSignT)(SeosCryptoCtx*                 self,
                                SeosCrypto_SignatureHandle     sigHandle,
                                const void*                    hash,
                                size_t                         hashSize,
                                void*                          signature,
                                size_t*                        signatureSize);

typedef seos_err_t
(*SeosCryptoCtx_signatureVerifyT)(SeosCryptoCtx*                 self,
                                  SeosCrypto_SignatureHandle     sigHandle,
                                  const void*                    hash,
                                  size_t                         hashSize,
                                  const void*                    signature,
                                  size_t                         signatureSize);

// ----------------------------- Agreement API ---------------------------------

typedef seos_err_t
(*SeosCryptoCtx_agreementInitT)(SeosCryptoCtx*                self,
                                SeosCrypto_AgreementHandle*   pAgrHandle,
                                SeosCryptoAgreement_Algorithm algorithm,
                                SeosCrypto_KeyHandle          prvHandle);

typedef seos_err_t
(*SeosCryptoCtx_agreementFreeT)(SeosCryptoCtx*               self,
                                SeosCrypto_AgreementHandle   agrHandle);

typedef seos_err_t
(*SeosCryptoCtx_agreementAgreeT)(SeosCryptoCtx*                 self,
                                 SeosCrypto_AgreementHandle     agrHandle,
                                 SeosCrypto_KeyHandle           pubHandle,
                                 void*                          shared,
                                 size_t*                        sharedSize);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*SeosCryptoCtx_cipherInitT)(SeosCryptoCtx*                 self,
                             SeosCrypto_CipherHandle*       pCipherHandle,
                             SeosCryptoCipher_Algorithm     algorithm,
                             SeosCrypto_KeyHandle           keyHandle,
                             const void*                    iv,
                             size_t                         ivLen);

typedef seos_err_t
(*SeosCryptoCtx_cipherFreeT)(SeosCryptoCtx*                self,
                             SeosCrypto_CipherHandle       cipherHandle);

typedef seos_err_t
(*SeosCryptoCtx_cipherProcessT)(SeosCryptoCtx*               self,
                                SeosCrypto_CipherHandle      cipherHandle,
                                const void*                  data,
                                size_t                       dataLen,
                                void*                        output,
                                size_t*                      outputSize);

typedef seos_err_t
(*SeosCryptoCtx_cipherStartT)(SeosCryptoCtx*               self,
                              SeosCrypto_CipherHandle      cipherHandle,
                              const void*                  data,
                              size_t                       dataLen);

typedef seos_err_t
(*SeosCryptoCtx_cipherFinalizeT)(SeosCryptoCtx*               self,
                                 SeosCrypto_CipherHandle      cipherHandle,
                                 void*                        output,
                                 size_t*                      outputSize);

// -----------------------------------------------------------------------------

typedef void (*SeosCryptoCtx_freeT)(SeosCryptoCtx* self);

typedef struct
{
    SeosCryptoCtx_rngGetBytesT           rngGetBytes;
    SeosCryptoCtx_rngReSeedT             rngReSeed;
    SeosCryptoCtx_digestInitT            digestInit;
    SeosCryptoCtx_digestFreeT            digestFree;
    SeosCryptoCtx_digestProcessT         digestProcess;
    SeosCryptoCtx_digestFinalizeT        digestFinalize;
    SeosCryptoCtx_keyGenerateT           keyGenerate;
    SeosCryptoCtx_keyMakePublicT         keyMakePublic;
    SeosCryptoCtx_keyImportT             keyImport;
    SeosCryptoCtx_keyExportT             keyExport;
    SeosCryptoCtx_keyGetParamsT          keyGetParams;
    SeosCryptoCtx_keyLoadParamsT         keyLoadParams;
    SeosCryptoCtx_keyFreeT               keyFree;
    SeosCryptoCtx_signatureInitT         signatureInit;
    SeosCryptoCtx_signatureFreeT         signatureFree;
    SeosCryptoCtx_signatureSignT         signatureSign;
    SeosCryptoCtx_signatureVerifyT       signatureVerify;
    SeosCryptoCtx_agreementInitT         agreementInit;
    SeosCryptoCtx_agreementFreeT         agreementFree;
    SeosCryptoCtx_agreementAgreeT        agreementAgree;
    SeosCryptoCtx_cipherInitT            cipherInit;
    SeosCryptoCtx_cipherFreeT            cipherFree;
    SeosCryptoCtx_cipherProcessT         cipherProcess;
    SeosCryptoCtx_cipherStartT           cipherStart;
    SeosCryptoCtx_cipherFinalizeT        cipherFinalize;
    SeosCryptoCtx_freeT                  free;
}
SeosCryptoCtx_Vtable;

struct SeosCryptoCtx
{
    const SeosCryptoCtx_Vtable* vtable;
};

/** @} */
