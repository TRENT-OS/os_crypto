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
                             unsigned int                   algorithm);

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
(*SeosCryptoCtx_keyGenerateT_v5)(SeosCryptoCtx*            self,
                                 SeosCrypto_KeyHandle_v5*  pKeyHandle,
                                 const SeosCryptoKey_Spec* spec);

typedef seos_err_t
(*SeosCryptoCtx_keyMakePublicT_v5)(SeosCryptoCtx*                  self,
                                   SeosCrypto_KeyHandle_v5*        pPubKeyHandle,
                                   const SeosCrypto_KeyHandle_v5   prvKeyHandle,
                                   const SeosCryptoKey_Attribs*    attribs);

typedef seos_err_t
(*SeosCryptoCtx_keyImportT_v5)(SeosCryptoCtx*                   self,
                               SeosCrypto_KeyHandle_v5*         pKeyHandle,
                               const SeosCrypto_KeyHandle_v5    wrapKeyHandle,
                               const SeosCryptoKey_Data*        keyData);

typedef seos_err_t
(*SeosCryptoCtx_keyExportT_v5)(SeosCryptoCtx*                   self,
                               const SeosCrypto_KeyHandle_v5    keyHandle,
                               const SeosCrypto_KeyHandle_v5    wrapKeyHandle,
                               SeosCryptoKey_Data*              keyData);


typedef seos_err_t
(*SeosCryptoCtx_keyGetParamsT_v5)(SeosCryptoCtx*                self,
                                  const SeosCrypto_KeyHandle_v5 keyHandle,
                                  void*                         keyParams,
                                  size_t*                       paramSize);

typedef seos_err_t
(*SeosCryptoCtx_keyLoadParamsT_v5)(SeosCryptoCtx*               self,
                                   const SeosCryptoKey_Param    name,
                                   void*                        keyParams,
                                   size_t*                      paramSize);

typedef seos_err_t
(*SeosCryptoCtx_keyFreeT_v5)(SeosCryptoCtx*                self,
                             const SeosCrypto_KeyHandle_v5 keyHandle);

// -------------------------------- Key API ------------------------------------


typedef seos_err_t
(*SeosCryptoCtx_keyGenerateT)(SeosCryptoCtx*            self,
                              SeosCrypto_KeyHandle*     pKeyHandle,
                              const SeosCryptoKey_Type  type,
                              const SeosCryptoKey_Flags flags,
                              const size_t              bits);

typedef seos_err_t
(*SeosCryptoCtx_keyGenerateFromParamsT)(SeosCryptoCtx*            self,
                                        SeosCrypto_KeyHandle*     pKeyHandle,
                                        const SeosCryptoKey_Type  type,
                                        const SeosCryptoKey_Flags flags,
                                        const void*               keyParams,
                                        const size_t              paramLen);

typedef seos_err_t
(*SeosCryptoCtx_keyDerivePublicT)(SeosCryptoCtx*                self,
                                  SeosCrypto_KeyHandle*         pPubKeyHandle,
                                  const SeosCrypto_KeyHandle    prvKeyHandle,
                                  const SeosCryptoKey_Flags     flags);

typedef seos_err_t
(*SeosCryptoCtx_keyGeneratePairT)(SeosCryptoCtx*                self,
                                  SeosCrypto_KeyHandle*         pPrvKeyHandle,
                                  SeosCrypto_KeyHandle*         pPubKeyHandle,
                                  const SeosCryptoKey_PairType  type,
                                  const SeosCryptoKey_Flags     prvFlags,
                                  const SeosCryptoKey_Flags     pubFlags,
                                  const size_t                  bits);

typedef seos_err_t
(*SeosCryptoCtx_keyImportT)(SeosCryptoCtx*              self,
                            SeosCrypto_KeyHandle*       pKeyHandle,
                            const SeosCrypto_KeyHandle  wrapkeyHandle,
                            const SeosCryptoKey_Type    type,
                            const SeosCryptoKey_Flags   flags,
                            const void*                 buf,
                            size_t                      bufSize);

typedef seos_err_t
(*SeosCryptoCtx_keyExportT)(SeosCryptoCtx*              self,
                            const SeosCrypto_KeyHandle  keyHandle,
                            const SeosCrypto_KeyHandle  wrapKeyHandle,
                            SeosCryptoKey_Type*         type,
                            SeosCryptoKey_Flags*        flags,
                            void*                       buf,
                            size_t*                     bufSize);

typedef seos_err_t
(*SeosCryptoCtx_keyExtractParamsT)(SeosCryptoCtx*              self,
                                   const SeosCrypto_KeyHandle  keyHandle,
                                   void*                       buf,
                                   size_t*                     bufSize);

typedef seos_err_t
(*SeosCryptoCtx_keyFreeT)(SeosCryptoCtx*                 self,
                          SeosCrypto_KeyHandle           keyHandle);


// ----------------------------- Signature API ---------------------------------

typedef seos_err_t
(*SeosCryptoCtx_signatureInitT)(SeosCryptoCtx*                self,
                                SeosCrypto_SignatureHandle*   pSigHandle,
                                unsigned int                  algorithm,
                                SeosCrypto_KeyHandle_v5          prvHandle,
                                SeosCrypto_KeyHandle_v5          pubHandle);

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
                                SeosCrypto_KeyHandle_v5          prvHandle);

typedef seos_err_t
(*SeosCryptoCtx_agreementFreeT)(SeosCryptoCtx*               self,
                                SeosCrypto_AgreementHandle   agrHandle);

typedef seos_err_t
(*SeosCryptoCtx_agreementAgreeT)(SeosCryptoCtx*                 self,
                                 SeosCrypto_AgreementHandle     agrHandle,
                                 SeosCrypto_KeyHandle_v5           pubHandle,
                                 void*                          shared,
                                 size_t*                        sharedSize);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*SeosCryptoCtx_cipherInitT)(SeosCryptoCtx*                 self,
                             SeosCrypto_CipherHandle*       pCipherHandle,
                             unsigned int                   algorithm,
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
    SeosCryptoCtx_rngGetBytesT              rngGetBytes;
    SeosCryptoCtx_rngReSeedT                rngReSeed;
    SeosCryptoCtx_digestInitT               digestInit;
    SeosCryptoCtx_digestFreeT               digestFree;
    SeosCryptoCtx_digestProcessT            digestProcess;
    SeosCryptoCtx_digestFinalizeT           digestFinalize;
    SeosCryptoCtx_keyGenerateT_v5           keyGenerate_v5;
    SeosCryptoCtx_keyMakePublicT_v5         keyMakePublic_v5;
    SeosCryptoCtx_keyImportT_v5             keyImport_v5;
    SeosCryptoCtx_keyExportT_v5             keyExport_v5;
    SeosCryptoCtx_keyGetParamsT_v5          keyGetParams_v5;
    SeosCryptoCtx_keyLoadParamsT_v5         keyLoadParams_v5;
    SeosCryptoCtx_keyFreeT_v5               keyFree_v5;
    SeosCryptoCtx_keyGenerateT              keyGenerate;
    SeosCryptoCtx_keyGenerateFromParamsT    keyGenerateFromParams;
    SeosCryptoCtx_keyDerivePublicT          keyDerivePublic;
    SeosCryptoCtx_keyGeneratePairT          keyGeneratePair;
    SeosCryptoCtx_keyImportT                keyImport;
    SeosCryptoCtx_keyExportT                keyExport;
    SeosCryptoCtx_keyExtractParamsT         keyExtractParams;
    SeosCryptoCtx_keyFreeT                  keyFree;
    SeosCryptoCtx_signatureInitT            signatureInit;
    SeosCryptoCtx_signatureFreeT            signatureFree;
    SeosCryptoCtx_signatureSignT            signatureSign;
    SeosCryptoCtx_signatureVerifyT          signatureVerify;
    SeosCryptoCtx_agreementInitT            agreementInit;
    SeosCryptoCtx_agreementFreeT            agreementFree;
    SeosCryptoCtx_agreementAgreeT           agreementAgree;
    SeosCryptoCtx_cipherInitT               cipherInit;
    SeosCryptoCtx_cipherFreeT               cipherFree;
    SeosCryptoCtx_cipherProcessT            cipherProcess;
    SeosCryptoCtx_cipherStartT              cipherStart;
    SeosCryptoCtx_cipherFinalizeT           cipherFinalize;
    SeosCryptoCtx_freeT                     free;
}
SeosCryptoCtx_Vtable;

struct SeosCryptoCtx
{
    const SeosCryptoCtx_Vtable* vtable;
};

/** @} */
