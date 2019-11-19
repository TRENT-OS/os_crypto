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
#include "SeosError.h"

typedef struct SeosCryptoCtx SeosCryptoCtx;

// -------------------------------- RNG API ------------------------------------

typedef seos_err_t
(*SeosCryptoCtx_rngGetBytesT)(SeosCryptoCtx*  self,
                              unsigned int    flags,
                              void*           buf,
                              const size_t    bufSize);

typedef seos_err_t
(*SeosCryptoCtx_rngReSeedT)(SeosCryptoCtx*  self,
                            const void*     seed,
                            const size_t    seedLen);

// --------------------------------- MAC API -----------------------------------

typedef seos_err_t
(*SeosCryptoCtx_macInitT)(SeosCryptoCtx*                self,
                          SeosCrypto_MacHandle*         pMacHandle,
                          const SeosCryptoMac_Algorithm algorithm);

typedef seos_err_t
(*SeosCryptoCtx_macFreeT)(SeosCryptoCtx*                self,
                          const SeosCrypto_MacHandle    macHandle);

typedef seos_err_t
(*SeosCryptoCtx_macStartT)(SeosCryptoCtx*               self,
                           const SeosCrypto_MacHandle   macHandle,
                           const void*                  secret,
                           const size_t                 secretLen);

typedef seos_err_t
(*SeosCryptoCtx_macProcessT)(SeosCryptoCtx*                 self,
                             const SeosCrypto_MacHandle     macHandle,
                             const void*                    data,
                             const size_t                   dataLen);

typedef seos_err_t
(*SeosCryptoCtx_macFinalizeT)(SeosCryptoCtx*                self,
                              const SeosCrypto_MacHandle    macHandle,
                              void*                         mac,
                              size_t*                       macSize);

// ------------------------------- Digest API ----------------------------------

typedef seos_err_t
(*SeosCryptoCtx_digestInitT)(SeosCryptoCtx*                     self,
                             SeosCrypto_DigestHandle*           pDigestHandle,
                             const SeosCryptoDigest_Algorithm   algorithm);

typedef seos_err_t
(*SeosCryptoCtx_digestFreeT)(SeosCryptoCtx*                 self,
                             const SeosCrypto_DigestHandle  digestHandle);

typedef seos_err_t
(*SeosCryptoCtx_digestCloneT)(SeosCryptoCtx*                 self,
                              const SeosCrypto_DigestHandle  dstDigHandle,
                              const SeosCrypto_DigestHandle  srcDigHandle);

typedef seos_err_t
(*SeosCryptoCtx_digestProcessT)(SeosCryptoCtx*                  self,
                                const SeosCrypto_DigestHandle   digestHandle,
                                const void*                     data,
                                const size_t                    dataLen);

typedef seos_err_t
(*SeosCryptoCtx_digestFinalizeT)(SeosCryptoCtx*                 self,
                                 const SeosCrypto_DigestHandle  digestHandle,
                                 void*                          digest,
                                 size_t*                        digestSize);

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
(*SeosCryptoCtx_keyImportT)(SeosCryptoCtx*               self,
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
(*SeosCryptoCtx_signatureInitT)(SeosCryptoCtx*                      self,
                                SeosCrypto_SignatureHandle*         pSigHandle,
                                const SeosCryptoSignature_Algorithm algorithm,
                                const SeosCryptoDigest_Algorithm    digest,
                                const SeosCrypto_KeyHandle          prvHandle,
                                const SeosCrypto_KeyHandle          pubHandle);

typedef seos_err_t
(*SeosCryptoCtx_signatureFreeT)(SeosCryptoCtx*                      self,
                                const SeosCrypto_SignatureHandle    sigHandle);

typedef seos_err_t
(*SeosCryptoCtx_signatureSignT)(SeosCryptoCtx*                      self,
                                const SeosCrypto_SignatureHandle    sigHandle,
                                const void*                         hash,
                                const size_t                        hashSize,
                                void*                               signature,
                                size_t*                             signatureSize);

typedef seos_err_t
(*SeosCryptoCtx_signatureVerifyT)(SeosCryptoCtx*                    self,
                                  const SeosCrypto_SignatureHandle  sigHandle,
                                  const void*                       hash,
                                  const size_t                      hashSize,
                                  const void*                       signature,
                                  const size_t                      signatureSize);

// ----------------------------- Agreement API ---------------------------------

typedef seos_err_t
(*SeosCryptoCtx_agreementInitT)(SeosCryptoCtx*                      self,
                                SeosCrypto_AgreementHandle*         pAgrHandle,
                                const SeosCryptoAgreement_Algorithm algorithm,
                                const SeosCrypto_KeyHandle          prvHandle);

typedef seos_err_t
(*SeosCryptoCtx_agreementFreeT)(SeosCryptoCtx*                      self,
                                const SeosCrypto_AgreementHandle    agrHandle);

typedef seos_err_t
(*SeosCryptoCtx_agreementAgreeT)(SeosCryptoCtx*                     self,
                                 const SeosCrypto_AgreementHandle   agrHandle,
                                 const SeosCrypto_KeyHandle         pubHandle,
                                 void*                              shared,
                                 size_t*                            sharedSize);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*SeosCryptoCtx_cipherInitT)(SeosCryptoCtx*                     self,
                             SeosCrypto_CipherHandle*           pCipherHandle,
                             const SeosCryptoCipher_Algorithm   algorithm,
                             const SeosCrypto_KeyHandle         keyHandle,
                             const void*                        iv,
                             const size_t                       ivLen);

typedef seos_err_t
(*SeosCryptoCtx_cipherFreeT)(SeosCryptoCtx*                 self,
                             const SeosCrypto_CipherHandle  cipherHandle);

typedef seos_err_t
(*SeosCryptoCtx_cipherProcessT)(SeosCryptoCtx*                  self,
                                const SeosCrypto_CipherHandle   cipherHandle,
                                const void*                     data,
                                const size_t                    dataLen,
                                void*                           output,
                                size_t*                         outputSize);

typedef seos_err_t
(*SeosCryptoCtx_cipherStartT)(SeosCryptoCtx*                self,
                              const SeosCrypto_CipherHandle cipherHandle,
                              const void*                   data,
                              const size_t                  dataLen);

typedef seos_err_t
(*SeosCryptoCtx_cipherFinalizeT)(SeosCryptoCtx*                 self,
                                 const SeosCrypto_CipherHandle  cipherHandle,
                                 void*                          output,
                                 size_t*                        outputSize);

// -----------------------------------------------------------------------------

typedef seos_err_t (*SeosCryptoCtx_freeT)(SeosCryptoCtx* self);

// -----------------------------------------------------------------------------

typedef struct
{
    SeosCryptoCtx_rngGetBytesT          rngGetBytes;
    SeosCryptoCtx_rngReSeedT            rngReSeed;
    SeosCryptoCtx_macInitT              macInit;
    SeosCryptoCtx_macFreeT              macFree;
    SeosCryptoCtx_macStartT             macStart;
    SeosCryptoCtx_macProcessT           macProcess;
    SeosCryptoCtx_macFinalizeT          macFinalize;
    SeosCryptoCtx_digestInitT           digestInit;
    SeosCryptoCtx_digestFreeT           digestFree;
    SeosCryptoCtx_digestCloneT          digestClone;
    SeosCryptoCtx_digestProcessT        digestProcess;
    SeosCryptoCtx_digestFinalizeT       digestFinalize;
    SeosCryptoCtx_keyGenerateT          keyGenerate;
    SeosCryptoCtx_keyMakePublicT        keyMakePublic;
    SeosCryptoCtx_keyImportT            keyImport;
    SeosCryptoCtx_keyExportT            keyExport;
    SeosCryptoCtx_keyGetParamsT         keyGetParams;
    SeosCryptoCtx_keyLoadParamsT        keyLoadParams;
    SeosCryptoCtx_keyFreeT              keyFree;
    SeosCryptoCtx_signatureInitT        signatureInit;
    SeosCryptoCtx_signatureFreeT        signatureFree;
    SeosCryptoCtx_signatureSignT        signatureSign;
    SeosCryptoCtx_signatureVerifyT      signatureVerify;
    SeosCryptoCtx_agreementInitT        agreementInit;
    SeosCryptoCtx_agreementFreeT        agreementFree;
    SeosCryptoCtx_agreementAgreeT       agreementAgree;
    SeosCryptoCtx_cipherInitT           cipherInit;
    SeosCryptoCtx_cipherFreeT           cipherFree;
    SeosCryptoCtx_cipherProcessT        cipherProcess;
    SeosCryptoCtx_cipherStartT          cipherStart;
    SeosCryptoCtx_cipherFinalizeT       cipherFinalize;
    SeosCryptoCtx_freeT                 free;
}
SeosCryptoCtx_Vtable;

struct SeosCryptoCtx
{
    const SeosCryptoCtx_Vtable* vtable;
};

/** @} */
