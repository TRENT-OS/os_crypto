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

#include "SeosCryptoApi.h"

// -------------------------------- RNG API ------------------------------------

typedef seos_err_t
(*SeosCryptoApi_rngGetBytesT)(SeosCryptoApi_Context* self,
                              unsigned int           flags,
                              void*                  buf,
                              const size_t           bufSize);

typedef seos_err_t
(*SeosCryptoApi_rngReSeedT)(SeosCryptoApi_Context* self,
                            const void*            seed,
                            const size_t           seedLen);

// --------------------------------- MAC API -----------------------------------

typedef seos_err_t
(*SeosCryptoApi_macInitT)(SeosCryptoApi_Context*      self,
                          SeosCryptoApi_Mac*          pMacHandle,
                          const SeosCryptoApi_Mac_Alg algorithm);

typedef seos_err_t
(*SeosCryptoApi_macFreeT)(SeosCryptoApi_Context*  self,
                          const SeosCryptoApi_Mac macHandle);

typedef seos_err_t
(*SeosCryptoApi_macStartT)(SeosCryptoApi_Context*  self,
                           const SeosCryptoApi_Mac macHandle,
                           const void*             secret,
                           const size_t            secretLen);

typedef seos_err_t
(*SeosCryptoApi_macProcessT)(SeosCryptoApi_Context*  self,
                             const SeosCryptoApi_Mac macHandle,
                             const void*             data,
                             const size_t            dataLen);

typedef seos_err_t
(*SeosCryptoApi_macFinalizeT)(SeosCryptoApi_Context*  self,
                              const SeosCryptoApi_Mac macHandle,
                              void*                   mac,
                              size_t*                 macSize);

// ------------------------------- Digest API ----------------------------------

typedef seos_err_t
(*SeosCryptoApi_digestInitT)(SeosCryptoApi_Context*         self,
                             SeosCryptoApi_Digest*          pDigestHandle,
                             const SeosCryptoApi_Digest_Alg algorithm);

typedef seos_err_t
(*SeosCryptoApi_digestFreeT)(SeosCryptoApi_Context*     self,
                             const SeosCryptoApi_Digest digestHandle);

typedef seos_err_t
(*SeosCryptoApi_digestCloneT)(SeosCryptoApi_Context*     self,
                              const SeosCryptoApi_Digest dstDigHandle,
                              const SeosCryptoApi_Digest srcDigHandle);

typedef seos_err_t
(*SeosCryptoApi_digestProcessT)(SeosCryptoApi_Context*     self,
                                const SeosCryptoApi_Digest digestHandle,
                                const void*                data,
                                const size_t               dataLen);

typedef seos_err_t
(*SeosCryptoApi_digestFinalizeT)(SeosCryptoApi_Context*     self,
                                 const SeosCryptoApi_Digest digestHandle,
                                 void*                      digest,
                                 size_t*                    digestSize);

// -------------------------------- Key API ------------------------------------

typedef seos_err_t
(*SeosCryptoApi_keyGenerateT)(SeosCryptoApi_Context*        self,
                              SeosCryptoApi_Key*            pKeyHandle,
                              const SeosCryptoApi_Key_Spec* spec);

typedef seos_err_t
(*SeosCryptoApi_keyMakePublicT)(SeosCryptoApi_Context*           self,
                                SeosCryptoApi_Key*               pPubKeyHandle,
                                const SeosCryptoApi_Key          prvKeyHandle,
                                const SeosCryptoApi_Key_Attribs* attribs);

typedef seos_err_t
(*SeosCryptoApi_keyImportT)(SeosCryptoApi_Context*        self,
                            SeosCryptoApi_Key*            pKeyHandle,
                            const SeosCryptoApi_Key       wrapKeyHandle,
                            const SeosCryptoApi_Key_Data* keyData);

typedef seos_err_t
(*SeosCryptoApi_keyExportT)(SeosCryptoApi_Context*  self,
                            const SeosCryptoApi_Key keyHandle,
                            const SeosCryptoApi_Key wrapKeyHandle,
                            SeosCryptoApi_Key_Data* keyData);

typedef seos_err_t
(*SeosCryptoApi_keyGetParamsT)(SeosCryptoApi_Context*  self,
                               const SeosCryptoApi_Key keyHandle,
                               void*                   keyParams,
                               size_t*                 paramSize);

typedef seos_err_t
(*SeosCryptoApi_keyLoadParamsT)(SeosCryptoApi_Context*        self,
                                const SeosCryptoApi_Key_Param name,
                                void*                         keyParams,
                                size_t*                       paramSize);

typedef seos_err_t
(*SeosCryptoApi_keyFreeT)(SeosCryptoApi_Context*  self,
                          const SeosCryptoApi_Key keyHandle);

// ----------------------------- Signature API ---------------------------------

typedef seos_err_t
(*SeosCryptoApi_signatureInitT)(SeosCryptoApi_Context*
                                self,
                                SeosCryptoApi_Signature*          pSigHandle,
                                const SeosCryptoApi_Signature_Alg algorithm,
                                const SeosCryptoApi_Digest_Alg    digest,
                                const SeosCryptoApi_Key           prvHandle,
                                const SeosCryptoApi_Key           pubHandle);

typedef seos_err_t
(*SeosCryptoApi_signatureFreeT)(SeosCryptoApi_Context*
                                self,
                                const SeosCryptoApi_Signature sigHandle);

typedef seos_err_t
(*SeosCryptoApi_signatureSignT)(SeosCryptoApi_Context*
                                self,
                                const SeosCryptoApi_Signature sigHandle,
                                const void*                   hash,
                                const size_t                  hashSize,
                                void*                         signature,
                                size_t*                       signatureSize);

typedef seos_err_t
(*SeosCryptoApi_signatureVerifyT)(SeosCryptoApi_Context*
                                  self,
                                  const SeosCryptoApi_Signature sigHandle,
                                  const void*                   hash,
                                  const size_t                  hashSize,
                                  const void*                   signature,
                                  const size_t                  signatureSize);

// ----------------------------- Agreement API ---------------------------------

typedef seos_err_t
(*SeosCryptoApi_agreementInitT)(SeosCryptoApi_Context*
                                self,
                                SeosCryptoApi_Agreement*          pAgrHandle,
                                const SeosCryptoApi_Agreement_Alg algorithm,
                                const SeosCryptoApi_Key           prvHandle);

typedef seos_err_t
(*SeosCryptoApi_agreementFreeT)(SeosCryptoApi_Context*
                                self,
                                const SeosCryptoApi_Agreement agrHandle);

typedef seos_err_t
(*SeosCryptoApi_agreementAgreeT)(SeosCryptoApi_Context*
                                 self,
                                 const SeosCryptoApi_Agreement agrHandle,
                                 const SeosCryptoApi_Key       pubHandle,
                                 void*                         shared,
                                 size_t*                       sharedSize);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*SeosCryptoApi_cipherInitT)(SeosCryptoApi_Context*         self,
                             SeosCryptoApi_Cipher*          pCipherHandle,
                             const SeosCryptoApi_Cipher_Alg algorithm,
                             const SeosCryptoApi_Key        keyHandle,
                             const void*                    iv,
                             const size_t                   ivLen);

typedef seos_err_t
(*SeosCryptoApi_cipherFreeT)(SeosCryptoApi_Context*     self,
                             const SeosCryptoApi_Cipher cipherHandle);

typedef seos_err_t
(*SeosCryptoApi_cipherProcessT)(SeosCryptoApi_Context*     self,
                                const SeosCryptoApi_Cipher cipherHandle,
                                const void*                data,
                                const size_t               dataLen,
                                void*                      output,
                                size_t*                    outputSize);

typedef seos_err_t
(*SeosCryptoApi_cipherStartT)(SeosCryptoApi_Context*     self,
                              const SeosCryptoApi_Cipher cipherHandle,
                              const void*                data,
                              const size_t               dataLen);

typedef seos_err_t
(*SeosCryptoApi_cipherFinalizeT)(SeosCryptoApi_Context*     self,
                                 const SeosCryptoApi_Cipher cipherHandle,
                                 void*                      output,
                                 size_t*                    outputSize);

// -----------------------------------------------------------------------------

typedef seos_err_t (*SeosCryptoApi_freeT)(SeosCryptoApi_Context* self);

// -----------------------------------------------------------------------------

typedef struct
{
    SeosCryptoApi_rngGetBytesT rngGetBytes;
    SeosCryptoApi_rngReSeedT rngReSeed;
    SeosCryptoApi_macInitT macInit;
    SeosCryptoApi_macFreeT macFree;
    SeosCryptoApi_macStartT macStart;
    SeosCryptoApi_macProcessT macProcess;
    SeosCryptoApi_macFinalizeT macFinalize;
    SeosCryptoApi_digestInitT digestInit;
    SeosCryptoApi_digestFreeT digestFree;
    SeosCryptoApi_digestCloneT digestClone;
    SeosCryptoApi_digestProcessT digestProcess;
    SeosCryptoApi_digestFinalizeT digestFinalize;
    SeosCryptoApi_keyGenerateT keyGenerate;
    SeosCryptoApi_keyMakePublicT keyMakePublic;
    SeosCryptoApi_keyImportT keyImport;
    SeosCryptoApi_keyExportT keyExport;
    SeosCryptoApi_keyGetParamsT keyGetParams;
    SeosCryptoApi_keyLoadParamsT keyLoadParams;
    SeosCryptoApi_keyFreeT keyFree;
    SeosCryptoApi_signatureInitT signatureInit;
    SeosCryptoApi_signatureFreeT signatureFree;
    SeosCryptoApi_signatureSignT signatureSign;
    SeosCryptoApi_signatureVerifyT signatureVerify;
    SeosCryptoApi_agreementInitT agreementInit;
    SeosCryptoApi_agreementFreeT agreementFree;
    SeosCryptoApi_agreementAgreeT agreementAgree;
    SeosCryptoApi_cipherInitT cipherInit;
    SeosCryptoApi_cipherFreeT cipherFree;
    SeosCryptoApi_cipherProcessT cipherProcess;
    SeosCryptoApi_cipherStartT cipherStart;
    SeosCryptoApi_cipherFinalizeT cipherFinalize;
    SeosCryptoApi_freeT free;
}
SeosCryptoApi_Vtable;

struct SeosCryptoApi_Context
{
    const SeosCryptoApi_Vtable* vtable;
};

/** @} */
