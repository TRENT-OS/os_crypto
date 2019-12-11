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
(*SeosCryptoApi_Rng_getBytesT)(
    SeosCryptoApi_Context* self,
    unsigned int           flags,
    void*                  buf,
    const size_t           bufSize);

typedef seos_err_t
(*SeosCryptoApi_Rng_reseedT)(
    SeosCryptoApi_Context* self,
    const void*            seed,
    const size_t           seedLen);

// --------------------------------- MAC API -----------------------------------

typedef seos_err_t
(*SeosCryptoApi_Mac_initT)(
    SeosCryptoApi_Context*      self,
    SeosCryptoApi_Mac*          pMacHandle,
    const SeosCryptoApi_Mac_Alg algorithm);

typedef seos_err_t
(*SeosCryptoApi_Mac_freeT)(
    SeosCryptoApi_Context*  self,
    const SeosCryptoApi_Mac macHandle);

typedef seos_err_t
(*SeosCryptoApi_Mac_startT)(
    SeosCryptoApi_Context*  self,
    const SeosCryptoApi_Mac macHandle,
    const void*             secret,
    const size_t            secretLen);

typedef seos_err_t
(*SeosCryptoApi_Mac_processT)(
    SeosCryptoApi_Context*  self,
    const SeosCryptoApi_Mac macHandle,
    const void*             data,
    const size_t            dataLen);

typedef seos_err_t
(*SeosCryptoApi_Mac_finalizeT)(
    SeosCryptoApi_Context*  self,
    const SeosCryptoApi_Mac macHandle,
    void*                   mac,
    size_t*                 macSize);

// ------------------------------- Digest API ----------------------------------

typedef seos_err_t
(*SeosCryptoApi_Digest_initT)(
    SeosCryptoApi_Context*         self,
    SeosCryptoApi_Digest*          pDigestHandle,
    const SeosCryptoApi_Digest_Alg algorithm);

typedef seos_err_t
(*SeosCryptoApi_Digest_freeT)(
    SeosCryptoApi_Context*     self,
    const SeosCryptoApi_Digest digestHandle);

typedef seos_err_t
(*SeosCryptoApi_Digest_cloneT)(
    SeosCryptoApi_Context*     self,
    const SeosCryptoApi_Digest dstDigHandle,
    const SeosCryptoApi_Digest srcDigHandle);

typedef seos_err_t
(*SeosCryptoApi_Digest_processT)(
    SeosCryptoApi_Context*     self,
    const SeosCryptoApi_Digest digestHandle,
    const void*                data,
    const size_t               dataLen);

typedef seos_err_t
(*SeosCryptoApi_Digest_finalizeT)(
    SeosCryptoApi_Context*     self,
    const SeosCryptoApi_Digest digestHandle,
    void*                      digest,
    size_t*                    digestSize);

// -------------------------------- Key API ------------------------------------

typedef seos_err_t
(*SeosCryptoApi_Key_generateT)(
    SeosCryptoApi_Context*        self,
    SeosCryptoApi_Key*            pKeyHandle,
    const SeosCryptoApi_Key_Spec* spec);

typedef seos_err_t
(*SeosCryptoApi_Key_makePublicT)(
    SeosCryptoApi_Context*           self,
    SeosCryptoApi_Key*               pPubKeyHandle,
    const SeosCryptoApi_Key          prvKeyHandle,
    const SeosCryptoApi_Key_Attribs* attribs);

typedef seos_err_t
(*SeosCryptoApi_Key_importT)(
    SeosCryptoApi_Context*        self,
    SeosCryptoApi_Key*            pKeyHandle,
    const SeosCryptoApi_Key       wrapKeyHandle,
    const SeosCryptoApi_Key_Data* keyData);

typedef seos_err_t
(*SeosCryptoApi_Key_exportT)(
    SeosCryptoApi_Context*  self,
    const SeosCryptoApi_Key keyHandle,
    const SeosCryptoApi_Key wrapKeyHandle,
    SeosCryptoApi_Key_Data* keyData);

typedef seos_err_t
(*SeosCryptoApi_Key_getParamsT)(
    SeosCryptoApi_Context*  self,
    const SeosCryptoApi_Key keyHandle,
    void*                   keyParams,
    size_t*                 paramSize);

typedef seos_err_t
(*SeosCryptoApi_Key_loadParamsT)(
    SeosCryptoApi_Context*        self,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize);

typedef seos_err_t
(*SeosCryptoApi_Key_freeT)(
    SeosCryptoApi_Context*  self,
    const SeosCryptoApi_Key keyHandle);

// ----------------------------- Signature API ---------------------------------

typedef seos_err_t
(*SeosCryptoApi_Signature_initT)(
    SeosCryptoApi_Context*
    self,
    SeosCryptoApi_Signature*          pSigHandle,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoApi_Key           prvHandle,
    const SeosCryptoApi_Key           pubHandle);

typedef seos_err_t
(*SeosCryptoApi_Signature_freeT)(
    SeosCryptoApi_Context*
    self,
    const SeosCryptoApi_Signature sigHandle);

typedef seos_err_t
(*SeosCryptoApi_Signature_signT)(
    SeosCryptoApi_Context*
    self,
    const SeosCryptoApi_Signature sigHandle,
    const void*                   hash,
    const size_t                  hashSize,
    void*                         signature,
    size_t*                       signatureSize);

typedef seos_err_t
(*SeosCryptoApi_Signature_verifyT)(
    SeosCryptoApi_Context*
    self,
    const SeosCryptoApi_Signature sigHandle,
    const void*                   hash,
    const size_t                  hashSize,
    const void*                   signature,
    const size_t                  signatureSize);

// ----------------------------- Agreement API ---------------------------------

typedef seos_err_t
(*SeosCryptoApi_Agreement_initT)(
    SeosCryptoApi_Context*
    self,
    SeosCryptoApi_Agreement*          pAgrHandle,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoApi_Key           prvHandle);

typedef seos_err_t
(*SeosCryptoApi_Agreement_freeT)(
    SeosCryptoApi_Context*
    self,
    const SeosCryptoApi_Agreement agrHandle);

typedef seos_err_t
(*SeosCryptoApi_Agreement_agreeT)(
    SeosCryptoApi_Context*
    self,
    const SeosCryptoApi_Agreement agrHandle,
    const SeosCryptoApi_Key       pubHandle,
    void*                         shared,
    size_t*                       sharedSize);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*SeosCryptoApi_Cipher_initT)(
    SeosCryptoApi_Context*         self,
    SeosCryptoApi_Cipher*          pCipherHandle,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoApi_Key        keyHandle,
    const void*                    iv,
    const size_t                   ivLen);

typedef seos_err_t
(*SeosCryptoApi_Cipher_freeT)(
    SeosCryptoApi_Context*     self,
    const SeosCryptoApi_Cipher cipherHandle);

typedef seos_err_t
(*SeosCryptoApi_Cipher_processT)(
    SeosCryptoApi_Context*     self,
    const SeosCryptoApi_Cipher cipherHandle,
    const void*                data,
    const size_t               dataLen,
    void*                      output,
    size_t*                    outputSize);

typedef seos_err_t
(*SeosCryptoApi_Cipher_startT)(
    SeosCryptoApi_Context*     self,
    const SeosCryptoApi_Cipher cipherHandle,
    const void*                data,
    const size_t               dataLen);

typedef seos_err_t
(*SeosCryptoApi_Cipher_finalizeT)(
    SeosCryptoApi_Context*     self,
    const SeosCryptoApi_Cipher cipherHandle,
    void*                      output,
    size_t*                    outputSize);

// -----------------------------------------------------------------------------

typedef seos_err_t (*SeosCryptoApi_freeT)(
    SeosCryptoApi_Context* self);

// -----------------------------------------------------------------------------

typedef struct
{
    SeosCryptoApi_Rng_getBytesT Rng_getBytes;
    SeosCryptoApi_Rng_reseedT Rng_reseed;
    SeosCryptoApi_Mac_initT Mac_init;
    SeosCryptoApi_Mac_freeT Mac_free;
    SeosCryptoApi_Mac_startT Mac_start;
    SeosCryptoApi_Mac_processT Mac_process;
    SeosCryptoApi_Mac_finalizeT Mac_finalize;
    SeosCryptoApi_Digest_initT Digest_init;
    SeosCryptoApi_Digest_freeT Digest_free;
    SeosCryptoApi_Digest_cloneT Digest_clone;
    SeosCryptoApi_Digest_processT Digest_process;
    SeosCryptoApi_Digest_finalizeT Digest_finalize;
    SeosCryptoApi_Key_generateT Key_generate;
    SeosCryptoApi_Key_makePublicT Key_makePublic;
    SeosCryptoApi_Key_importT Key_import;
    SeosCryptoApi_Key_exportT Key_export;
    SeosCryptoApi_Key_getParamsT Key_getParams;
    SeosCryptoApi_Key_loadParamsT Key_loadParams;
    SeosCryptoApi_Key_freeT Key_free;
    SeosCryptoApi_Signature_initT Signature_init;
    SeosCryptoApi_Signature_freeT Signature_free;
    SeosCryptoApi_Signature_signT Signature_sign;
    SeosCryptoApi_Signature_verifyT Signature_verify;
    SeosCryptoApi_Agreement_initT Agreement_init;
    SeosCryptoApi_Agreement_freeT Agreement_free;
    SeosCryptoApi_Agreement_agreeT Agreement_agree;
    SeosCryptoApi_Cipher_initT Cipher_init;
    SeosCryptoApi_Cipher_freeT Cipher_free;
    SeosCryptoApi_Cipher_processT Cipher_process;
    SeosCryptoApi_Cipher_startT Cipher_start;
    SeosCryptoApi_Cipher_finalizeT Cipher_finalize;
    SeosCryptoApi_freeT free;
}
SeosCryptoApi_Vtable;

struct SeosCryptoApi_Context
{
    const SeosCryptoApi_Vtable* vtable;
};

/** @} */
