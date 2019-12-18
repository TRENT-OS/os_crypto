/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoLib.h
 *
 * @brief Crypto core functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "lib/SeosCryptoLib_Rng.h"

#include "LibUtil/PointerVector.h"

#include "compiler.h"

// Internal types/defines/enums ------------------------------------------------

#define SeosCryptoLib_SIZE_BUFFER SeosCryptoApi_SIZE_DATAPORT

typedef struct
{
    SeosCryptoApi_MemIf memIf;
    SeosCryptoLib_Rng cryptoRng;
    PointerVector keyHandleVector;
    PointerVector macHandleVector;
    PointerVector digestHandleVector;
    PointerVector cipherHandleVector;
    PointerVector signatureHandleVector;
    PointerVector agreementHandleVector;
    /**
     * When we have a function that takes an input buffer and produces an output
     * buffer, we copy the inputs to this buffer internally, so the caller can
     * use the identical buffer as input/output.
     */
    uint8_t buffer[SeosCryptoLib_SIZE_BUFFER];
} SeosCryptoLib;

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_init(
    SeosCryptoLib*                  self,
    const SeosCryptoApi_Vtable**    vtable,
    const SeosCryptoApi_MemIf*      memIf,
    const SeosCryptoApi_Lib_Config* cfg);

seos_err_t
SeosCryptoLib_free(
    SeosCryptoLib* self);

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoLib_Rng_getBytes(
    SeosCryptoApi*               api,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufLen);

seos_err_t
SeosCryptoLib_Rng_reseed(
    SeosCryptoApi* api,
    const void*    seed,
    const size_t   seedLen);

// -------------------------------- MAC API ------------------------------------

seos_err_t
SeosCryptoLib_Mac_init(
    SeosCryptoApi*              api,
    SeosCryptoLib_Mac**         pMacObj,
    const SeosCryptoApi_Mac_Alg algorithm);

seos_err_t
SeosCryptoLib_Mac_free(
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj);

seos_err_t
SeosCryptoLib_Mac_start(
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj,
    const void*        secret,
    const size_t       secretSize);

seos_err_t
SeosCryptoLib_Mac_process(
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj,
    const void*        data,
    const size_t       dataLen);

seos_err_t
SeosCryptoLib_Mac_finalize(
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj,
    void*              mac,
    size_t*            macSize);

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoLib_Digest_init(
    SeosCryptoApi*                 api,
    SeosCryptoLib_Digest**         pDigObj,
    const SeosCryptoApi_Digest_Alg algorithm);

seos_err_t
SeosCryptoLib_Digest_free(
    SeosCryptoApi*        api,
    SeosCryptoLib_Digest* digObj);

seos_err_t
SeosCryptoLib_Digest_clone(
    SeosCryptoApi*              api,
    SeosCryptoLib_Digest*       dstDigObj,
    const SeosCryptoLib_Digest* srcDigObj);

seos_err_t
SeosCryptoLib_Digest_process(
    SeosCryptoApi*        api,
    SeosCryptoLib_Digest* digObj,
    const void*           data,
    const size_t          len);

seos_err_t
SeosCryptoLib_Digest_finalize(
    SeosCryptoApi*        api,
    SeosCryptoLib_Digest* digObj,
    void*                 digest,
    size_t*               digestSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoLib_Key_generate(
    SeosCryptoApi*                api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Spec* spec);

seos_err_t
SeosCryptoLib_Key_makePublic(
    SeosCryptoApi*                   api,
    SeosCryptoLib_Key**              pPubKeyObj,
    const SeosCryptoLib_Key*         prvKeyObj,
    const SeosCryptoApi_Key_Attribs* attribs);

seos_err_t
SeosCryptoLib_Key_import(
    SeosCryptoApi*                api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoLib_Key*      wrapKeyObj,
    const SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoLib_Key_export(
    SeosCryptoApi*           api,
    const SeosCryptoLib_Key* keyObj,
    const SeosCryptoLib_Key* wrapKeyObj,
    SeosCryptoApi_Key_Data*  keyData);

seos_err_t
SeosCryptoLib_Key_getParams(
    SeosCryptoApi*           api,
    const SeosCryptoLib_Key* keyObj,
    void*                    keyParams,
    size_t*                  paramSize);

seos_err_t
SeosCryptoLib_Key_free(
    SeosCryptoApi*     api,
    SeosCryptoLib_Key* keyObj);

seos_err_t
SeosCryptoLib_Key_loadParams(
    SeosCryptoApi*                api,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize);

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoLib_Cipher_init(
    SeosCryptoApi*                 api,
    SeosCryptoLib_Cipher**         pCipherObj,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       keyObj,
    const void*                    iv,
    const size_t                   ivLen);

seos_err_t
SeosCryptoLib_Cipher_free(
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj);

seos_err_t
SeosCryptoLib_Cipher_process(
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize);

seos_err_t
SeosCryptoLib_Cipher_start(
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj,
    const void*           input,
    const size_t          inputSize);

seos_err_t
SeosCryptoLib_Cipher_finalize(
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj,
    void*                 output,
    size_t*               outputSize);

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoLib_Signature_init(
    SeosCryptoApi*                    ctx,
    SeosCryptoLib_Signature**         pSigObj,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey);

seos_err_t
SeosCryptoLib_Signature_free(
    SeosCryptoApi*           ctx,
    SeosCryptoLib_Signature* sigObj);


seos_err_t
SeosCryptoLib_Signature_sign(
    SeosCryptoApi*           ctx,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize);

seos_err_t
SeosCryptoLib_Signature_verify(
    SeosCryptoApi*           ctx,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize);

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoLib_Agreement_init(
    SeosCryptoApi*                    api,
    SeosCryptoLib_Agreement**         pAgrObj,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey);

seos_err_t
SeosCryptoLib_Agreement_free(
    SeosCryptoApi*           api,
    SeosCryptoLib_Agreement* agrObj);

seos_err_t
SeosCryptoLib_Agreement_agree(
    SeosCryptoApi*           api,
    SeosCryptoLib_Agreement* agrObj,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize);

/** @} */
