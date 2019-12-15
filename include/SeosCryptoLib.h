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
#include "SeosCryptoCtx.h"

#include "lib/SeosCryptoRng.h"

#include "LibUtil/PointerVector.h"

#include "compiler.h"

// Internal types/defines/enums ------------------------------------------------

#define SeosCryptoLib_SIZE_BUFFER SeosCryptoApi_SIZE_DATAPORT

struct SeosCryptoLib
{
    SeosCryptoApi_Context parent;
    SeosCryptoApi_MemIf memIf;
    SeosCryptoRng cryptoRng;
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
};

// Internal functions ----------------------------------------------------------

/**
 * @brief initializes a crypto API context. Usually, no crypto context is needed
 *  and most function accept NULL as context. The parameter mallocFunc allows
 *  passing a custom function that will be called to allocate memory. The
 *  parameter freeFunc allows passing a custom function that will call to free
 *  memory. The parameter self will receive a context handle, that is used with
 *  further calls. It must be closed with crypto_api_close() eventually. This
 *  call will also initialize the internal RNG of the API.
 *
 * @param self (required) pointer to the seos_crypto context to initialize
 * @param cbFuncs (required) Callback functions for malloc, free, entropy
 * @param entropyCtx (optional) context for entropy callback
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_ABORTED if an internal error occured
 *
 */
seos_err_t
SeosCryptoLib_init(
    SeosCryptoLib*                 self,
    const SeosCryptoApi_Callbacks* cbFuncs,
    void*                          entropyCtx);

seos_err_t
SeosCryptoLib_free(
    SeosCryptoApi_Context* api);

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoLib_Rng_getBytes(
    SeosCryptoApi_Context*       api,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufLen);

seos_err_t
SeosCryptoLib_Rng_reseed(
    SeosCryptoApi_Context* api,
    const void*            seed,
    const size_t           seedLen);

// -------------------------------- MAC API ------------------------------------

seos_err_t
SeosCryptoLib_Mac_init(
    SeosCryptoApi_Context*      api,
    SeosCryptoLib_Mac**         pMacObj,
    const SeosCryptoApi_Mac_Alg algorithm);

seos_err_t
SeosCryptoLib_Mac_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macObj);

seos_err_t
SeosCryptoLib_Mac_start(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macObj,
    const void*            secret,
    const size_t           secretSize);

seos_err_t
SeosCryptoLib_Mac_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macObj,
    const void*            data,
    const size_t           dataLen);

seos_err_t
SeosCryptoLib_Mac_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macObj,
    void*                  mac,
    size_t*                macSize);

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoLib_Digest_init(
    SeosCryptoApi_Context*         api,
    SeosCryptoLib_Digest**         pDigObj,
    const SeosCryptoApi_Digest_Alg algorithm);

seos_err_t
SeosCryptoLib_Digest_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digObj);

seos_err_t
SeosCryptoLib_Digest_clone(
    SeosCryptoApi_Context*      api,
    SeosCryptoLib_Digest*       dstDigObj,
    const SeosCryptoLib_Digest* srcDigObj);

seos_err_t
SeosCryptoLib_Digest_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digObj,
    const void*            data,
    const size_t           len);

seos_err_t
SeosCryptoLib_Digest_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digObj,
    void*                  digest,
    size_t*                digestSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoLib_Key_generate(
    SeosCryptoApi_Context*        api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Spec* spec);

seos_err_t
SeosCryptoLib_Key_makePublic(
    SeosCryptoApi_Context*           api,
    SeosCryptoLib_Key**              pPubKeyObj,
    const SeosCryptoLib_Key*         prvKeyObj,
    const SeosCryptoApi_Key_Attribs* attribs);

seos_err_t
SeosCryptoLib_Key_import(
    SeosCryptoApi_Context*        api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoLib_Key*      wrapKeyObj,
    const SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoLib_Key_export(
    SeosCryptoApi_Context*   api,
    const SeosCryptoLib_Key* keyObj,
    const SeosCryptoLib_Key* wrapKeyObj,
    SeosCryptoApi_Key_Data*  keyData);

seos_err_t
SeosCryptoLib_Key_getParams(
    SeosCryptoApi_Context*   api,
    const SeosCryptoLib_Key* keyObj,
    void*                    keyParams,
    size_t*                  paramSize);

seos_err_t
SeosCryptoLib_Key_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Key*     keyObj);

seos_err_t
SeosCryptoLib_Key_loadParams(
    SeosCryptoApi_Context*        api,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize);

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoLib_Cipher_init(
    SeosCryptoApi_Context*         api,
    SeosCryptoLib_Cipher**         pCipherObj,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       keyObj,
    const void*                    iv,
    const size_t                   ivLen);

seos_err_t
SeosCryptoLib_Cipher_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj);

seos_err_t
SeosCryptoLib_Cipher_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    const void*            input,
    const size_t           inputSize,
    void*                  output,
    size_t*                outputSize);

seos_err_t
SeosCryptoLib_Cipher_start(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    const void*            input,
    const size_t           inputSize);

seos_err_t
SeosCryptoLib_Cipher_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    void*                  output,
    size_t*                outputSize);

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoLib_Signature_init(
    SeosCryptoApi_Context*            ctx,
    SeosCryptoLib_Signature**         pSigObj,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey);

seos_err_t
SeosCryptoLib_Signature_free(
    SeosCryptoApi_Context*   ctx,
    SeosCryptoLib_Signature* sigObj);


seos_err_t
SeosCryptoLib_Signature_sign(
    SeosCryptoApi_Context*   ctx,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize);

seos_err_t
SeosCryptoLib_Signature_verify(
    SeosCryptoApi_Context*   ctx,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize);

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoLib_Agreement_init(
    SeosCryptoApi_Context*            api,
    SeosCryptoLib_Agreement**         pAgrObj,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey);

seos_err_t
SeosCryptoLib_Agreement_free(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Agreement* agrObj);

seos_err_t
SeosCryptoLib_Agreement_agree(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Agreement* agrObj,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize);

/** @} */
