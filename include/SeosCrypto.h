/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCrypto.h
 *
 * @brief SEOS Crypto context and functions
 *
 */
#pragma once

#include "SeosCryptoRng_Impl.h"
#include "SeosCryptoKey_Impl.h"
#include "SeosCryptoDigest_Impl.h"
#include "SeosCryptoCipher_Impl.h"
#include "SeosCrypto_Impl.h"

#include "SeosCrypto_Handles.h"

#include "compiler.h"
#include "seos_err.h"

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
SeosCrypto_init(SeosCrypto*                 self,
                const SeosCrypto_Callbacks* cbFuncs,
                void*                       entropyCtx);

/**
 * @brief closes the initialized crypto context and releases all the allocated
 *  resources
 *
 * @param self (required) pointer to the seos_crypto context
 *
 */
void
SeosCrypto_free(SeosCryptoCtx* api);

// -------------------------------- RNG API ------------------------------------

/**
 * @brief implements SeosCryptoApi_rngGetBytes() in a local connection
 *  (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_rngGetBytes(SeosCryptoCtx*               api,
                       const SeosCryptoRng_Flags    flags,
                       void*                        buf,
                       const size_t                 bufLen);

/**
 * @brief implements SeosCryptoApi_rngReSeed() in a local connection
 *  (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_rngReSeed(SeosCryptoCtx*     api,
                     const void*        seed,
                     const size_t       seedLen);

// ------------------------------ Digest API -----------------------------------
/**
 * @brief implements SeosCryptoApi_digestInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestInit(SeosCryptoCtx*                    api,
                      SeosCrypto_DigestHandle*          pDigestHandle,
                      const SeosCryptoDigest_Algorithm  algorithm);
/**
 * @brief implements SeosCryptoApi_digestInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestFree(SeosCryptoCtx*                api,
                      const SeosCrypto_DigestHandle digestHandle);
/**
 * @brief implements SeosCryptoApi_digestProcess() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestProcess(SeosCryptoCtx*                  api,
                         const SeosCrypto_DigestHandle   digestHandle,
                         const void*                     data,
                         const size_t                    len);
/**
 * @brief implements SeosCryptoApi_digestFinalize() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestFinalize(SeosCryptoCtx*                api,
                          const SeosCrypto_DigestHandle digestHandle,
                          void*                         digest,
                          size_t*                       digestSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCrypto_keyGenerate(SeosCryptoCtx*               api,
                       SeosCrypto_KeyHandle*        pKeyHandle,
                       const SeosCryptoKey_Spec*    spec);

seos_err_t
SeosCrypto_keyMakePublic(SeosCryptoCtx*                 api,
                         SeosCrypto_KeyHandle*          pPubKeyHandle,
                         const SeosCrypto_KeyHandle     prvKeyHandle,
                         const SeosCryptoKey_Attribs*   attribs);

seos_err_t
SeosCrypto_keyImport(SeosCryptoCtx*             api,
                     SeosCrypto_KeyHandle*      pKeyHandle,
                     const SeosCrypto_KeyHandle wrapKeyHandle,
                     const SeosCryptoKey_Data*  keyData);

seos_err_t
SeosCrypto_keyExport(SeosCryptoCtx*             api,
                     const SeosCrypto_KeyHandle keyHandle,
                     const SeosCrypto_KeyHandle wrapKeyHandle,
                     SeosCryptoKey_Data*        keyData);

seos_err_t
SeosCrypto_keyGetParams(SeosCryptoCtx*              api,
                        const SeosCrypto_KeyHandle  keyHandle,
                        void*                       keyParams,
                        size_t*                     paramSize);

seos_err_t
SeosCrypto_keyLoadParams(SeosCryptoCtx*             api,
                         const SeosCryptoKey_Param  name,
                         void*                      keyParams,
                         size_t*                    paramSize);

seos_err_t
SeosCrypto_keyFree(SeosCryptoCtx*                api,
                   const SeosCrypto_KeyHandle keyHandle);

// ------------------------------ Cipher API -----------------------------------

/**
 * @brief implements SeosCryptoApi_cipherInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherInit(SeosCryptoCtx*                    api,
                      SeosCrypto_CipherHandle*          pCipherHandle,
                      const SeosCryptoCipher_Algorithm  algorithm,
                      const SeosCrypto_KeyHandle        keyHandle,
                      const void*                       iv,
                      const size_t                      ivLen);
/**
 * @brief implements SeosCryptoApi_cipherFree() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherFree(SeosCryptoCtx*                api,
                      const SeosCrypto_CipherHandle cipherHandle);
/**
 * @brief implements SeosCryptoApi_cipherProcess() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherProcess(SeosCryptoCtx*                  api,
                         const SeosCrypto_CipherHandle   cipherHandle,
                         const void*                     input,
                         const size_t                    inputSize,
                         void*                           output,
                         size_t*                         outputSize);
/**
 * @brief implements SeosCryptoApi_cipherStart() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherStart(SeosCryptoCtx*                   api,
                       const SeosCrypto_CipherHandle    cipherHandle,
                       const void*                      input,
                       const size_t                     inputSize);
/**
 * @brief implements SeosCryptoApi_cipherFinalize() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherFinalize(SeosCryptoCtx*                api,
                          const SeosCrypto_CipherHandle cipherHandle,
                          void*                         output,
                          size_t*                       outputSize);

// ----------------------------- Signature API ---------------------------------

/**
 * @brief implements SeosCryptoApi_signatureInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_signatureInit(SeosCryptoCtx*                         api,
                         SeosCrypto_SignatureHandle*            pSigHandle,
                         const SeosCryptoSignature_Algorithm    algorithm,
                         const SeosCrypto_KeyHandle             prvHandle,
                         const SeosCrypto_KeyHandle             pubHandle);

/**
 * @brief implements SeosCryptoApi_signatureFree() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_signatureFree(SeosCryptoCtx*                     api,
                         const SeosCrypto_SignatureHandle   sigHandle);

/**
 * @brief implements SeosCryptoApi_signatureSign() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_signatureSign(SeosCryptoCtx*                     api,
                         const SeosCrypto_SignatureHandle   sigHandle,
                         const void*                        hash,
                         const size_t                       hashSize,
                         void*                              signature,
                         size_t*                            signatureSize);

/**
 * @brief implements SeosCryptoApi_signatureVerify() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_signatureVerify(SeosCryptoCtx*                   api,
                           const SeosCrypto_SignatureHandle sigHandle,
                           const void*                      hash,
                           const size_t                     hashSize,
                           const void*                      signature,
                           const size_t                     signatureSize);

// ----------------------------- Agreement API ---------------------------------

/**
 * @brief implements SeosCryptoApi_agreementInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_agreementInit(SeosCryptoCtx*                         api,
                         SeosCrypto_AgreementHandle*            pAgrHandle,
                         const SeosCryptoAgreement_Algorithm    algorithm,
                         const SeosCrypto_KeyHandle             prvHandle);

/**
 * @brief implements SeosCryptoApi_agreementFree() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_agreementFree(SeosCryptoCtx*                     api,
                         const SeosCrypto_AgreementHandle   agrHandle);

/**
 * @brief implements SeosCryptoApi_agreementAgree() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_agreementAgree(SeosCryptoCtx*                    api,
                          const SeosCrypto_AgreementHandle  agrHandle,
                          const SeosCrypto_KeyHandle        pubHandle,
                          void*                             shared,
                          size_t*                           sharedSize);

/** @} */
