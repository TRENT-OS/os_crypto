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
 * @param mallocFunc (required) provided malloc function
 * @param freeFunc (required) provided free function
 * @param entropyFunc (required) provided entropy function for feeding the
 *  internal RNG
 * @param entropyCtx (optional) context for entropy function
 * @param seed (optional) seed for internal RNG
 * @param seedLen (optional) lenght of seed
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 *
 */
seos_err_t
SeosCrypto_init(SeosCrypto*             self,
                SeosCrypto_MallocFunc   mallocFunc,
                SeosCrypto_FreeFunc     freeFunc,
                SeosCrypto_EntropyFunc  entropyFunc,
                void*                   entropyCtx);

/**
 * @brief closes the initialized crypto context and releases all the allocated
 *  resources
 *
 * @param self (required) pointer to the seos_crypto context
 *
 */
void
SeosCrypto_deInit(SeosCryptoCtx* api);

// -------------------------------- RNG API ------------------------------------

/**
 * @brief implements SeosCryptoApi_rngGetBytes() in a local connection
 *  (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_rngGetBytes(SeosCryptoCtx*   api,
                       void*            buf,
                       size_t           bufLen);

/**
 * @brief implements SeosCryptoApi_rngReSeed() in a local connection
 *  (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_rngReSeed(SeosCryptoCtx*     api,
                     const void*        seed,
                     size_t             seedLen);

// ------------------------------ Digest API -----------------------------------
/**
 * @brief implements SeosCryptoApi_digestInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestInit(SeosCryptoCtx*                api,
                      SeosCrypto_DigestHandle*      pDigestHandle,
                      unsigned                      algorithm);
/**
 * @brief implements SeosCryptoApi_digestInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestClose(SeosCryptoCtx*               api,
                       SeosCrypto_DigestHandle      digestHandle);
/**
 * @brief implements SeosCryptoApi_digestUpdate() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestUpdate(SeosCryptoCtx*              api,
                        SeosCrypto_DigestHandle     digestHandle,
                        const void*                 data,
                        size_t                      len);
/**
 * @brief implements SeosCryptoApi_digestFinalize() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestFinalize(SeosCryptoCtx*                api,
                          SeosCrypto_DigestHandle       digestHandle,
                          void*                         digest,
                          size_t*                       digestSize);

// -------------------------------- Key API ------------------------------------

/**
 * @brief implements SeosCryptoApi_keyInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyInit(SeosCryptoCtx*                   api,
                   SeosCrypto_KeyHandle*            pKeyHandle,
                   unsigned int                     type,
                   unsigned int                     flags,
                   size_t                           bits);

/**
 * @brief implements SeosCryptoApi_keyGenerate() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyGenerate(SeosCryptoCtx*               api,
                       SeosCrypto_KeyHandle         keyHandle);

/**
 * @brief implements SeosCryptoApi_keyGeneratePair() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyGeneratePair(SeosCryptoCtx*           api,
                           SeosCrypto_KeyHandle     prvKeyHandle,
                           SeosCrypto_KeyHandle     pubKeyHandle);

/**
 * @brief implements SeosCryptoApi_keyImport() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyImport(SeosCryptoCtx*                 api,
                     SeosCrypto_KeyHandle           keyHandle,
                     SeosCrypto_KeyHandle           wrapKeyHandle,
                     const void*                    keyBytes,
                     size_t                         keySize);

/**
 * @brief implements SeosCryptoApi_keyExport() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyExport(SeosCryptoCtx*                 api,
                     SeosCrypto_KeyHandle           keyHandle,
                     SeosCrypto_KeyHandle           wrapKeyHandle,
                     void*                          buf,
                     size_t*                        bufSize);

/**
 * @brief implements SeosCryptoApi_keyDeInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyDeInit(SeosCryptoCtx*                 api,
                     SeosCrypto_KeyHandle           keyHandle);

// ------------------------------ Cipher API -----------------------------------

/**
 * @brief implements SeosCryptoApi_cipherInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherInit(SeosCryptoCtx*             api,
                      SeosCrypto_CipherHandle*   pCipherHandle,
                      unsigned int               algorithm,
                      SeosCrypto_KeyHandle       keyHandle,
                      const void*                iv,
                      size_t                     ivLen);
/**
 * @brief implements SeosCryptoApi_cipherClose() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherClose(SeosCryptoCtx*            api,
                       SeosCrypto_CipherHandle   cipherHandle);
/**
 * @brief implements SeosCryptoApi_cipherUpdate() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherUpdate(SeosCryptoCtx*              api,
                        SeosCrypto_CipherHandle     cipherHandle,
                        const void*                 input,
                        size_t                      inputSize,
                        void*                       output,
                        size_t*                     outputSize);
/**
 * @brief implements SeosCryptoApi_cipherStart() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherStart(SeosCryptoCtx*              api,
                       SeosCrypto_CipherHandle     cipherHandle,
                       const void*                 input,
                       size_t                      inputSize);
/**
 * @brief implements SeosCryptoApi_cipherFinalize() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherFinalize(SeosCryptoCtx*                api,
                          SeosCrypto_CipherHandle       cipherHandle,
                          void*                         output,
                          size_t*                       outputSize);

// ----------------------------- Signature API ---------------------------------

/**
 * @brief implements SeosCryptoApi_signatureInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_signatureInit(SeosCryptoCtx*                api,
                         SeosCrypto_SignatureHandle*   pSigHandle,
                         unsigned int                  algorithm,
                         SeosCrypto_KeyHandle          prvHandle,
                         SeosCrypto_KeyHandle          pubHandle);

/**
 * @brief implements SeosCryptoApi_signatureDeInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_signatureDeInit(SeosCryptoCtx*               api,
                           SeosCrypto_SignatureHandle   sigHandle);

/**
 * @brief implements SeosCryptoApi_signatureSign() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_signatureSign(SeosCryptoCtx*                 api,
                         SeosCrypto_SignatureHandle     sigHandle,
                         const void*                    hash,
                         size_t                         hashSize,
                         void**                         signature,
                         size_t*                        signatureSize);

/**
 * @brief implements SeosCryptoApi_signatureVerify() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_signatureVerify(SeosCryptoCtx*                 api,
                           SeosCrypto_SignatureHandle     sigHandle,
                           const void*                    hash,
                           size_t                         hashSize,
                           const void*                    signature,
                           size_t                         signatureSize);

// ----------------------------- Agreement API ---------------------------------

/**
 * @brief implements SeosCryptoApi_agreementInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_agreementInit(SeosCryptoCtx*                api,
                         SeosCrypto_AgreementHandle*   pAgrHandle,
                         unsigned int                  algorithm,
                         SeosCrypto_KeyHandle          prvHandle);

/**
 * @brief implements SeosCryptoApi_agreementDeInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_agreementDeInit(SeosCryptoCtx*               api,
                           SeosCrypto_AgreementHandle   agrHandle);

/**
 * @brief implements SeosCryptoApi_agreementComputeShared() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_agreementComputeShared(SeosCryptoCtx*                 api,
                                  SeosCrypto_AgreementHandle     agrHandle,
                                  SeosCrypto_KeyHandle           pubHandle,
                                  void**                         shared,
                                  size_t*                        sharedSize);

/** @} */
