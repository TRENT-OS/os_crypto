/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoClient.h
 *
 * @brief Client object and functions to access the SEOS crypto API running on
 *  a camkes server. May of the functions here are just a wrapper of the
 *  SeosCryptoRpc functions running on the server and called by the client via
 *  RPC calls.
 *
 */
#pragma once

#include "SeosCryptoClient_Impl.h"
#include "SeosCryptoRpc.h"

#include "compiler.h"
#include "seos_err.h"

/**
 * @brief constructor of a seos crypto client
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  constructed
 * @param rpcHandle handle to point the remote RPC context
 * @param dataport pointer to the dataport connected to the server
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 *
 */
seos_err_t
SeosCryptoClient_init(SeosCryptoClient*     self,
                      SeosCryptoRpc_Handle  rpcHandle,
                      void*                 dataport);
/**
 * @brief destructor of a seos crypto client
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  destructed
 *
 */
void
SeosCryptoClient_free(SeosCryptoCtx* api);

// -------------------------------- RNG API ------------------------------------

/**
 * @brief implements SeosCryptoApi_rngGetBytes() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_rngGetBytes(SeosCryptoCtx*             self,
                             const SeosCryptoRng_Flags  flags,
                             void*                      buf,
                             const size_t               bufLen);

/**
 * @brief implements SeosCryptoApi_rngReSeed() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_rngReSeed(SeosCryptoCtx*   self,
                           const void*      seed,
                           const size_t     seedLen);

// ------------------------------ Digest API -----------------------------------

/**
 * @brief implements SeosCryptoApi_digestInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_digestInit(SeosCryptoCtx*                      api,
                            SeosCrypto_DigestHandle*            pDigestHandle,
                            const SeosCryptoDigest_Algorithm    algorithm);

/**
 * @brief implements SeosCryptoApi_digestFree() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_digestFree(SeosCryptoCtx*                  api,
                            const SeosCrypto_DigestHandle   digestHandle);

/**
 * @brief implements SeosCryptoApi_digestProcess() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_digestProcess(SeosCryptoCtx*                   api,
                               const SeosCrypto_DigestHandle    digestHandle,
                               const void*                      data,
                               const size_t                     dataLen);
/**
 * @brief implements SeosCryptoApi_digestFinalize() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoCtx*                  api,
                                const SeosCrypto_DigestHandle   digestHandle,
                                void*                           digest,
                                size_t*                         digestSize);

// ----------------------------- Signature API ---------------------------------

/**
 * @brief implements SeosCryptoApi_signatureInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_signatureInit(SeosCryptoCtx*                       api,
                               SeosCrypto_SignatureHandle*          pSigHandle,
                               const SeosCryptoSignature_Algorithm  algorithm,
                               const SeosCrypto_KeyHandle_v5           prvHandle,
                               const SeosCrypto_KeyHandle_v5           pubHandle);

/**
 * @brief implements SeosCryptoApi_signatureFree() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_signatureFree(SeosCryptoCtx*                   api,
                               const SeosCrypto_SignatureHandle sigHandle);

/**
 * @brief implements SeosCryptoApi_signatureSign() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_signatureSign(SeosCryptoCtx*                   api,
                               const SeosCrypto_SignatureHandle sigHandle,
                               const void*                      hash,
                               const size_t                     hashSize,
                               void*                            signature,
                               size_t*                          signatureSize);

/**
 * @brief implements SeosCryptoApi_signatureVerify() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_signatureVerify(SeosCryptoCtx*                     api,
                                 const SeosCrypto_SignatureHandle   sigHandle,
                                 const void*                        hash,
                                 const size_t                       hashSize,
                                 const void*                        signature,
                                 const size_t                       signatureSize);

// ----------------------------- Agreement API ---------------------------------

/**
 * @brief implements SeosCryptoApi_agreementInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_agreementInit(SeosCryptoCtx*                       api,
                               SeosCrypto_AgreementHandle*          pAgrHandle,
                               const SeosCryptoAgreement_Algorithm  algorithm,
                               const SeosCrypto_KeyHandle           prvHandle);

/**
 * @brief implements SeosCryptoApi_agreementFree() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_agreementFree(SeosCryptoCtx*                       api,
                               const SeosCrypto_AgreementHandle     agrHandle);

/**
 * @brief implements SeosCryptoApi_agreemenAgree() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_agreementAgree(SeosCryptoCtx*                      api,
                                const SeosCrypto_AgreementHandle    agrHandle,
                                const SeosCrypto_KeyHandle          pubHandle,
                                void*                               shared,
                                size_t*                             sharedSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoClient_keyGenerate_v5(SeosCryptoCtx*              api,
                                SeosCrypto_KeyHandle_v5*    pKeyHandle,
                                const SeosCryptoKey_Spec*   spec);

seos_err_t
SeosCryptoClient_keyMakePublic_v5(SeosCryptoCtx*                api,
                                  SeosCrypto_KeyHandle_v5*      pPubKeyHandle,
                                  const SeosCrypto_KeyHandle_v5 prvKeyHandle,
                                  const SeosCryptoKey_Attribs*  attribs);

seos_err_t
SeosCryptoClient_keyImport_v5(SeosCryptoCtx*                    api,
                              SeosCrypto_KeyHandle_v5*          pKeyHandle,
                              const SeosCrypto_KeyHandle_v5     wrapKeyHandle,
                              const SeosCryptoKey_Data*         keyData);

seos_err_t
SeosCryptoClient_keyExport_v5(SeosCryptoCtx*                    api,
                              const SeosCrypto_KeyHandle_v5     keyHandle,
                              const SeosCrypto_KeyHandle_v5     wrapKeyHandle,
                              SeosCryptoKey_Data*               keyData);

seos_err_t
SeosCryptoClient_keyGetParams_v5(SeosCryptoCtx*                 api,
                                 const SeosCrypto_KeyHandle_v5  keyHandle,
                                 void*                          keyParams,
                                 size_t*                        paramSize);

seos_err_t
SeosCryptoClient_keyLoadParams_v5(SeosCryptoCtx*            api,
                                  const SeosCryptoKey_Param name,
                                  void*                     keyParams,
                                  size_t*                   paramSize);

seos_err_t
SeosCryptoClient_keyFree_v5(SeosCryptoCtx*                  api,
                            const SeosCrypto_KeyHandle_v5   keyHandle);


/**
 * @brief implements SeosCryptoApi_keyGenerate() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyGenerate(SeosCryptoCtx*             ctx,
                             SeosCrypto_KeyHandle*      pKeyHandle,
                             const SeosCryptoKey_Type   type,
                             const SeosCryptoKey_Flags  flags,
                             const size_t               bits);

seos_err_t
SeosCryptoClient_keyGenerateFromParams(SeosCryptoCtx*             api,
                                       SeosCrypto_KeyHandle*      pKeyHandle,
                                       const SeosCryptoKey_Type   type,
                                       const SeosCryptoKey_Flags  flags,
                                       const void*                keyParams,
                                       const size_t               paramLen);

seos_err_t
SeosCryptoClient_keyDerivePublic(SeosCryptoCtx*             api,
                                 SeosCrypto_KeyHandle*      pPubKeyHandle,
                                 const SeosCrypto_KeyHandle prvKeyHandle,
                                 const SeosCryptoKey_Flags  flags);

/**
 * @brief implements SeosCryptoApi_keyGeneratePair() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyGeneratePair(SeosCryptoCtx*                 ctx,
                                 SeosCrypto_KeyHandle*          pPrvKeyHandle,
                                 SeosCrypto_KeyHandle*          pPubKeyHandle,
                                 const SeosCryptoKey_PairType   type,
                                 const SeosCryptoKey_Flags      prvFlags,
                                 const SeosCryptoKey_Flags      pubFlags,
                                 const size_t                   bits);

/**
 * @brief implements SeosCryptoApi_keyImport() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyImport(SeosCryptoCtx*               ctx,
                           SeosCrypto_KeyHandle*        pKeyHandle,
                           const SeosCrypto_KeyHandle   wrapKeyHandle,
                           const SeosCryptoKey_Type     type,
                           const SeosCryptoKey_Flags    flags,
                           const void*                  keyData,
                           const size_t                 keySize);

/**
 * @brief implements SeosCryptoApi_keyExport() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyExport(SeosCryptoCtx*               ctx,
                           const SeosCrypto_KeyHandle   keyHandle,
                           const SeosCrypto_KeyHandle   wrapKeyHandle,
                           SeosCryptoKey_Type*          type,
                           SeosCryptoKey_Flags*         flags,
                           void*                        keyData,
                           size_t*                      keySize);

/**
 * @brief implements SeosCryptoApi_keyExtractParams() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyExtractParams(SeosCryptoCtx*               api,
                                  const SeosCrypto_KeyHandle   keyHandle,
                                  void*                        buf,
                                  size_t*                      bufSize);

/**
 * @brief implements SeosCryptoApi_keyFree() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyFree(SeosCryptoCtx*             ctx,
                         const SeosCrypto_KeyHandle keyHandle);

// ------------------------------- Cipher API ----------------------------------

/**
 * @brief implements SeosCryptoApi_cipherInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherInit(SeosCryptoCtx*                      api,
                            SeosCrypto_CipherHandle*            pCipherHandle,
                            const SeosCryptoCipher_Algorithm    algorithm,
                            const SeosCrypto_KeyHandle          key,
                            const void*                         iv,
                            const size_t                        ivLen);
/**
 * @brief implements SeosCryptoApi_cipherFree() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherFree(SeosCryptoCtx*                  api,
                            const SeosCrypto_CipherHandle   cipherHandle);
/**
 * @brief implements SeosCryptoApi_cipherProcess() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherProcess(SeosCryptoCtx*                api,
                               const SeosCrypto_CipherHandle cipherHandle,
                               const void*                   data,
                               const size_t                  dataLen,
                               void*                         output,
                               size_t*                       outputSize);

/**
 * @brief implements SeosCryptoApi_cipherStart() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherStart(SeosCryptoCtx*                api,
                             SeosCrypto_CipherHandle       cipherHandle,
                             const void*                   ad,
                             const size_t                  adLen);
/**
 * @brief implements SeosCryptoApi_cipherFinalize() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherFinalize(SeosCryptoCtx*              api,
                                SeosCrypto_CipherHandle     cipherHandle,
                                void*                       output,
                                size_t*                     outputSize);

/** @} */
