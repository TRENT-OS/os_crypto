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
#include "SeosError.h"

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

seos_err_t
SeosCryptoClient_free(SeosCryptoCtx* api);

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoClient_rngGetBytes(SeosCryptoCtx*             self,
                             const SeosCryptoRng_Flags  flags,
                             void*                      buf,
                             const size_t               bufLen);

seos_err_t
SeosCryptoClient_rngReSeed(SeosCryptoCtx*   self,
                           const void*      seed,
                           const size_t     seedLen);

// -------------------------------- MAC API ------------------------------------

seos_err_t
SeosCryptoClient_macInit(SeosCryptoCtx*                 api,
                         SeosCrypto_MacHandle*          pMacHandle,
                         const SeosCryptoMac_Algorithm  algorithm);

seos_err_t
SeosCryptoClient_macFree(SeosCryptoCtx*             api,
                         const SeosCrypto_MacHandle macHandle);

seos_err_t
SeosCryptoClient_macStart(SeosCryptoCtx*                api,
                          const SeosCrypto_MacHandle    macHandle,
                          const void*                   secret,
                          const size_t                  secretSize);

seos_err_t
SeosCryptoClient_macProcess(SeosCryptoCtx*              api,
                            const SeosCrypto_MacHandle  macHandle,
                            const void*                 data,
                            const size_t                dataLen);

seos_err_t
SeosCryptoClient_macFinalize(SeosCryptoCtx*             api,
                             const SeosCrypto_MacHandle macHandle,
                             void*                      mac,
                             size_t*                    macSize);

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoClient_digestInit(SeosCryptoCtx*                      api,
                            SeosCrypto_DigestHandle*            pDigestHandle,
                            const SeosCryptoDigest_Algorithm    algorithm);

seos_err_t
SeosCryptoClient_digestFree(SeosCryptoCtx*                  api,
                            const SeosCrypto_DigestHandle   digestHandle);

seos_err_t
SeosCryptoClient_digestProcess(SeosCryptoCtx*                   api,
                               const SeosCrypto_DigestHandle    digestHandle,
                               const void*                      data,
                               const size_t                     dataLen);

seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoCtx*                  api,
                                const SeosCrypto_DigestHandle   digestHandle,
                                void*                           digest,
                                size_t*                         digestSize);

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoClient_signatureInit(SeosCryptoCtx*                       api,
                               SeosCrypto_SignatureHandle*          pSigHandle,
                               const SeosCryptoSignature_Algorithm  algorithm,
                               const SeosCrypto_KeyHandle           prvHandle,
                               const SeosCrypto_KeyHandle           pubHandle);

seos_err_t
SeosCryptoClient_signatureFree(SeosCryptoCtx*                   api,
                               const SeosCrypto_SignatureHandle sigHandle);

seos_err_t
SeosCryptoClient_signatureSign(SeosCryptoCtx*                   api,
                               const SeosCrypto_SignatureHandle sigHandle,
                               const void*                      hash,
                               const size_t                     hashSize,
                               void*                            signature,
                               size_t*                          signatureSize);

seos_err_t
SeosCryptoClient_signatureVerify(SeosCryptoCtx*                     api,
                                 const SeosCrypto_SignatureHandle   sigHandle,
                                 const void*                        hash,
                                 const size_t                       hashSize,
                                 const void*                        signature,
                                 const size_t                       signatureSize);

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoClient_agreementInit(SeosCryptoCtx*                       api,
                               SeosCrypto_AgreementHandle*          pAgrHandle,
                               const SeosCryptoAgreement_Algorithm  algorithm,
                               const SeosCrypto_KeyHandle           prvHandle);

seos_err_t
SeosCryptoClient_agreementFree(SeosCryptoCtx*                       api,
                               const SeosCrypto_AgreementHandle     agrHandle);

seos_err_t
SeosCryptoClient_agreementAgree(SeosCryptoCtx*                      api,
                                const SeosCrypto_AgreementHandle    agrHandle,
                                const SeosCrypto_KeyHandle          pubHandle,
                                void*                               shared,
                                size_t*                             sharedSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoClient_keyGenerate(SeosCryptoCtx*             api,
                             SeosCrypto_KeyHandle*      pKeyHandle,
                             const SeosCryptoKey_Spec*  spec);

seos_err_t
SeosCryptoClient_keyMakePublic(SeosCryptoCtx*               api,
                               SeosCrypto_KeyHandle*        pPubKeyHandle,
                               const SeosCrypto_KeyHandle   prvKeyHandle,
                               const SeosCryptoKey_Attribs* attribs);

seos_err_t
SeosCryptoClient_keyImport(SeosCryptoCtx*               api,
                           SeosCrypto_KeyHandle*        pKeyHandle,
                           const SeosCrypto_KeyHandle   wrapKeyHandle,
                           const SeosCryptoKey_Data*    keyData);

seos_err_t
SeosCryptoClient_keyExport(SeosCryptoCtx*               api,
                           const SeosCrypto_KeyHandle   keyHandle,
                           const SeosCrypto_KeyHandle   wrapKeyHandle,
                           SeosCryptoKey_Data*          keyData);

seos_err_t
SeosCryptoClient_keyGetParams(SeosCryptoCtx*                api,
                              const SeosCrypto_KeyHandle    keyHandle,
                              void*                         keyParams,
                              size_t*                       paramSize);

seos_err_t
SeosCryptoClient_keyLoadParams(SeosCryptoCtx*               api,
                               const SeosCryptoKey_Param    name,
                               void*                        keyParams,
                               size_t*                      paramSize);

seos_err_t
SeosCryptoClient_keyFree(SeosCryptoCtx*             api,
                         const SeosCrypto_KeyHandle keyHandle);

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoClient_cipherInit(SeosCryptoCtx*                      api,
                            SeosCrypto_CipherHandle*            pCipherHandle,
                            const SeosCryptoCipher_Algorithm    algorithm,
                            const SeosCrypto_KeyHandle          key,
                            const void*                         iv,
                            const size_t                        ivLen);

seos_err_t
SeosCryptoClient_cipherFree(SeosCryptoCtx*                  api,
                            const SeosCrypto_CipherHandle   cipherHandle);

seos_err_t
SeosCryptoClient_cipherProcess(SeosCryptoCtx*                api,
                               const SeosCrypto_CipherHandle cipherHandle,
                               const void*                   data,
                               const size_t                  dataLen,
                               void*                         output,
                               size_t*                       outputSize);

seos_err_t
SeosCryptoClient_cipherStart(SeosCryptoCtx*                api,
                             SeosCrypto_CipherHandle       cipherHandle,
                             const void*                   ad,
                             const size_t                  adLen);

seos_err_t
SeosCryptoClient_cipherFinalize(SeosCryptoCtx*              api,
                                SeosCrypto_CipherHandle     cipherHandle,
                                void*                       output,
                                size_t*                     outputSize);

/** @} */