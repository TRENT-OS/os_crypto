/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Server
 * @{
 *
 * @file SeosCryptoRpc.h
 *
 * @brief RPC functions to handle the requests of a SEOS crypto client on the
 * server's side
 *
 */

#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoDigest_Impl.h"
#include "SeosCryptoCipher_Impl.h"
#include "SeosCryptoKey_Impl.h"
#include "SeosCryptoRpc_Impl.h"
#include "SeosCrypto_Handles.h"

#include "SeosError.h"
#include "compiler.h"

/**
 * @brief constructor of a seos crypto RPC object
 *
 * @param self (required) pointer to the seos crypto rpc object to be
 *  constructed
 * @param seosCryptoApiCtx the SeosCrypto context needed to allocate the
 *  resources
 * @param serverDataport pointer to the dataport connected to the client
 *
 * @return an error code.
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_ABORTED if there is no way to allocate needed resources
 *
 */
seos_err_t
SeosCryptoRpc_init(SeosCryptoRpc* self,
                   SeosCrypto* seosCryptoApiCtx,
                   void* serverDataport);
/**
 * @brief constructor of a seos crypto RPC object
 *
 * @param self (required) pointer to the seos crypto rpc object to be
 *  destructed
 *
 */
seos_err_t
SeosCryptoRpc_free(SeosCryptoRpc* self);

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpc_rngGetBytes(SeosCryptoRpc*    self,
                          unsigned int      flags,
                          size_t            dataLen);

seos_err_t
SeosCryptoRpc_rngReSeed(SeosCryptoRpc*      self,
                        size_t              seedLen);

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpc_digestInit(SeosCryptoRpc*                 self,
                         SeosCrypto_DigestHandle*       pDigestHandle,
                         SeosCryptoDigest_Algorithm     algorithm);

seos_err_t
SeosCryptoRpc_digestFree(SeosCryptoRpc*            self,
                         SeosCrypto_DigestHandle   digestHandle);

seos_err_t
SeosCryptoRpc_digestProcess(SeosCryptoRpc*           self,
                            SeosCrypto_DigestHandle  digestHandle,
                            size_t                   inLen);

seos_err_t
SeosCryptoRpc_digestFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_DigestHandle    digestHandle,
                             size_t*                    digestSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpc_keyGenerate(SeosCryptoRpc*        self,
                          SeosCrypto_KeyHandle* pKeyHandle);

seos_err_t
SeosCryptoRpc_keyMakePublic(SeosCryptoRpc*          self,
                            SeosCrypto_KeyHandle*   pPubKeyHandle,
                            SeosCrypto_KeyHandle    prvKeyHandle);

seos_err_t
SeosCryptoRpc_keyImport(SeosCryptoRpc*          self,
                        SeosCrypto_KeyHandle*   pKeyHandle,
                        SeosCrypto_KeyHandle    wrapKeyHandle);

seos_err_t
SeosCryptoRpc_keyExport(SeosCryptoRpc*          self,
                        SeosCrypto_KeyHandle    keyHandle,
                        SeosCrypto_KeyHandle    wrapKeyHandle);

seos_err_t
SeosCryptoRpc_keyGetParams(SeosCryptoRpc*       self,
                           SeosCrypto_KeyHandle keyHandle,
                           size_t*              paramSize);

seos_err_t
SeosCryptoRpc_keyLoadParams(SeosCryptoRpc*          self,
                            SeosCryptoKey_Param     name,
                            size_t*                 paramSize);

seos_err_t
SeosCryptoRpc_keyFree(SeosCryptoRpc*        self,
                      SeosCrypto_KeyHandle  keyHandle);

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpc_signatureInit(SeosCryptoRpc*                   self,
                            SeosCrypto_SignatureHandle*      pSigHandle,
                            SeosCryptoSignature_Algorithm    algorithm,
                            SeosCrypto_KeyHandle             prvHandle,
                            SeosCrypto_KeyHandle             pubHandle);

seos_err_t
SeosCryptoRpc_signatureVerify(SeosCryptoRpc*                self,
                              SeosCrypto_SignatureHandle    sigHandle,
                              size_t                        hashSize,
                              size_t                        signatureSize);

seos_err_t
SeosCryptoRpc_signatureSign(SeosCryptoRpc*                self,
                            SeosCrypto_SignatureHandle    sigHandle,
                            size_t                        hashSize,
                            size_t*                       signatureSize);

seos_err_t
SeosCryptoRpc_signatureFree(SeosCryptoRpc*                  self,
                            SeosCrypto_SignatureHandle      sigHandle);


// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpc_agreementInit(SeosCryptoRpc*                   self,
                            SeosCrypto_AgreementHandle*      pAgrHandle,
                            SeosCryptoAgreement_Algorithm    algorithm,
                            SeosCrypto_KeyHandle             prvHandle);

seos_err_t
SeosCryptoRpc_agreementAgree(SeosCryptoRpc*                self,
                             SeosCrypto_AgreementHandle    agrHandle,
                             SeosCrypto_KeyHandle          pubHandle,
                             size_t*                       sharedSize);

seos_err_t
SeosCryptoRpc_agreementFree(SeosCryptoRpc*                self,
                            SeosCrypto_AgreementHandle    agrHandle);

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoRpc_cipherInit(SeosCryptoRpc*                 self,
                         SeosCrypto_CipherHandle*       pCipherHandle,
                         SeosCryptoCipher_Algorithm     algorithm,
                         SeosCrypto_KeyHandle           keyHandle,
                         size_t                         ivLen);

seos_err_t
SeosCryptoRpc_cipherFree(SeosCryptoRpc*                self,
                         SeosCrypto_CipherHandle       cipherHandle);

seos_err_t
SeosCryptoRpc_cipherProcess(SeosCryptoRpc*               self,
                            SeosCrypto_CipherHandle      cipherHandle,
                            size_t                       inputLen,
                            size_t*                      outputSize);

seos_err_t
SeosCryptoRpc_cipherStart(SeosCryptoRpc*             self,
                          SeosCrypto_CipherHandle    cipherHandle,
                          size_t                     len);

seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_CipherHandle    cipherHandle,
                             size_t*                    len);

/** @} */