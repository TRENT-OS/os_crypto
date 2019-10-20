/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Server
 * @{
 *
 * @file SeosCryptoRpc.h
 *
 * @brief RPC object and functions to handle the requests of a SEOS crypto
 *  client on the server's side
 *
 */
#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoDigest_Impl.h"
#include "SeosCryptoCipher_Impl.h"
#include "SeosCryptoKey_Impl.h"
#include "SeosCryptoKey_Impl_v5.h"
#include "SeosCryptoRpc_Impl.h"
#include "SeosCrypto_Handles.h"

#include "seos_err.h"
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
void
SeosCryptoRpc_free(SeosCryptoRpc* self);

// -------------------------------- RNG API ------------------------------------

/**
 * @brief rpc management of SeosCrypto_rngGetBytes()
 *
 */
seos_err_t
SeosCryptoRpc_rngGetBytes(SeosCryptoRpc*    self,
                          unsigned int      flags,
                          size_t            dataLen);

/**
 * @brief rpc management of SeosCrypto_rngReSeed()
 *
 */
seos_err_t
SeosCryptoRpc_rngReSeed(SeosCryptoRpc*      self,
                        size_t              seedLen);

// ------------------------------ Digest API -----------------------------------

/**
 * @brief rpc management of SeosCrypto_digestInit()
 *
 */
seos_err_t
SeosCryptoRpc_digestInit(SeosCryptoRpc*                 self,
                         SeosCrypto_DigestHandle*       pDigestHandle,
                         SeosCryptoDigest_Algorithm     algorithm);

/**
 * @brief rpc management of SeosCrypto_digestFree()
 *
 */
seos_err_t
SeosCryptoRpc_digestFree(SeosCryptoRpc*            self,
                         SeosCrypto_DigestHandle   digestHandle);

/**
 * @brief rpc management of SeosCrypto_digestProcess()
 *
 */
seos_err_t
SeosCryptoRpc_digestProcess(SeosCryptoRpc*           self,
                            SeosCrypto_DigestHandle  digestHandle,
                            size_t                   inLen);

/**
 * @brief rpc management of SeosCrypto_digestFinalize()
 *
 */
seos_err_t
SeosCryptoRpc_digestFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_DigestHandle    digestHandle,
                             size_t                     outSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpc_keyGenerate_v5(SeosCryptoRpc*             self,
                             SeosCrypto_KeyHandle_v5*   pKeyHandle);

seos_err_t
SeosCryptoRpc_keyMakePublic_v5(SeosCryptoRpc*           self,
                               SeosCrypto_KeyHandle_v5* pPubKeyHandle,
                               SeosCrypto_KeyHandle_v5  prvKeyHandle);

seos_err_t
SeosCryptoRpc_keyImport_v5(SeosCryptoRpc*           self,
                           SeosCrypto_KeyHandle_v5* pKeyHandle,
                           SeosCrypto_KeyHandle_v5  wrapKeyHandle);

seos_err_t
SeosCryptoRpc_keyExport_v5(SeosCryptoRpc*           self,
                           SeosCrypto_KeyHandle_v5  keyHandle,
                           SeosCrypto_KeyHandle_v5  wrapKeyHandle);

seos_err_t
SeosCryptoRpc_keyGetParams_v5(SeosCryptoRpc*            self,
                              SeosCrypto_KeyHandle_v5   keyHandle,
                              size_t                    paramSize);

seos_err_t
SeosCryptoRpc_keyLoadParams_v5(SeosCryptoRpc*       self,
                               SeosCryptoKey_Param  name,
                               size_t               paramSize);

seos_err_t
SeosCryptoRpc_keyFree_v5(SeosCryptoRpc*            self,
                         SeosCrypto_KeyHandle_v5   keyHandle);

/**
 * @brief rpc management of SeosCryptoRpc_keyGenerate()
 *
 */
seos_err_t
SeosCryptoRpc_keyGenerate(SeosCryptoRpc*         self,
                          SeosCrypto_KeyHandle*  pKeyHandle,
                          SeosCryptoKey_Type     type,
                          SeosCryptoKey_Flags    flags,
                          size_t                 bits);

seos_err_t
SeosCryptoRpc_keyDerivePublic(SeosCryptoRpc*        self,
                              SeosCrypto_KeyHandle* pPubKeyHandle,
                              SeosCrypto_KeyHandle  prvKeyHandle,
                              SeosCryptoKey_Flags   flags);

seos_err_t
SeosCryptoRpc_keyGenerateFromParams(SeosCryptoRpc*        self,
                                    SeosCrypto_KeyHandle* pKeyHandle,
                                    SeosCryptoKey_Type    type,
                                    SeosCryptoKey_Flags   flags,
                                    size_t                paramLen);

/**
 * @brief rpc management of SeosCryptoRpc_keyGeneratePair()
 *
 */
seos_err_t
SeosCryptoRpc_keyGeneratePair(SeosCryptoRpc*            self,
                              SeosCrypto_KeyHandle*     pPrvKeyHandle,
                              SeosCrypto_KeyHandle*     pPubKeyHandle,
                              SeosCryptoKey_PairType    type,
                              SeosCryptoKey_Flags       prvFlags,
                              SeosCryptoKey_Flags       pubFlags,
                              size_t                    bits);

/**
 * @brief rpc management of SeosCryptoRpc_keyImport()
 *
 */
seos_err_t
SeosCryptoRpc_keyImport(SeosCryptoRpc*          self,
                        SeosCrypto_KeyHandle*   pKeyHandle,
                        SeosCrypto_KeyHandle    wrapkeyHandle,
                        SeosCryptoKey_Type      type,
                        SeosCryptoKey_Flags     flags,
                        size_t                  keySize);

/**
 * @brief rpc management of SeosCryptoRpc_keyExport()
 *
 */
seos_err_t
SeosCryptoRpc_keyExport(SeosCryptoRpc*          self,
                        SeosCrypto_KeyHandle    keyHandle,
                        SeosCrypto_KeyHandle    wrapKeyHandle,
                        SeosCryptoKey_Type*     type,
                        SeosCryptoKey_Flags*    flags,
                        size_t                  bufSize);

/**
 * @brief rpc management of SeosCryptoRpc_keyExport()
 *
 */
seos_err_t
SeosCryptoRpc_keyExtractParams(SeosCryptoRpc*          self,
                               SeosCrypto_KeyHandle    keyHandle,
                               size_t                  bufSize);

/**
 * @brief rpc management of SeosCryptoRpc_keyFree()
 *
 */
seos_err_t
SeosCryptoRpc_keyFree(SeosCryptoRpc*                 self,
                      SeosCrypto_KeyHandle           keyHandle);

// ----------------------------- Signature API ---------------------------------

/**
 * @brief rpc management of SeosCrypto_signatureInit()
 *
 */
seos_err_t
SeosCryptoRpc_signatureInit(SeosCryptoRpc*                   self,
                            SeosCrypto_SignatureHandle*      pSigHandle,
                            SeosCryptoSignature_Algorithm    algorithm,
                            SeosCrypto_KeyHandle             prvHandle,
                            SeosCrypto_KeyHandle             pubHandle);

/**
 * @brief rpc management of SeosCrypto_signatureVerify()
 *
 */
seos_err_t
SeosCryptoRpc_signatureVerify(SeosCryptoRpc*                self,
                              SeosCrypto_SignatureHandle    sigHandle,
                              size_t                        hashSize,
                              size_t                        signatureSize);

/**
 * @brief rpc management of SeosCrypto_signatureSign()
 *
 */
seos_err_t
SeosCryptoRpc_signatureSign(SeosCryptoRpc*                self,
                            SeosCrypto_SignatureHandle    sigHandle,
                            size_t                        hashSize,
                            size_t                        signatureSize);

/**
 * @brief rpc management of SeosCrypto_signatureFree()
 *
 */
seos_err_t
SeosCryptoRpc_signatureFree(SeosCryptoRpc*                  self,
                            SeosCrypto_SignatureHandle      sigHandle);


// ----------------------------- Agreement API ---------------------------------

/**
 * @brief rpc management of SeosCrypto_agreementInit()
 *
 */
seos_err_t
SeosCryptoRpc_agreementInit(SeosCryptoRpc*                   self,
                            SeosCrypto_AgreementHandle*      pAgrHandle,
                            SeosCryptoAgreement_Algorithm    algorithm,
                            SeosCrypto_KeyHandle             prvHandle);

/**
 * @brief rpc management of SeosCrypto_agreementAgree()
 *
 */
seos_err_t
SeosCryptoRpc_agreementAgree(SeosCryptoRpc*                self,
                             SeosCrypto_AgreementHandle    agrHandle,
                             SeosCrypto_KeyHandle          pubHandle,
                             size_t                        sharedSize);

/**
 * @brief rpc management of SeosCrypto_agreementFree()
 *
 */
seos_err_t
SeosCryptoRpc_agreementFree(SeosCryptoRpc*                self,
                            SeosCrypto_AgreementHandle    agrHandle);

// ------------------------------- Cipher API ----------------------------------

/**
 * @brief rpc management of SeosCrypto_cipherInit()
 *
 */
seos_err_t
SeosCryptoRpc_cipherInit(SeosCryptoRpc*                 self,
                         SeosCrypto_CipherHandle*       pCipherHandle,
                         SeosCryptoCipher_Algorithm     algorithm,
                         SeosCrypto_KeyHandle           keyHandle,
                         size_t                         ivLen);
/**
 * @brief rpc management of SeosCrypto_cipherFree()
 *
 */
seos_err_t
SeosCryptoRpc_cipherFree(SeosCryptoRpc*                self,
                         SeosCrypto_CipherHandle       cipherHandle);
/**
 * @brief rpc management of SeosCrypto_cipherProcess()
 *
 */
seos_err_t
SeosCryptoRpc_cipherProcess(SeosCryptoRpc*               self,
                            SeosCrypto_CipherHandle      cipherHandle,
                            size_t                       inputLen,
                            size_t                       outputSize);
/**
 * @brief rpc management of SeosCrypto_cipherStart()
 *
 */
seos_err_t
SeosCryptoRpc_cipherStart(SeosCryptoRpc*             self,
                          SeosCrypto_CipherHandle    cipherHandle,
                          size_t                     len);

/**
 * @brief rpc management of SeosCrypto_cipherFinalize()
 *
 */
seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_CipherHandle    cipherHandle,
                             size_t                     len);


/** @} */
