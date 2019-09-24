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
SeosCryptoClient_deInit(SeosCryptoCtx* api);

// -------------------------------- RNG API ------------------------------------

/**
 * @brief implements SeosCryptoApi_rngGetBytes() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_rngGetBytes(SeosCryptoCtx*       self,
                             void*                buf,
                             size_t               bufLen);

/**
 * @brief implements SeosCryptoApi_rngReSeed() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_rngReSeed(SeosCryptoCtx*       self,
                           const void*          seed,
                           size_t               seedLen);

/**
 * @brief implements SeosCryptoApi_digestInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_digestInit(SeosCryptoCtx*              api,
                            SeosCrypto_DigestHandle*    pDigestHandle,
                            unsigned int                algorithm);

// ------------------------------ Digest API -----------------------------------

/**
 * @brief implements SeosCryptoApi_digestClose() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_digestClose(SeosCryptoCtx*             api,
                             SeosCrypto_DigestHandle    digestHandle);

/**
 * @brief implements SeosCryptoApi_digestUpdate() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_digestUpdate(SeosCryptoCtx*                api,
                              SeosCrypto_DigestHandle       digestHandle,
                              const void*                   data,
                              size_t                        dataLen);
/**
 * @brief implements SeosCryptoApi_digestFinalize() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoCtx*              api,
                                SeosCrypto_DigestHandle     digestHandle,
                                void*                       digest,
                                size_t*                     digestSize);

// ----------------------------- Signature API ---------------------------------

/**
 * @brief implements SeosCryptoApi_signatureInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_signatureInit(SeosCryptoCtx*                api,
                               SeosCrypto_SignatureHandle*   pSigHandle,
                               unsigned int                  algorithm,
                               SeosCrypto_KeyHandle          prvHandle,
                               SeosCrypto_KeyHandle          pubHandle);

/**
 * @brief implements SeosCryptoApi_signatureDeInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_signatureDeInit(SeosCryptoCtx*               api,
                                 SeosCrypto_SignatureHandle   sigHandle);

/**
 * @brief implements SeosCryptoApi_signatureSign() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_signatureSign(SeosCryptoCtx*                 api,
                               SeosCrypto_SignatureHandle     sigHandle,
                               const void*                    hash,
                               size_t                         hashSize,
                               void**                         signature,
                               size_t*                        signatureSize);

/**
 * @brief implements SeosCryptoApi_signatureVerify() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_signatureVerify(SeosCryptoCtx*                 api,
                                 SeosCrypto_SignatureHandle     sigHandle,
                                 const void*                    hash,
                                 size_t                         hashSize,
                                 const void*                    signature,
                                 size_t                         signatureSize);

// ----------------------------- Agreement API ---------------------------------

/**
 * @brief implements SeosCryptoApi_agreementInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_agreementInit(SeosCryptoCtx*                api,
                               SeosCrypto_AgreementHandle*   pAgrHandle,
                               unsigned int                  algorithm,
                               SeosCrypto_KeyHandle          prvHandle);

/**
 * @brief implements SeosCryptoApi_agreementDeInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_agreementDeInit(SeosCryptoCtx*               api,
                                 SeosCrypto_AgreementHandle   agrHandle);

/**
 * @brief implements SeosCryptoApi_agreemenAgree() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_agreementAgree(SeosCryptoCtx*                 api,
                                SeosCrypto_AgreementHandle     agrHandle,
                                SeosCrypto_KeyHandle           pubHandle,
                                void*                          shared,
                                size_t*                        sharedSize);

// -------------------------------- Key API ------------------------------------

/**
 * @brief implements SeosCryptoApi_keyInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyInit(SeosCryptoCtx*                   ctx,
                         SeosCrypto_KeyHandle*            keyHandle,
                         unsigned int                     type,
                         unsigned int                     flags,
                         size_t                           keySize);

/**
 * @brief implements SeosCryptoApi_keyGenerate() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyGenerate(SeosCryptoCtx*               ctx,
                             SeosCrypto_KeyHandle         keyHandle);

/**
 * @brief implements SeosCryptoApi_keyGeneratePair() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyGeneratePair(SeosCryptoCtx*           ctx,
                                 SeosCrypto_KeyHandle     prvKeyHandle,
                                 SeosCrypto_KeyHandle     pubKeyHandle);

/**
 * @brief implements SeosCryptoApi_keyImport() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyImport(SeosCryptoCtx*                 ctx,
                           SeosCrypto_KeyHandle           keyHandle,
                           SeosCrypto_KeyHandle           wrapKeyHandle,
                           const void*                    key,
                           size_t                         keyLen);

/**
 * @brief implements SeosCryptoApi_keyExport() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyExport(SeosCryptoCtx*                 ctx,
                           SeosCrypto_KeyHandle           keyHandle,
                           SeosCrypto_KeyHandle           wrapKeyHandle,
                           void*                          key,
                           size_t*                        keySize);

/**
 * @brief implements SeosCryptoApi_keyDeInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyDeInit(SeosCryptoCtx*                 ctx,
                           SeosCrypto_KeyHandle           keyHandle);

// ------------------------------- Cipher API ----------------------------------

/**
 * @brief implements SeosCryptoApi_cipherInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherInit(SeosCryptoCtx*                  api,
                            SeosCrypto_CipherHandle*        pCipherHandle,
                            unsigned int                    algorithm,
                            SeosCrypto_KeyHandle            key,
                            const void*                     iv,
                            size_t                          ivLen);
/**
 * @brief implements SeosCryptoApi_cipherClose() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherClose(SeosCryptoCtx*             api,
                             SeosCrypto_CipherHandle    cipherHandle);
/**
 * @brief implements SeosCryptoApi_cipherUpdate() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherUpdate(SeosCryptoCtx*                api,
                              SeosCrypto_CipherHandle       cipherHandle,
                              const void*                   data,
                              size_t                        dataLen,
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
                             size_t                        adLen);
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
