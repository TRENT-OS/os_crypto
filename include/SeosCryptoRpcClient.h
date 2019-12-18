/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoRpcClient.h
 *
 * @brief Client object and functions to access the SEOS crypto API running on
 *  a camkes server. May of the functions here are just a wrapper of the
 *  SeosCryptoRpcServer functions running on the server and called by the client via
 *  RPC calls.
 *
 */

#pragma once

#include "SeosCryptoApi.h"
#include "SeosCryptoCtx.h"

// Internal types/defines/enums ------------------------------------------------

typedef struct
{
    SeosCryptoApi_Context parent;
    /**
     * pointer to be used in the rpc call, this pointer is not valid in our address
     * tell the server which is the correct object in his address space
     * */
    SeosCryptoApi_RpcServer rpcHandle;
    /**
     * the client's address of the dataport shared with the server
     */
    void* clientDataport;
}
SeosCryptoRpcClient;

// Internal functions ----------------------------------------------------------

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
SeosCryptoRpcClient_init(SeosCryptoRpcClient*    self,
                         SeosCryptoApi_RpcServer rpcHandle,
                         void*                   dataport);

seos_err_t
SeosCryptoRpcClient_free(SeosCryptoApi_Context* api);

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpcClient_rngGetBytes(SeosCryptoApi_Context*       self,
                                const SeosCryptoApi_Rng_Flag flags,
                                void*                        buf,
                                const size_t                 bufLen);

seos_err_t
SeosCryptoRpcClient_rngReSeed(SeosCryptoApi_Context* self,
                              const void*            seed,
                              const size_t           seedLen);

// -------------------------------- MAC API ------------------------------------

seos_err_t
SeosCryptoRpcClient_macInit(SeosCryptoApi_Context*      api,
                            SeosCryptoApi_Mac*          pMacHandle,
                            const SeosCryptoApi_Mac_Alg algorithm);

seos_err_t
SeosCryptoRpcClient_macFree(SeosCryptoApi_Context*  api,
                            const SeosCryptoApi_Mac macHandle);

seos_err_t
SeosCryptoRpcClient_macStart(SeosCryptoApi_Context*  api,
                             const SeosCryptoApi_Mac macHandle,
                             const void*             secret,
                             const size_t            secretSize);

seos_err_t
SeosCryptoRpcClient_macProcess(SeosCryptoApi_Context*  api,
                               const SeosCryptoApi_Mac macHandle,
                               const void*             data,
                               const size_t            dataLen);

seos_err_t
SeosCryptoRpcClient_macFinalize(SeosCryptoApi_Context*  api,
                                const SeosCryptoApi_Mac macHandle,
                                void*                   mac,
                                size_t*                 macSize);

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcClient_digestInit(SeosCryptoApi_Context*         api,
                               SeosCryptoApi_Digest*          pDigestHandle,
                               const SeosCryptoApi_Digest_Alg algorithm);

seos_err_t
SeosCryptoRpcClient_digestFree(SeosCryptoApi_Context*     api,
                               const SeosCryptoApi_Digest digestHandle);

seos_err_t
SeosCryptoRpcClient_digestClone(SeosCryptoApi_Context*     api,
                                const SeosCryptoApi_Digest dstDigHandle,
                                const SeosCryptoApi_Digest srcDigHandle);

seos_err_t
SeosCryptoRpcClient_digestProcess(SeosCryptoApi_Context*     api,
                                  const SeosCryptoApi_Digest digestHandle,
                                  const void*                data,
                                  const size_t               dataLen);

seos_err_t
SeosCryptoRpcClient_digestFinalize(SeosCryptoApi_Context*     api,
                                   const SeosCryptoApi_Digest digestHandle,
                                   void*                      digest,
                                   size_t*                    digestSize);

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpcClient_signatureInit(SeosCryptoApi_Context*
                                  api,
                                  SeosCryptoApi_Signature*          pSigHandle,
                                  const SeosCryptoApi_Signature_Alg algorithm,
                                  const SeosCryptoApi_Digest_Alg    digest,
                                  const SeosCryptoApi_Key           prvHandle,
                                  const SeosCryptoApi_Key           pubHandle);

seos_err_t
SeosCryptoRpcClient_signatureFree(SeosCryptoApi_Context*        api,
                                  const SeosCryptoApi_Signature sigHandle);

seos_err_t
SeosCryptoRpcClient_signatureSign(SeosCryptoApi_Context*        api,
                                  const SeosCryptoApi_Signature sigHandle,
                                  const void*                   hash,
                                  const size_t                  hashSize,
                                  void*                         signature,
                                  size_t*                       signatureSize);

seos_err_t
SeosCryptoRpcClient_signatureVerify(SeosCryptoApi_Context*
                                    api,
                                    const SeosCryptoApi_Signature sigHandle,
                                    const void*                   hash,
                                    const size_t                  hashSize,
                                    const void*                   signature,
                                    const size_t                  signatureSize);

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpcClient_agreementInit(SeosCryptoApi_Context*
                                  api,
                                  SeosCryptoApi_Agreement*          pAgrHandle,
                                  const SeosCryptoApi_Agreement_Alg algorithm,
                                  const SeosCryptoApi_Key           prvHandle);

seos_err_t
SeosCryptoRpcClient_agreementFree(SeosCryptoApi_Context*
                                  api,
                                  const SeosCryptoApi_Agreement agrHandle);

seos_err_t
SeosCryptoRpcClient_agreementAgree(SeosCryptoApi_Context*
                                   api,
                                   const SeosCryptoApi_Agreement agrHandle,
                                   const SeosCryptoApi_Key       pubHandle,
                                   void*                         shared,
                                   size_t*                       sharedSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpcClient_keyGenerate(SeosCryptoApi_Context*        api,
                                SeosCryptoApi_Key*            pKeyHandle,
                                const SeosCryptoApi_Key_Spec* spec);

seos_err_t
SeosCryptoRpcClient_keyMakePublic(SeosCryptoApi_Context*           api,
                                  SeosCryptoApi_Key*               pPubKeyHandle,
                                  const SeosCryptoApi_Key          prvKeyHandle,
                                  const SeosCryptoApi_Key_Attribs* attribs);

seos_err_t
SeosCryptoRpcClient_keyImport(SeosCryptoApi_Context*        api,
                              SeosCryptoApi_Key*            pKeyHandle,
                              const SeosCryptoApi_Key       wrapKeyHandle,
                              const SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoRpcClient_keyExport(SeosCryptoApi_Context*  api,
                              const SeosCryptoApi_Key keyHandle,
                              const SeosCryptoApi_Key wrapKeyHandle,
                              SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoRpcClient_keyGetParams(SeosCryptoApi_Context*  api,
                                 const SeosCryptoApi_Key keyHandle,
                                 void*                   keyParams,
                                 size_t*                 paramSize);

seos_err_t
SeosCryptoRpcClient_keyLoadParams(SeosCryptoApi_Context*        api,
                                  const SeosCryptoApi_Key_Param name,
                                  void*                         keyParams,
                                  size_t*                       paramSize);

seos_err_t
SeosCryptoRpcClient_keyFree(SeosCryptoApi_Context*  api,
                            const SeosCryptoApi_Key keyHandle);

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoRpcClient_cipherInit(SeosCryptoApi_Context*         api,
                               SeosCryptoApi_Cipher*          pCipherHandle,
                               const SeosCryptoApi_Cipher_Alg algorithm,
                               const SeosCryptoApi_Key        key,
                               const void*                    iv,
                               const size_t                   ivLen);

seos_err_t
SeosCryptoRpcClient_cipherFree(SeosCryptoApi_Context*     api,
                               const SeosCryptoApi_Cipher cipherHandle);

seos_err_t
SeosCryptoRpcClient_cipherProcess(SeosCryptoApi_Context*     api,
                                  const SeosCryptoApi_Cipher cipherHandle,
                                  const void*                data,
                                  const size_t               dataLen,
                                  void*                      output,
                                  size_t*                    outputSize);

seos_err_t
SeosCryptoRpcClient_cipherStart(SeosCryptoApi_Context* api,
                                SeosCryptoApi_Cipher   cipherHandle,
                                const void*            ad,
                                const size_t           adLen);

seos_err_t
SeosCryptoRpcClient_cipherFinalize(SeosCryptoApi_Context* api,
                                   SeosCryptoApi_Cipher   cipherHandle,
                                   void*                  output,
                                   size_t*                outputSize);

/** @} */