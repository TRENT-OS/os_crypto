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
SeosCryptoRpcClient_Rng_getBytes(SeosCryptoApi_Context*       self,
                                 const SeosCryptoApi_Rng_Flag flags,
                                 void*                        buf,
                                 const size_t                 bufLen);

seos_err_t
SeosCryptoRpcClient_Rng_reseed(SeosCryptoApi_Context* self,
                               const void*            seed,
                               const size_t           seedLen);

// -------------------------------- MAC API ------------------------------------

seos_err_t
SeosCryptoRpcClient_Mac_init(SeosCryptoApi_Context*      api,
                             SeosCryptoApi_Mac*          pMacHandle,
                             const SeosCryptoApi_Mac_Alg algorithm);

seos_err_t
SeosCryptoRpcClient_Mac_free(SeosCryptoApi_Context*  api,
                             const SeosCryptoApi_Mac macHandle);

seos_err_t
SeosCryptoRpcClient_Mac_start(SeosCryptoApi_Context*  api,
                              const SeosCryptoApi_Mac macHandle,
                              const void*             secret,
                              const size_t            secretSize);

seos_err_t
SeosCryptoRpcClient_Mac_process(SeosCryptoApi_Context*  api,
                                const SeosCryptoApi_Mac macHandle,
                                const void*             data,
                                const size_t            dataLen);

seos_err_t
SeosCryptoRpcClient_Mac_finalize(SeosCryptoApi_Context*  api,
                                 const SeosCryptoApi_Mac macHandle,
                                 void*                   mac,
                                 size_t*                 macSize);

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoRpcClient_Digest_init(SeosCryptoApi_Context*         api,
                                SeosCryptoApi_Digest*          pDigestHandle,
                                const SeosCryptoApi_Digest_Alg algorithm);

seos_err_t
SeosCryptoRpcClient_Digest_free(SeosCryptoApi_Context*     api,
                                const SeosCryptoApi_Digest digestHandle);

seos_err_t
SeosCryptoRpcClient_Digest_clone(SeosCryptoApi_Context*     api,
                                 const SeosCryptoApi_Digest dstDigHandle,
                                 const SeosCryptoApi_Digest srcDigHandle);

seos_err_t
SeosCryptoRpcClient_Digest_process(SeosCryptoApi_Context*     api,
                                   const SeosCryptoApi_Digest digestHandle,
                                   const void*                data,
                                   const size_t               dataLen);

seos_err_t
SeosCryptoRpcClient_Digest_finalize(SeosCryptoApi_Context*     api,
                                    const SeosCryptoApi_Digest digestHandle,
                                    void*                      digest,
                                    size_t*                    digestSize);

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoRpcClient_Signature_init(SeosCryptoApi_Context*
                                   api,
                                   SeosCryptoApi_Signature*          pSigHandle,
                                   const SeosCryptoApi_Signature_Alg algorithm,
                                   const SeosCryptoApi_Digest_Alg    digest,
                                   const SeosCryptoApi_Key           prvHandle,
                                   const SeosCryptoApi_Key           pubHandle);

seos_err_t
SeosCryptoRpcClient_Signature_free(SeosCryptoApi_Context*        api,
                                   const SeosCryptoApi_Signature sigHandle);

seos_err_t
SeosCryptoRpcClient_Signature_sign(SeosCryptoApi_Context*        api,
                                   const SeosCryptoApi_Signature sigHandle,
                                   const void*                   hash,
                                   const size_t                  hashSize,
                                   void*                         signature,
                                   size_t*                       signatureSize);

seos_err_t
SeosCryptoRpcClient_Signature_verify(SeosCryptoApi_Context*
                                     api,
                                     const SeosCryptoApi_Signature sigHandle,
                                     const void*                   hash,
                                     const size_t                  hashSize,
                                     const void*                   signature,
                                     const size_t                  signatureSize);

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoRpcClient_Agreement_init(SeosCryptoApi_Context*
                                   api,
                                   SeosCryptoApi_Agreement*          pAgrHandle,
                                   const SeosCryptoApi_Agreement_Alg algorithm,
                                   const SeosCryptoApi_Key           prvHandle);

seos_err_t
SeosCryptoRpcClient_Agreement_free(SeosCryptoApi_Context*
                                   api,
                                   const SeosCryptoApi_Agreement agrHandle);

seos_err_t
SeosCryptoRpcClient_Agreement_agree(SeosCryptoApi_Context*
                                    api,
                                    const SeosCryptoApi_Agreement agrHandle,
                                    const SeosCryptoApi_Key       pubHandle,
                                    void*                         shared,
                                    size_t*                       sharedSize);

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoRpcClient_Key_generate(SeosCryptoApi_Context*        api,
                                 SeosCryptoApi_Key*            pKeyHandle,
                                 const SeosCryptoApi_Key_Spec* spec);

seos_err_t
SeosCryptoRpcClient_Key_makePublic(SeosCryptoApi_Context*           api,
                                   SeosCryptoApi_Key*               pPubKeyHandle,
                                   const SeosCryptoApi_Key          prvKeyHandle,
                                   const SeosCryptoApi_Key_Attribs* attribs);

seos_err_t
SeosCryptoRpcClient_Key_import(SeosCryptoApi_Context*        api,
                               SeosCryptoApi_Key*            pKeyHandle,
                               const SeosCryptoApi_Key       wrapKeyHandle,
                               const SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoRpcClient_Key_export(SeosCryptoApi_Context*  api,
                               const SeosCryptoApi_Key keyHandle,
                               const SeosCryptoApi_Key wrapKeyHandle,
                               SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoRpcClient_Key_getParams(SeosCryptoApi_Context*  api,
                                  const SeosCryptoApi_Key keyHandle,
                                  void*                   keyParams,
                                  size_t*                 paramSize);

seos_err_t
SeosCryptoRpcClient_Key_loadParams(SeosCryptoApi_Context*        api,
                                   const SeosCryptoApi_Key_Param name,
                                   void*                         keyParams,
                                   size_t*                       paramSize);

seos_err_t
SeosCryptoRpcClient_Key_free(SeosCryptoApi_Context*  api,
                             const SeosCryptoApi_Key keyHandle);

// ------------------------------- Cipher API ----------------------------------

seos_err_t
SeosCryptoRpcClient_Cipher_init(SeosCryptoApi_Context*         api,
                                SeosCryptoApi_Cipher*          pCipherHandle,
                                const SeosCryptoApi_Cipher_Alg algorithm,
                                const SeosCryptoApi_Key        key,
                                const void*                    iv,
                                const size_t                   ivLen);

seos_err_t
SeosCryptoRpcClient_Cipher_free(SeosCryptoApi_Context*     api,
                                const SeosCryptoApi_Cipher cipherHandle);

seos_err_t
SeosCryptoRpcClient_Cipher_process(SeosCryptoApi_Context*     api,
                                   const SeosCryptoApi_Cipher cipherHandle,
                                   const void*                data,
                                   const size_t               dataLen,
                                   void*                      output,
                                   size_t*                    outputSize);

seos_err_t
SeosCryptoRpcClient_Cipher_start(SeosCryptoApi_Context* api,
                                 SeosCryptoApi_Cipher   cipherHandle,
                                 const void*            ad,
                                 const size_t           adLen);

seos_err_t
SeosCryptoRpcClient_Cipher_finalize(SeosCryptoApi_Context* api,
                                    SeosCryptoApi_Cipher   cipherHandle,
                                    void*                  output,
                                    size_t*                outputSize);

/** @} */