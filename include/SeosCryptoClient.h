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

#include "seos_err.h"
#include "SeosCryptoRpc.h"
#include "SeosCryptoCtx.h"

#define SeosCryptoClient_TO_SEOS_CRYPTO_CTX(self) (&(self)->parent)

typedef struct
{
    SeosCryptoCtx   parent;
    SeosCryptoRpc_Handle
    rpcHandle;      ///< pointer to be used in the rpc call, this pointer is not valid in our address space but will be used as a handle to tell the server which is the correct object in his address space
    void*
    clientDataport; ///< the client's address of the dataport shared with the server
}
SeosCryptoClient;

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
/**
 * @brief calls the remote seos crypto API. See SeosCryptoRpc_rngGetBytes()
 * and SeosCrypto_rngGetBytes()
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  used
  * @param buffer pointer to the memory where the return data is
 * @param dataLen data length
 *
 * @return an error code. See SeosCrypto_rngGetBytes()
 *
 */
seos_err_t
SeosCryptoClient_rngGetBytes(SeosCryptoCtx*       self,
                             void**               buffer,
                             size_t               dataLen);

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
                            unsigned int                algorithm,
                            void*                       iv,
                            size_t                      ivLen);
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
                                const void*                 data,
                                size_t                      dataLen,
                                void**                      digest,
                                size_t*                     digestSize);

INLINE seos_err_t
SeosCryptoClient_digestFinalize2(SeosCryptoClient*          self,
                                 SeosCrypto_DigestHandle    digestHandle,
                                 const void*                data,
                                 size_t                     len,
                                 void*                      digest,
                                 size_t                     digestSize)
{
    void* pDigest = digest;
    return SeosCryptoClient_digestFinalize(SeosCryptoClient_TO_SEOS_CRYPTO_CTX(
                                               self),
                                           digestHandle,
                                           data,
                                           len,
                                           &pDigest,
                                           &digestSize);
}

INLINE seos_err_t
SeosCryptoClient_digestFinalizeNoData(SeosCryptoClient*         self,
                                      SeosCrypto_DigestHandle   digestHandle,
                                      void**                    digest,
                                      size_t*                   digestSize)
{
    return SeosCryptoClient_digestFinalize(SeosCryptoClient_TO_SEOS_CRYPTO_CTX(
                                               self),
                                           digestHandle,
                                           NULL, 0,
                                           digest, digestSize);
}

INLINE seos_err_t
SeosCryptoClient_digestFinalizeNoData2(SeosCryptoClient*        self,
                                       SeosCrypto_DigestHandle  digestHandle,
                                       void*                    digest,
                                       size_t                   digestSize)
{
    void* pDigest = digest;
    return SeosCryptoClient_digestFinalizeNoData(self,
                                                 digestHandle,
                                                 &pDigest,
                                                 &digestSize);
}
/**
 * @brief implements SeosCryptoApi_keyGenerate() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyGenerate(SeosCryptoCtx*             api,
                             SeosCrypto_KeyHandle*      pKeyHandle,
                             unsigned int               algorithm,
                             unsigned int               flags,
                             size_t                     lenBits);
/**
 * @brief implements SeosCryptoApi_keyImport() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyImport(SeosCryptoCtx*               api,
                           SeosCrypto_KeyHandle*        pKeyHandle,
                           unsigned int                 algorithm,
                           unsigned int                 flags,
                           void const*                  keyImportBuffer,
                           size_t                       keyImportLenBits);
/**
 * @brief implements SeosCryptoApi_keyClose() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_keyClose(SeosCryptoCtx*            api,
                          SeosCrypto_KeyHandle      keyHandle);
/**
 * @brief implements SeosCryptoApi_cipherInit() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherInit(SeosCryptoCtx*                  api,
                            SeosCrypto_CipherHandle*        pKeyHandle,
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
                              void**                        output,
                              size_t*                       outputSize);

/**
 * @brief implements SeosCryptoApi_cipherUpdateAd() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherUpdateAd(SeosCryptoCtx*                api,
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
                                void**                      output,
                                size_t*                     outputSize);
/**
 * @brief implements SeosCryptoApi_cipherVerifyTag() in a rpc connection
 *
 */
seos_err_t
SeosCryptoClient_cipherVerifyTag(SeosCryptoCtx*              api,
                                 SeosCrypto_CipherHandle     cipherHandle,
                                 const void*                 tag,
                                 size_t                      tagLen);

/** @} */
