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

#include "seos/seos_err.h"
#include "seos/SeosCryptoRpc.h"

typedef struct
{
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
 * @params rpcHandle handle to point the remote RPC context
 * @params dataport pointer to the dataport connected to the server
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 *
 */
seos_err_t
SeosCryptoClient_init(SeosCryptoClient* self,
                      SeosCryptoRpc_Handle rpcHandle,
                      void* dataport);
/**
 * @brief destructor of a seos crypto client
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  destructed
 *
 */
void
SeosCryptoClient_deInit(SeosCryptoClient* self);
/**
 * @brief calls the remote seos crypto API. See SeosCryptoRpc_getRandomData()
 * and SeosCrypto_getRandomData()
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  used
 * @params flags see SeosCrypto_getRandomData()
 * @params buffer pointer to the memory where the return data is
 * @params dataLen see SeosCrypto_getRandomData
 *
 * @return an error code. See SeosCrypto_getRandomData()
 *
 */
seos_err_t
SeosCryptoClient_getRandomData(SeosCryptoClient*    self,
                               unsigned int         flags,
                               void const*          saltBuffer,
                               size_t               saltLen,
                               void**               buffer,
                               size_t               dataLen);
INLINE seos_err_t
SeosCryptoClient_getRandomData2(SeosCryptoClient*    self,
                                unsigned int         flags,
                                void const*          saltBuffer,
                                size_t               saltLen,
                                void*                buffer,
                                size_t               dataLen)
{
    void* randomDataPtr = NULL;
    seos_err_t retval = SeosCryptoClient_getRandomData(self,
                                                       flags,
                                                       saltBuffer,
                                                       saltLen,
                                                       &randomDataPtr,
                                                       dataLen);
    memcpy(buffer, randomDataPtr, dataLen);
    return retval;
}

/**
 * @brief initializes the digest context owned by the client but leaving in the
 *  server
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  used
 * @params algorithm the chosen digest algorithm
 * @param iv (optional) the initialization vector
 * @param ivLen the initialization vector length
 *
 * @return an error code. See SeosCryptoRpc_digestInit()
 *
 */
seos_err_t
SeosCryptoClient_digestInit(SeosCryptoClient*           self,
                            SeosCrypto_DigestHandle*    pDigestHandle,
                            unsigned int                algorithm,
                            void*                       iv,
                            size_t                      ivLen);
/**
 * @brief closes the digest context owned by the client but leaving in the
 *  server
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  used
 *
 */
seos_err_t
SeosCryptoClient_digestClose(SeosCryptoClient*          self,
                             SeosCrypto_DigestHandle    digestHandle);
/**
 * @brief updates the computation of the digest providing a new block of data
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  used
 * @params data (required) the data block
 * @params dataLen the length of the data block
 *
 * @return an error code. See SeosCryptoRpc_digestUpdate()
 *
 */
seos_err_t
SeosCryptoClient_digestUpdate(SeosCryptoClient*         self,
                              SeosCrypto_DigestHandle   digestHandle,
                              const void*               data,
                              size_t                    dataLen);
/**
 * @brief finalizes the computation of the digest providing a new block of data
 *  or padding (when data == NULL).
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  used
 * @param data (optional) the data block. When not provided (== NULL) then
 *  padding is done
 * @param dataLen the length of the data block
 * @param digest (required) a pointer to the buffer containing the digest.
 *  When *digest == NULL then a buffer is provided as output parameter otherwise
 *  if provided by the caller then it is just used. In this last case
 *  *digestSize is taken first as input to check the boundaries of the buffer
 *  and then in any case is set to the size of the digest before to return
 * @param digestSize (required) size of digest. Can work both as input or
 *  output parameter as described for \p digest
 *
 * @return an error code. See SeosCryptoRpc_digestUpdate()
 *
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL if the size of the digest buffer provided
 *  by the caller is not enough to hold the data generated by the server
 *
 */
seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoClient*           self,
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
    return SeosCryptoClient_digestFinalize(self,
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
    return SeosCryptoClient_digestFinalize(self,
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
seos_err_t
SeosCryptoClient_keyGenerate(SeosCryptoClient*        self,
                             SeosCrypto_KeyHandle*    pKeyHandle,
                             unsigned int             algorithm,
                             unsigned int             flags,
                             size_t                   lenBits);
seos_err_t
SeosCryptoClient_keyImport(SeosCryptoClient*      self,
                           SeosCrypto_KeyHandle*  pKeyHandle,
                           unsigned int           algorithm,
                           unsigned int           flags,
                           void const*            keyImportBuffer,
                           size_t                 keyImportLenBits);

seos_err_t
SeosCryptoClient_keyClose(SeosCryptoClient*     self,
                          SeosCrypto_KeyHandle  keyHandle);
/**
 * @brief initializes the digest context owned by the client but leaving in the
 *  server
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  used
 * @param algorithm the cipher algorithm
 * @param key (required) the cipher key
 * @param iv (optional) the initialization vector
 * @param ivLen the initialization vector length
 *
 * @return an error code
 *
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 *
 */
seos_err_t
SeosCryptoClient_cipherInit(SeosCryptoClient*           self,
                            SeosCrypto_KeyHandle*       pKeyHandle,
                            unsigned int                algorithm,
                            SeosCrypto_KeyHandle        key,
                            void*                       iv,
                            size_t                      ivLen);
/**
 * @brief closes the digest context owned by the client but leaving in the
 *  server
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  used
 *
 */
seos_err_t
SeosCryptoClient_cipherClose(SeosCryptoClient*          self,
                             SeosCrypto_CipherHandle    cipherHandle);
/**
 * @brief perform cipher operation on a block
 *
 * @param self (required) pointer to context
 * @param data (required) input buffer
 * @param dataLen input buffer size
 * @param output (required) input/output parameter cointaining the pointer to
 *  the output buffer. If content is == NULL, then it is set to a local (to the
 *  context) buffer and the content of \p outputSize is set to the correct value
 *  of the amount of written data. Otherwise (!= NULL) the given buffer is used
 *  as output and the value in \p outputSize is used (in the meaning of capacity
 *  of the buffer) for boundary check before writing. If write is possible then
 *  the value of \p outputSize is set to the correct value of the amount of
 *  written data.
 * @param outputSize (required) input/output parameter holding the capacity/size
 *  of \p output
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 * @retval SEOS_ERROR_ABORTED if the underlying implementation of the algorithm
 *  fails for any reason or the output buffer is not big enough
 *
 */
seos_err_t
SeosCryptoClient_cipherUpdate(SeosCryptoClient*         self,
                              SeosCrypto_CipherHandle   cipherHandle,
                              const void*               data,
                              size_t                    dataLen,
                              void**                    output,
                              size_t*                   outputSize);
/**
 * @brief perform operation on final block, applies padding automatically if
 *  requested
 *
 * @param self (required) pointer to context
 * @param input (required) input buffer
 * @param inputSize input buffer size
 * @param output (optional) input/output parameter cointaining the pointer to
 *  the output buffer. If content is == NULL, then it is set to a local (to the
 *  context) buffer and the content of \p outputSize is set to the correct value
 *  of the amount of written data. Otherwise (!= NULL) the given buffer is used
 *  as output and the value in \p outputSize is used (in the meaning of capacity
 *  of the buffer) for boundary check before writing. If write is possible then
 *  the value of \p outputSize is set to the correct value of the amount of
 *  written data.
 * @param outputSize (required) input/output parameter holding the capacity/size
 *  of \p output
 * @param tag (optional) input/output parameter cointaining the pointer to
 *  the final tag buffer. It follows the same logic as output parameter.
 * @param tagSize (required) input/output parameter holding the capacity/size
 *  of \p tag
 *
 * @return an error code.  See SeosCryptoRpc_cipherFinalize()
 *
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 * @retval SEOS_ERROR_ABORTED if the underlying implementation of the algorithm
 *  fails for any reason or the output buffer is not big enough
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL if the size of the digest buffer provided
 *  by the caller is not enough to hold the data generated by the server
 *
 */
seos_err_t
SeosCryptoClient_cipherFinalize(SeosCryptoClient*       self,
                                SeosCrypto_CipherHandle cipherHandle,
                                const void*             data,
                                size_t                  dataLen,
                                void**                  digest,
                                size_t*                 digestSize);

/** @} */
