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

#include "SeosCrypto.h"
#include "SeosCryptoDigest.h"
#include "SeosCryptoCipher.h"
#include "SeosCryptoKey.h"
#include "seos_rng.h"

typedef struct
{
    SeosCryptoApi*
    seosCryptoApi;  ///< crypto context to be used by the RPC object
    void*
    serverDataport;     ///< the server's address of the dataport shared with the client
}
SeosCryptoRpc;

typedef SeosCryptoRpc* SeosCryptoRpc_Handle;

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
SeosCryptoRpc_deInit(SeosCryptoRpc* self);
/**
 * @brief rpc management of SeosCrypto_getRandomData()
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER if dataLen > PAGE_SIZE
 *
 */
seos_err_t
SeosCryptoRpc_getRandomData(SeosCryptoRpc* self,
                            unsigned int flags,
                            size_t saltLen,
                            size_t dataLen);
/**
 * @brief rpc management of SeosCrypto_digestInit()
 *
 */
seos_err_t
SeosCryptoRpc_digestInit(SeosCryptoRpc*                 self,
                         SeosCrypto_DigestHandle*       pDigestHandle,
                         SeosCryptoDigest_Algorithm     algorithm,
                         size_t                         ivLen);
/**
 * @brief rpc management of SeosCrypto_digestClose()
 *
 */
seos_err_t
SeosCryptoRpc_digestClose(SeosCryptoRpc*            self,
                          SeosCrypto_DigestHandle   digestHandle);
/**
 * @brief rpc management of SeosCrypto_digestUpdate() using the server dataport
 *  as input
 *
 */
seos_err_t
SeosCryptoRpc_digestUpdate(SeosCryptoRpc*           self,
                           SeosCrypto_DigestHandle  digestHandle,
                           size_t                   len);
/**
 * @brief rpc management of SeosCrypto_digestFinalize(). It uses the server
 *  dataport as input buffer if len > 0 (otherwise padding happens). The result
 *  is consequently written in the same dataport. The first sizeof(size_t)
 *  bytes are the size of the result and the following bytes (according to the
 *  size stored as header) are the result itself.
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER if dataLen > PAGE_SIZE
 */
seos_err_t
SeosCryptoRpc_digestFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_DigestHandle    digestHandle,
                             size_t                     len);
/**
 * @brief rpc management of SeosCrypto_keyGenerate()
 *
 */
seos_err_t
SeosCryptoRpc_keyGenerate(SeosCryptoRpc*            self,
                          SeosCrypto_KeyHandle*     pKeyHandle,
                          unsigned int              algorithm,
                          unsigned int              flags,
                          size_t                    lenBits);
/**
 * @brief rpc management of SeosCrypto_keyImport()
 *
 */
seos_err_t
SeosCryptoRpc_keyImport(SeosCryptoRpc*          self,
                        SeosCrypto_KeyHandle*   pKeyHandle,
                        unsigned int            algorithm,
                        unsigned int            flags,
                        size_t                  keyImportLenBits);
/**
 * @brief rpc management of SeosCrypto_keyClose()
 *
 */
seos_err_t
SeosCryptoRpc_keyClose(SeosCryptoRpc*          self,
                       SeosCrypto_KeyHandle    keyHandle);

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
 * @brief rpc management of SeosCrypto_cipherClose()
 *
 */
seos_err_t
SeosCryptoRpc_cipherClose(SeosCryptoRpc*                self,
                          SeosCrypto_CipherHandle       cipherHandle);
/**
 * @brief rpc management of SeosCrypto_cipherUpdate()
 *
 */
seos_err_t
SeosCryptoRpc_cipherUpdate(SeosCryptoRpc*               self,
                           SeosCrypto_CipherHandle      cipherHandle,
                           size_t                       len);
/**
 * @brief rpc management of SeosCrypto_cipherFinalize()
 *
 */
seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_CipherHandle    cipherHandle,
                             size_t                     len);

/** @} */
