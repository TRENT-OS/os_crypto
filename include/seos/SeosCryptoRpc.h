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
    SeosCrypto*
    seosCryptoCtx;  ///< crypto context to be used by the RPC object
    void*
    serverDataport;     ///< the server's address of the dataport shared with the client

    seos_rng_t        rng;
    SeosCryptoRng     seosCryptoRng;
    SeosCryptoCipher* seosCryptoCipher;
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
 * @brief calls SeosCrypto_getRandomData() using the server dataport as output
 *  buffer
 *
 * @return an error code. See SeosCrypto_getRandomData()
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
 * @brief creates a new instance of SeosCryptoDigest
 *
 * @param self (required) pointer to the seos crypto rpc object to be
 * @param algorithm
 * @param ivLen the initialization vector length saved in the server dataport
 *
 * @return an error code. See SeosCryptoDigest_ctor()
 *
 * @retval SEOS_ERROR_OPERATION_DENIED if an instance is already created
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE if out of memory resources
 *
 */
seos_err_t
SeosCryptoRpc_digestInit(SeosCryptoRpc*             self,
                         SeosCrypto_DigestHandle*   pDigestHandle,
                         SeosCryptoDigest_Algorithm algorithm,
                         size_t                     ivLen);
/**
 * @brief destroyes the instance of SeosCryptoDigest and frees resources
 *
 * @param self (required) pointer to the seos crypto rpc object to be used
 *
 * @return an error code. See SeosCryptoDigest_dtor()
 *
 */
void
SeosCryptoRpc_digestClose(SeosCryptoRpc* self,
                          SeosCrypto_DigestHandle   digestHandle);
/**
 * @brief calls SeosCryptoDigest_update() using the server dataport as input
 *  buffer.
 *  See SeosCryptoDigest_update()
 *
 */
seos_err_t
SeosCryptoRpc_digestUpdate(SeosCryptoRpc* self,
                           SeosCrypto_DigestHandle  digestHandle,
                           size_t len);
/**
 * @brief calls SeosCryptoDigest_finalize() using the server dataport as input
 *  buffer if len > 0 (otherwise paddinf happens). The result is consequently
 *  written in the same dataport. The first sizeof(size_t) bytes are the size
 *  of the result and the following bytes (according to the size stored as
 *  header) are the result itself.
 *  See SeosCryptoDigest_finalize()
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER if dataLen > PAGE_SIZE
 */
seos_err_t
SeosCryptoRpc_digestFinalize(SeosCryptoRpc*             self,
                             SeosCrypto_DigestHandle    digestHandle,
                             size_t                     len);
/**
 * @brief creates a new instance of SeosCryptoCipher
 *
 * @param self (required) pointer to the seos crypto rpc object to be
 * @param algorithm selected cipher algorithm
 * @param keyHandle handle of the key created by the client on the server
 * @param ivLen the initialization vector length saved in the server dataport
 *
 * @return an error code. See SeosCryptoCipher_ctor()
 *
 * @retval SEOS_ERROR_OPERATION_DENIED if an instance is already created
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE if out of memory resources
 *
 */
seos_err_t
SeosCryptoRpc_cipherInit(SeosCryptoRpc* self,
                         SeosCryptoCipher_Algorithm algorithm,
                         SeosCrypto_KeyHandle keyHandle,
                         size_t ivLen);
/**
 * @brief destroyes the instance of SeosCryptoCipher and frees resources
 *
 * @param self (required) pointer to the seos crypto rpc object to be used
 *
 * @return an error code. See SeosCryptoCipher_dtor()
 *
 */
void
SeosCryptoRpc_cipherClose(SeosCryptoRpc* self);
/**
 * @brief calls SeosCryptoCipher_update() using the server dataport as input
 *  buffer. The result is consequently written in the same dataport. The first
 *  sizeof(size_t) bytes are the size of the result and the following bytes
 *  (according to the size stored as header) are the result itself.
 *  See SeosCryptoDigest_finalize()
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER if dataLen > PAGE_SIZE
 * @retval SEOS_ERROR_ABORTED if the result cannot fit in the server dataport
 *
 */
seos_err_t
SeosCryptoRpc_cipherUpdate(SeosCryptoRpc* self,
                           size_t len);
/**
 * @brief calls SeosCryptoCipher_finalize() using the server dataport as input
 *  buffer. The result is consequently written in the same dataport. The first
 *  sizeof(size_t) bytes are the size of the result (cipher data) and the
 *  following bytes (according to the size stored as header) are the result
 *  itself. With same schema ([SIZE][DATA]) the tag is appended
 *  See SeosCryptoDigest_finalize()
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER if dataLen > PAGE_SIZE
 * @retval SEOS_ERROR_ABORTED if the result cannot fit in the server dataport
 */
seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc* self,
                             size_t len);
/**
 * @brief creates a random key and gives back and handle
 *
 * @param self (required) pointer to the seos crypto rpc object to be used
 * @param algorithm cipher algorithm for which the key is created
 * @param flags (e.g.: SeosCrypto_KEY_FLAGS_128_BIT)
 * @param pKeyHandle (required) pointer to the key handle.
 *  This is an <b>output</b> parameter
 *
 * @return an error code. See SeosCrypto_keyCreate()
 *
 */
seos_err_t
SeosCryptoRpc_keyCreate(SeosCryptoRpc* self,
                        SeosCryptoCipher_Algorithm algorithm,
                        unsigned int flags,
                        size_t lenBits,
                        SeosCrypto_KeyHandle* pKeyHandle);

/** @} */
