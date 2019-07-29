/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoAPI.h
 *
 * @brief SEOS Crypto API library
 *
 */
#pragma once

/***************************** Crypto functions *******************************/
/**
 * @brief generate random number
 *
 * @param cryptoCtx (required) pointer to the seos_crypto context
 * @param flags allows selecting a fast random source for bulk data or more
 *  secure source for cryptographically secure random data. Fast random data
 *  generation is usually implemented uses a PRNG seeded by a nonce obtained
 *  from a slow true RNG
 * @param saltBuffer (optional) is used with PRNGs only, it may be ignore if
 *  random data is obtained from a HW source
 * @param saltLen capacity of saltBuffer
 * @param buffer random data buffer container
 * @param len capacity of buffer
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_UNSUPPORTED requested random source is not supported or
 *  requested length of random data is not supported for this source
 * @retval SEOS_ERROR_ABORTED operation has been aborted, can happen if random
 *  source had an internal error or became unavailable during the operation. It
 *  may also happen if the operation is running for too long
 *
 */
seos_err_t
SeosCryptoApi_getRandomData(SeosCryptoCtx*  cryptoCtx,
                            unsigned int    flags,
                            void const*     saltBuffer,
                            size_t          saltLen,
                            void*           buffer,
                            size_t          dataLen);
/**
 * @brief initializes a digest context (local or remote) with the semantic of
 * SeosCryptoDigest_init() and gives back an handle to it
 *
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE
 * @retval SEOS_ERROR_INVALID_PARAMETER
 *
 */
seos_err_t
SeosCryptoApi_digestInit(SeosCryptoCtx*                 cryptoCtx,
                         SeosCrypto_DigestHandle*       pDigestHandle,
                         unsigned int                   algorithm,
                         void*                          iv,
                         size_t                         ivLen);
/**
 * @brief closes the digest context referred by \p digestHandle
 *
 * @retval SEOS_ERROR_INVALID_HANDLE
 *
 */
seos_err_t
SeosCryptoApi_digestClose(SeosCryptoCtx*                cryptoCtx,
                          SeosCrypto_DigestHandle       digestHandle);
/**
 * @brief given the reference to the digest context \p digestHandle, it performs
 * the semantic of SeosCryptoDigest_update()
 *
 * @retval SEOS_ERROR_INVALID_HANDLE
 *
 */
seos_err_t
SeosCryptoApi_digestUpdate(SeosCryptoCtx*               cryptoCtx,
                           SeosCrypto_DigestHandle      digestHandle,
                           const void*                  data,
                           size_t                       dataLen);
/**
 * @brief given the reference to the digest context \p digestHandle, it performs
 * the semantic of SeosCryptoDigest_finalize()
 *
 * @retval SEOS_ERROR_INVALID_HANDLE
 *
 */
seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoCtx*             cryptoCtx,
                             SeosCrypto_DigestHandle    digestHandle,
                             const void*                data,
                             size_t                     dataLen,
                             void**                     digest,
                             size_t*                    digestSize);
/**
 * @brief creates a random key and gives back an handle
 *
 * @param cryptoCtx (required) pointer to the seos crypto rpc object to be used
 * @param pKeyHandle (required) pointer to the key handle.
 *  This is an <b>output</b> parameter
 * @param algorithm cipher algorithm for which the key is created
 * @param flags \see SeosCryptoKey_Flags
 * @param lenBits lenth of the key in bits
 *
 * @return an error code
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE
 * @retval SEOS_ERROR_INVALID_PARAMETER
 *
 */
seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoCtx*            cryptoCtx,
                          SeosCrypto_KeyHandle*     pKeyHandle,
                          unsigned int              algorithm,
                          unsigned int              flags,
                          size_t                    lenBits);
/**
 * @brief imports a raw key via \p keyImportBuffer and gives back an handle.
 * Remaining parameters are like for SeosCryptoApi_keyGenerate()
 *
 */
seos_err_t
SeosCryptoApi_keyImport(SeosCryptoCtx*              cryptoCtx,
                        SeosCrypto_KeyHandle*       pKeyHandle,
                        unsigned int                algorithm,
                        unsigned int                flags,
                        void const*                 keyImportBuffer,
                        size_t                      keyImportLenBits);
/**
 * @brief closes the key context referred by \p keyHandle
 *
 * @retval SEOS_ERROR_INVALID_HANDLE
 *
 */
seos_err_t
SeosCryptoApi_keyClose(SeosCryptoCtx*           cryptoCtx,
                       SeosCrypto_KeyHandle     keyHandle);
/**
 * @brief initializes a cipher context (local or remote) with the semantic of
 * SeosCryptoCipher_init() and gives back an handle to it
 *
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE
 * @retval SEOS_ERROR_INVALID_PARAMETER
 */
seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoCtx*                 cryptoCtx,
                         SeosCrypto_CipherHandle*       pCipherHandle,
                         unsigned int                   algorithm,
                         SeosCrypto_KeyHandle           keyHandle,
                         void*                          iv,
                         size_t                         ivLen);
/**
 * @brief closes the cipher context referred by \p digestHandle
 *
 * @retval SEOS_ERROR_INVALID_HANDLE
 *
 */
seos_err_t
SeosCryptoApi_cipherClose(SeosCryptoCtx*                cryptoCtx,
                          SeosCrypto_CipherHandle       cipherHandle);
/**
 * @brief given the reference to the cipher context \p digestHandle, it performs
 * the semantic of SeosCryptoCipher_update()
 *
 * @retval SEOS_ERROR_INVALID_HANDLE
 *
 */
seos_err_t
SeosCryptoApi_cipherUpdate(SeosCryptoCtx*               cryptoCtx,
                           SeosCrypto_CipherHandle      cipherHandle,
                           const void*                  data,
                           size_t                       dataLen,
                           void**                       output,
                           size_t*                      outputSize);

/** @} */
