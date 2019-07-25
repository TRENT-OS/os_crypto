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

typedef struct SeosCryptoApi SeosCryptoApi;

typedef seos_err_t
(*SeosCryptoApi_GetRandomDataT)(SeosCryptoApi*  self,
                                unsigned int    flags,
                                void const*     saltBuffer,
                                size_t          saltLen,
                                void*           buffer,
                                size_t          dataLen);

typedef seos_err_t
(*SeosCryptoApi_digestInitT)(SeosCryptoApi*                 self,
                             SeosCrypto_DigestHandle*       pDigestHandle,
                             unsigned int                   algorithm,
                             void*                          iv,
                             size_t                         ivLen);

typedef seos_err_t
(*SeosCryptoApi_digestCloseT)(SeosCryptoApi*                self,
                              SeosCrypto_DigestHandle       digestHandle);

typedef seos_err_t
(*SeosCryptoApi_digestUpdateT)(SeosCryptoApi*               self,
                               SeosCrypto_DigestHandle      digestHandle,
                               const void*                  data,
                               size_t                       dataLen);

typedef seos_err_t
(*SeosCryptoApi_digestFinalizeT)(SeosCryptoApi*             self,
                                 SeosCrypto_DigestHandle    digestHandle,
                                 const void*                data,
                                 size_t                     dataLen,
                                 void**                     digest,
                                 size_t*                    digestSize);

typedef seos_err_t
(*SeosCryptoApi_keyGenerateT)(SeosCryptoApi*            self,
                              SeosCrypto_KeyHandle*     pKeyHandle,
                              unsigned int              algorithm,
                              unsigned int              flags,
                              size_t                    lenBits);
typedef seos_err_t
(*SeosCryptoApi_keyImportT)(SeosCryptoApi*              self,
                            SeosCrypto_KeyHandle*       pKeyHandle,
                            unsigned int                algorithm,
                            unsigned int                flags,
                            void const*                 keyImportBuffer,
                            size_t                      keyImportLenBits);

typedef seos_err_t
(*SeosCryptoApi_keyCloseT)(SeosCryptoApi*           self,
                           SeosCrypto_KeyHandle     keyHandle);

typedef seos_err_t
(*SeosCryptoApi_cipherInitT)(SeosCryptoApi*                 self,
                             SeosCrypto_CipherHandle*       pCipherHandle,
                             unsigned int                   algorithm,
                             SeosCrypto_KeyHandle           keyHandle,
                             void*                          iv,
                             size_t                         ivLen);

typedef seos_err_t
(*SeosCryptoApi_cipherCloseT)(SeosCryptoApi*                self,
                              SeosCrypto_CipherHandle       cipherHandle);
typedef seos_err_t
(*SeosCryptoApi_cipherUpdateT)(SeosCryptoApi*               self,
                               SeosCrypto_CipherHandle      cipherHandle,
                               const void*                  data,
                               size_t                       dataLen,
                               void**                       output,
                               size_t*                      outputSize);
typedef void
(*SeosCryptoApi_deInitT)(SeosCryptoApi* self);

typedef struct
{
    SeosCryptoApi_GetRandomDataT    getRandomData;
    SeosCryptoApi_digestInitT       digestInit;
    SeosCryptoApi_digestCloseT      digestClose;
    SeosCryptoApi_digestUpdateT     digestUpdate;
    SeosCryptoApi_digestFinalizeT   digestFinalize;
    SeosCryptoApi_keyGenerateT      keyGenerate;
    SeosCryptoApi_keyImportT        keyImport;
    SeosCryptoApi_keyCloseT         keyClose;
    SeosCryptoApi_cipherInitT       cipherInit;
    SeosCryptoApi_cipherCloseT      cipherClose;
    SeosCryptoApi_cipherUpdateT     cipherUpdate;

    SeosCryptoApi_deInitT           deInit;
}
SeosCryptoApi_Vtable;

struct SeosCryptoApi
{
    const SeosCryptoApi_Vtable* vtable;
};

/***************************** Crypto functions *******************************/
/**
 * @brief generate random number
 *
 * @param self (optional) pointer to the seos_crypto context
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
SeosCryptoApi_getRandomData(SeosCryptoApi*  self,
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
SeosCryptoApi_digestInit(SeosCryptoApi*                 self,
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
SeosCryptoApi_digestClose(SeosCryptoApi*                self,
                          SeosCrypto_DigestHandle       digestHandle);
/**
 * @brief given the reference to the digest context \p digestHandle, it performs
 * the semantic of SeosCryptoDigest_update()
 *
 * @retval SEOS_ERROR_INVALID_HANDLE
 *
 */
seos_err_t
SeosCryptoApi_digestUpdate(SeosCryptoApi*               self,
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
SeosCryptoApi_digestFinalize(SeosCryptoApi*             self,
                             SeosCrypto_DigestHandle    digestHandle,
                             const void*                data,
                             size_t                     dataLen,
                             void**                     digest,
                             size_t*                    digestSize);
/**
 * @brief creates a random key and gives back an handle
 *
 * @param self (required) pointer to the seos crypto rpc object to be used
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
SeosCryptoApi_keyGenerate(SeosCryptoApi*            self,
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
SeosCryptoApi_keyImport(SeosCryptoApi*              self,
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
SeosCryptoApi_keyClose(SeosCryptoApi*           self,
                       SeosCrypto_KeyHandle     keyHandle);
/**
 * @brief initializes a cipher context (local or remote) with the semantic of
 * SeosCryptoCipher_init() and gives back an handle to it
 *
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE
 * @retval SEOS_ERROR_INVALID_PARAMETER
 */
seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoApi*                 self,
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
SeosCryptoApi_cipherClose(SeosCryptoApi*                self,
                          SeosCrypto_CipherHandle       cipherHandle);
/**
 * @brief given the reference to the cipher context \p digestHandle, it performs
 * the semantic of SeosCryptoCipher_update()
 *
 * @retval SEOS_ERROR_INVALID_HANDLE
 *
 */
seos_err_t
SeosCryptoApi_cipherUpdate(SeosCryptoApi*               self,
                           SeosCrypto_CipherHandle      cipherHandle,
                           const void*                  data,
                           size_t                       dataLen,
                           void**                       output,
                           size_t*                      outputSize);

/** @} */
