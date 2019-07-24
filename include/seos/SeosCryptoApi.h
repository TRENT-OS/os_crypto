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

#include "compiler.h"

#include "SeosCryptoKey.h"
#include "SeosCryptoDigest.h"
#include "SeosCryptoCipher.h"

typedef struct SeosCryptoApi SeosCryptoApi;

typedef SeosCryptoKey*      SeosCryptoApi_KeyHandle;
typedef SeosCryptoDigest*   SeosCryptoApi_DigestHandle;
typedef SeosCryptoCipher*   SeosCryptoApi_CipherHandle;

typedef seos_err_t
(*SeosCryptoApi_GetRandomDataT)(SeosCryptoApi*  self,
                                unsigned int    flags,
                                void const*     saltBuffer,
                                size_t          saltLen,
                                void*           buffer,
                                size_t          dataLen);

typedef seos_err_t
(*SeosCryptoApi_digestInitT)(SeosCryptoApi*                 self,
                             SeosCryptoApi_DigestHandle*    pDigestHandle,
                             unsigned int                   algorithm,
                             void*                          iv,
                             size_t                         ivLen);

typedef seos_err_t
(*SeosCryptoApi_digestCloseT)(SeosCryptoApi*                self,
                              SeosCryptoApi_DigestHandle    digestHandle);

typedef seos_err_t
(*SeosCryptoApi_digestUpdateT)(SeosCryptoApi*               self,
                               SeosCryptoApi_DigestHandle   digestHandle,
                               const void*                  data,
                               size_t                       dataLen);

typedef seos_err_t
(*SeosCryptoApi_digestFinalizeT)(SeosCryptoApi*             self,
                                 SeosCryptoApi_DigestHandle digestHandle,
                                 const void*                data,
                                 size_t                     dataLen,
                                 void**                     digest,
                                 size_t*                    digestSize);

typedef seos_err_t
(*SeosCryptoApi_keyGenerateT)(SeosCryptoApi*            self,
                              SeosCryptoApi_KeyHandle*  pKeyHandle,
                              unsigned int              algorithm,
                              unsigned int              flags,
                              size_t                    lenBits);
typedef seos_err_t
(*SeosCryptoApi_keyImportT)(SeosCryptoApi*              self,
                            SeosCryptoApi_KeyHandle*    pKeyHandle,
                            unsigned int                algorithm,
                            unsigned int                flags,
                            void const*                 keyImportBuffer,
                            size_t                      keyImportLenBits);

typedef seos_err_t
(*SeosCryptoApi_keyCloseT)(SeosCryptoApi*           self,
                           SeosCryptoApi_KeyHandle  keyHandle);

typedef seos_err_t
(*SeosCryptoApi_cipherInitT)(SeosCryptoApi*                 self,
                             SeosCryptoApi_CipherHandle*    pCipherHandle,
                             unsigned int                   algorithm,
                             SeosCryptoApi_KeyHandle        keyHandle,
                             void*                          iv,
                             size_t                         ivLen);

typedef seos_err_t
(*SeosCryptoApi_cipherCloseT)(SeosCryptoApi*                self,
                              SeosCryptoApi_CipherHandle    cipherHandle);
typedef seos_err_t
(*SeosCryptoApi_cipherUpdateT)(SeosCryptoApi*               self,
                               SeosCryptoApi_CipherHandle   cipherHandle,
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
 * @param buffer ///TODO: NOT DOCUMENTED in Wiki
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

seos_err_t
SeosCryptoApi_digestInit(SeosCryptoApi*                 self,
                         SeosCryptoApi_DigestHandle*    pDigestHandle,
                         unsigned int                   algorithm,
                         void*                          iv,
                         size_t                         ivLen);

seos_err_t
SeosCryptoApi_digestClose(SeosCryptoApi*                self,
                          SeosCryptoApi_DigestHandle    digestHandle);

seos_err_t
SeosCryptoApi_digestUpdate(SeosCryptoApi*               self,
                           SeosCryptoApi_DigestHandle   digestHandle,
                           const void*                  data,
                           size_t                       dataLen);

seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoApi*             self,
                             SeosCryptoApi_DigestHandle digestHandle,
                             const void*                data,
                             size_t                     dataLen,
                             void**                     digest,
                             size_t*                    digestSize);

seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoApi*            self,
                          SeosCryptoApi_KeyHandle*  pKeyHandle,
                          unsigned int              algorithm,
                          unsigned int              flags,
                          size_t                    lenBits);
seos_err_t
SeosCryptoApi_keyImport(SeosCryptoApi*              self,
                        SeosCryptoApi_KeyHandle*    pKeyHandle,
                        unsigned int                algorithm,
                        unsigned int                flags,
                        void const*                 keyImportBuffer,
                        size_t                      keyImportLenBits);

seos_err_t
SeosCryptoApi_keyClose(SeosCryptoApi*           self,
                       SeosCryptoApi_KeyHandle  keyHandle);

seos_err_t
SeosCryptoApi_cipherInit(SeosCryptoApi*                 self,
                         SeosCryptoApi_CipherHandle*    pCipherHandle,
                         unsigned int                   algorithm,
                         SeosCryptoApi_KeyHandle        keyHandle,
                         void*                          iv,
                         size_t                         ivLen);

seos_err_t
SeosCryptoApi_cipherClose(SeosCryptoApi*                self,
                          SeosCryptoApi_CipherHandle    cipherHandle);
seos_err_t
SeosCryptoApi_cipherUpdate(SeosCryptoApi*               self,
                           SeosCryptoApi_CipherHandle   cipherHandle,
                           const void*                  data,
                           size_t                       dataLen,
                           void**                       output,
                           size_t*                      outputSize);

/** @} */
