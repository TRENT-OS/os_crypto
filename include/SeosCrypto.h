/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCrypto.h
 *
 * @brief SEOS Crypto context and functions
 *
 */
#pragma once

#include "seos_err.h"
#include "seos_rng.h"
#include "SeosCryptoRng.h"
#include "SeosCryptoKey.h"
#include "SeosCryptoDigest.h"
#include "SeosCryptoCipher.h"
#include "SeosCrypto_Handles.h"
#include "SeosCryptoCtx.h"

#include "LibUtil/PointerVector.h"

#define SeosCrypto_TO_SEOS_CRYPTO_CTX(self) (&(self)->parent)
#define SeosCrypto_RANDOM_SEED_STR "SeosCryptoAPI"

typedef struct SeosCrypto SeosCrypto;

typedef void* (SeosCrypto_MallocFunc)(size_t size);
typedef void  (SeosCrypto_FreeFunc)(void* ptr);

typedef struct
{
    SeosCrypto_MallocFunc*   malloc;
    SeosCrypto_FreeFunc*     free;
}
SeosCrypto_MemIf;

typedef struct
{
    void*   buf;
    size_t  len;
}
SeosCrypto_StaticBuf;

struct SeosCrypto
{
    SeosCryptoCtx   parent;
    union
    {
        SeosCrypto_MemIf        memIf;
        SeosCrypto_StaticBuf    staticBuf;
    }
    mem;
    bool            isRngInitialized;
    seos_rng_t      rng;

    PointerVector keyHandleVector;
    PointerVector digestHandleVector;
    PointerVector cipherHandleVector;
};

/**
 * @brief initializes a crypto API context. Usually, no crypto context is needed
 *  and most function accept NULL as context. The parameter malloc allows
 *  passing a custom function that will be called to allocate memory. The
 *  parameter func_free allows passing a custom function that will call to free
 *  memory. The parameter self will receive a context handle, that is used with
 *  further calls. It must be closed with crypto_api_close() eventually. The
 *  parameter buffer_self and len_buffer_self can be used to provide space for
 *  actual context. The space must be kept as long as self is used in calls to
 *  the library.
 *
 * @param self (required) pointer to the seos_crypto context to initialize
 * @param malloc (required) provided malloc function
 * @param free (required) provided free function
 * @param bufferCtx if NULL and lenBufferCtx is 0, then this will be set to
 *  the buffer size that is needed for bufferCtx. If bufferCtx is NULL and
 *  lenBufferCtx is -1, then the function from malloc will be called to
 *  allocate a context.
 * @param lenBufferCtx (required) length of lenBufferCtx
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 *
 */
seos_err_t
SeosCrypto_init(SeosCrypto* self,
                SeosCrypto_MallocFunc malloc,
                SeosCrypto_FreeFunc free,
                void* bufferCtx,
                size_t* lenBufferCtx);
/**
 * @brief closes the initialized crypto context and releases all the allocated
 *  resources
 *
 * @param self (required) pointer to the seos_crypto context
 *
 */
void
SeosCrypto_deInit(SeosCryptoCtx* api);

/**
 * @brief implements SeosCryptoApi_getRandomData() in a local connection
 *  (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_getRandomData(SeosCryptoCtx* api,
                         unsigned int   flags,
                         void const*    saltBuffer,
                         size_t         saltLen,
                         void*          buffer,
                         size_t         buffer_len);


// ------------------------------ Digest API -----------------------------------
/**
 * @brief implements SeosCryptoApi_digestInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestInit(SeosCryptoCtx*                api,
                      SeosCrypto_DigestHandle*   pDigestHandle,
                      unsigned                      algorithm,
                      void*                         iv,
                      size_t                        ivLen);
/**
 * @brief implements SeosCryptoApi_digestInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestClose(SeosCryptoCtx*               api,
                       SeosCrypto_DigestHandle   digestHandle);
/**
 * @brief implements SeosCryptoApi_digestUpdate() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestUpdate(SeosCryptoCtx*              api,
                        SeosCrypto_DigestHandle  digestHandle,
                        const void*                 data,
                        size_t                      len);
/**
 * @brief implements SeosCryptoApi_digestFinalize() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_digestFinalize(SeosCryptoCtx*                api,
                          SeosCrypto_DigestHandle    digestHandle,
                          const void*                   data,
                          size_t                        len,
                          void**                        digest,
                          size_t*                       digestSize);

// -------------------------------- Key API ------------------------------------
/**
 * @brief implements SeosCryptoApi_keyGenerate() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyGenerate(SeosCryptoCtx*           api,
                       SeosCrypto_KeyHandle* pKeyHandle,
                       unsigned int             algorithm,
                       unsigned int             flags,
                       size_t                   lenBits);
/**
 * @brief implements SeosCryptoApi_keyImport() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyImport(SeosCryptoCtx*             api,
                     SeosCrypto_KeyHandle*   pKeyHandle,
                     unsigned int               algorithm,
                     unsigned int               flags,
                     void const*                keyImportBuffer,
                     size_t                     keyImportLenBits);
/**
 * @brief export the key material. Export of certain keys may not be allowed.
 *  The public part of an asymmetric key is usually exportable
 *
 * @param api (optional) pointer to the seos_crypto context
 * @param flags contains key specific setting about what to export and which
 *  format is used the format of the key material is specific to the key type
 * @param hKey ///TODO: NOT DOCUMENTED in Wiki
 * @param buffer (optional) if NULL, then the parameter len_buffer contains the
 *  buffer size that is needed on output
 * @param buffer_len (optional) if the parameter buffer is not NULL, the
 *  parameter len_buffer must contain the buffer size on input and will contain
 *  the length used on return
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 * @retval SEOS_ERROR_INVALID_HANDLE invalid key store handle
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL len_keyBlobBuffer contains the size
 *  that would be needed for the key blob
 * @retval SEOS_ERROR_ACCESS_DENIED export denied
 *
 */
seos_err_t
SeosCrypto_keyExport(SeosCryptoCtx*             api,
                     SeosCrypto_KeyHandle    keyHandle,
                     void*                      buffer,
                     size_t                     bufferLen);
/**
 * @brief implements SeosCryptoApi_digestInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_keyClose(SeosCryptoCtx*          api,
                    SeosCrypto_KeyHandle keyHandle);


// ----------------------------- Key Derivation --------------------------------

/**
 * @brief closes a key handle. The buffer of the key will no longer be in use,
 *  however any pending operation with this key can continue
 *
 * @param api (optional) pointer to the seos_crypto context
 * @param flags contains key specific setting about what to export and which
 *  format is used the format of the key material is specific to the key type
 * @param hKey ///TODO: NOT DOCUMENTED in Wiki
 * @param buffer (optional) if NULL, then the parameter len_buffer contains the
 *  buffer size that is needed on output
 * @param buffer_len (optional) if the parameter buffer is not NULL, the
 *  parameter len_buffer must contain the buffer size on input and will contain
 *  the length used on return
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 * @retval SEOS_ERROR_INVALID_HANDLE invalid key store handle
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL lenKeyBlobBuffer contains the size
 *  that would be needed for the key blob
 * @retval SEOS_ERROR_ACCESS_DENIED export denied
 *
 */
seos_err_t
SeosCrypto_deriveKey(SeosCryptoCtx* api,
                     SeosCrypto_KeyHandle hParentKey,
                     unsigned int lifetime,
                     unsigned int algorithm,
                     void const* saltBuffer,
                     size_t saltLen,
                     SeosCrypto_KeyHandle* hKey,
                     void* keyBlobBuffer,
                     size_t* lenKeyBlobBuffer);
/**
 * @brief closes a key handle. The buffer of the key will no longer be in use,
 *  however any pending operation with this key can continue
 *
 * @param api (optional) pointer to the seos_crypto context
 * @param flags contains key specific setting about what to export and which
 *  format is used the format of the key material is specific to the key type
 * @param hKey ///TODO: NOT DOCUMENTED in Wiki
 * @param buffer (optional) if NULL, then the parameter len_buffer contains the
 *  buffer size that is needed on output
 * @param buffer_len (optional) if the parameter buffer is not NULL, the
 *  parameter len_buffer must contain the buffer size on input and will contain
 *  the length used on return
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 * @retval SEOS_ERROR_INVALID_HANDLE invalid key store handle
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL len_keyBlobBuffer contains the size
 *  that would be needed for the key blob
 * @retval SEOS_ERROR_ACCESS_DENIED export denied
 *
 */
//seos_err_t
//SeosCrypto_deriveKey(SeosCrypto* api,
//                       SeosCrypto_HKey hParentKey,
//                       unsigned int lifetime,
//                       unsigned int algorithm,
//                       void const* saltBuffer,
//                       size_t saltLen,
//                       SeosCrypto_HKey* hKey,
//                       void* keyBlobBuffer,
//                       size_t* len_keyBlobBuffer);

// ------------------------------ Cipher API -----------------------------------
/**
 * @brief implements SeosCryptoApi_cipherInit() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherInit(SeosCryptoCtx*             api,
                      SeosCrypto_CipherHandle*   pCipherHandle,
                      unsigned int               algorithm,
                      SeosCrypto_KeyHandle       keyHandle,
                      const void*                iv,
                      size_t                     ivLen);
/**
 * @brief implements SeosCryptoApi_cipherClose() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherClose(SeosCryptoCtx*            api,
                       SeosCrypto_CipherHandle   cipherHandle);
/**
 * @brief implements SeosCryptoApi_cipherUpdate() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherUpdate(SeosCryptoCtx*              api,
                        SeosCrypto_CipherHandle     cipherHandle,
                        const void*                 input,
                        size_t                      inputSize,
                        void**                      output,
                        size_t*                     outputSize);
/**
 * @brief implements SeosCryptoApi_cipherUpdateAd() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherUpdateAd(SeosCryptoCtx*              api,
                          SeosCrypto_CipherHandle     cipherHandle,
                          const void*                 input,
                          size_t                      inputSize);
/**
 * @brief implements SeosCryptoApi_cipherFinalize() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherFinalize(SeosCryptoCtx*                api,
                          SeosCrypto_CipherHandle       cipherHandle,
                          void**                        output,
                          size_t*                       outputSize);

/**
 * @brief implements SeosCryptoApi_cipherVerifyTag() in a local connection
 * (function call, no rpc)
 *
 */
seos_err_t
SeosCrypto_cipherVerifyTag(SeosCryptoCtx*                api,
                           SeosCrypto_CipherHandle       cipherHandle,
                           const void*                   tag,
                           size_t                        tagSize);

/** @} */
