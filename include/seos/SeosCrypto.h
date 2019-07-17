/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCrypto.h
 *
 * @brief SEOS Crypto API library
 *
 */
#pragma once

#include "seos_err.h"
#include "seos_rng.h"
#include "SeosCryptoKey.h"

#define SeosCrypto_RANDOM_SEED_STR "SeosCryptoAPI"

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

typedef SeosCryptoKey* SeosCrypto_KeyHandle;

typedef struct
{
    union
    {
        SeosCrypto_MemIf        memIf;
        SeosCrypto_StaticBuf    staticBuf;
    }
    mem;
    seos_rng_t rng;
}
SeosCrypto;

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
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 *
 */
seos_err_t
SeosCrypto_deInit(SeosCrypto* self);
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
SeosCrypto_getRandomData(SeosCrypto* self,
                         unsigned int flags,
                         void const* saltBuffer,
                         size_t saltLen,
                         void*   buffer,
                         size_t  buffer_len);

// -------------------------------- Key API ------------------------------------
/**
 * @brief creates a key and provides a handle to it. The number of key handles
 *  that are active in parallel can be limited
 *
 * @param self (optional) pointer to the seos_crypto context
 * @param algorithm ///TODO: NOT DOCUMENTED in Wiki
 * @param flags ///TODO: NOT DOCUMENTED in Wiki
 * @param lenBits length of the key in bits
 * @param hKey (required) will receive a key handle, that is used to work with
 *  the key. It must be closed with key_close() when the key is not longer
 *  needed
 * @param keyBlobBuffer (optional) can be: a pointer to a buffer where the key
 *  blob is put into. The buffer must be kept as long as the key handle is not
 *  closed. If the key handle is passed to another crypto function that creates
 *  it's own context, the key details are copied into this context and thus this
 *  does not depend on the key's buffer any longer. NULL if this function is
 *  just used for probing the required buffer size or if the function should
 *  allocate the memory internally
 * @param len_keyBlobBuffer (required) depends on the parameter
 *  key_bob_buffer:
 *  if key_bob_buffer is not NULL, it must contain the size of the buffer on
 *  input and will be set to the size that is actually used on return. If
 *  key_bob_buffer is NULL, then is must be:
 *  0 to indicate that the function is called for probing, on return it will
 *  contains the size that would be needed for the key blob. In this case the
 *  parameter hKey is ignored and should be NULL.
 *  -1 to indicate the function should allocate the buffer internally.
 *  If crypto_api_self has been set up to use a custom allocator, this one will
 *  be used. The buffer will be associated with hKey and will be relased when
 *  the key handle is closed. Any other value will make the function fail with
 *  SEOS_ERROR_INVALID_PARAMETER.
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 * @retval SEOS_ERROR_INVALID_HANDLE invalid key store handle
 * @retval SEOS_ERROR_ACCESS_DENIED read-only key store or insufficient rights
 *  to create a key
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL len_keyBlobBuffer contains the size
 *  that would be needed for the key blob
 *
 */
seos_err_t
SeosCrypto_keyCreate(SeosCrypto* self,
                     unsigned int algorithm,
                     uint16_t flags,
                     size_t lenBits,
                     SeosCrypto_KeyHandle* hKey,
                     void* keyBlobBuffer,
                     size_t* len_keyBlobBuffer);
/**
 * @brief imports a key and provides a handle to it. The number of key handles
 *  that are active in parallel can be limited
 *
 * @param self (optional) pointer to the seos_crypto context
 * @paeam flags ///TODO: NOT DOCUMENTED in Wiki
 * @param hKey (required) will receive a key handle, that is used to work with
 *  the key. It must be closed with key_close() when the key is not longer
 *  needed
 * @param keyBlobBuffer (optional) works as described in key_create()
 * @param len_keyBlobBuffer (required) works as described in key_create()
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 * @retval SEOS_ERROR_INVALID_HANDLE invalid key store handle
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL len_keyBlobBuffer contains the size
 *  that would be needed for the key blob
 *
 */
seos_err_t
SeosCrypto_keyImport(SeosCrypto* self,
                     unsigned int flags,
                     void const* key_import_buffer,
                     size_t key_import_len,
                     SeosCrypto_KeyHandle* hKey,
                     void* keyBlobBuffer,
                     size_t* len_keyBlobBuffer);
/**
 * @brief export the key material. Export of certain keys may not be allowed.
 *  The public part of an asymmetric key is usually exportable
 *
 * @param self (optional) pointer to the seos_crypto context
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
SeosCrypto_keyExport(SeosCrypto* self,
                     unsigned int flags,
                     SeosCrypto_KeyHandle* hKey,
                     void* buffer,
                     size_t* buffer_len);
/**
 * @brief closes a key handle. The buffer of the key will no longer be in use,
 *  however any pending operation with this key can continue
 *
 * @param self (optional) pointer to the seos_crypto context
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
SeosCrypto_keyClose(SeosCrypto* self,
                    unsigned int flags,
                    SeosCrypto_KeyHandle* hKey,
                    void* buffer,
                    size_t* buffer_len);


// ----------------------------- Key Derivation --------------------------------

/**
 * @brief closes a key handle. The buffer of the key will no longer be in use,
 *  however any pending operation with this key can continue
 *
 * @param self (optional) pointer to the seos_crypto context
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
SeosCrypto_deriveKey(SeosCrypto* self,
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
 * @param self (optional) pointer to the seos_crypto context
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
//SeosCrypto_deriveKey(SeosCrypto* self,
//                       SeosCrypto_HKey hParentKey,
//                       unsigned int lifetime,
//                       unsigned int algorithm,
//                       void const* saltBuffer,
//                       size_t saltLen,
//                       SeosCrypto_HKey* hKey,
//                       void* keyBlobBuffer,
//                       size_t* len_keyBlobBuffer);
/** @} */
