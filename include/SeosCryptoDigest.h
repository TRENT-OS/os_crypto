/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoDigest.h
 *
 * @brief Digest functions and context
 *
 */
#pragma once

#include "compiler.h"
#include "seos_err.h"

#include <string.h>

#define SeosCryptoDigest_SIZE_MD5     16
#define SeosCryptoDigest_SIZE_SHA256  32

#define SeosCryptoDigest_MAX_DIGEST_SIZE SeosCryptoDigest_SIZE_SHA256

typedef enum
{
    // be aware!! At the moment those enums are matching those of
    // mbedtls_md_type_t for convenience reasons. Do not change values unless
    // you know what you are doing.
    SeosCryptoDigest_Algorithm_NONE,
    SeosCryptoDigest_Algorithm_MD2,
    SeosCryptoDigest_Algorithm_MD4,
    SeosCryptoDigest_Algorithm_MD5,
    SeosCryptoDigest_Algorithm_SHA1,
    SeosCryptoDigest_Algorithm_SHA224,
    SeosCryptoDigest_Algorithm_SHA256,
    SeosCryptoDigest_Algorithm_SHA384,
    SeosCryptoDigest_Algorithm_SHA512,
    SeosCryptoDigest_Algorithm_RIPEMD160
}
SeosCryptoDigest_Algorithm;

#include "SeosCryptoDigest_Impl.h"
typedef struct SeosCryptoDigest SeosCryptoDigest;

/**
 * @brief initializes a digest context
 *
 * @param self (required) pointer to context to initialize
 * @param algorithm the digest algorithm
 * @param iv (optional) the initialization vector
 * @param ivLen the initialization vector length
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 *
 */
seos_err_t
SeosCryptoDigest_init(SeosCryptoDigest*             self,
                      SeosCryptoDigest_Algorithm    algorithm,
                      void*                         iv,
                      size_t                        ivLen);
/**
 * @brief closes a cipher context.
 *
 * @param self (required) pointer to context to initialize
 *
 */
void
SeosCryptoDigest_deInit(SeosCryptoDigest* self);
/**
 * @brief updates the computation of the digest providing a new block of data
 *
 * @param self (required) pointer to the SeosCryptoDigest context
 * @param data (required) the data block
 * @param dataLen the length of the data block
 *
 * @return an error code.
 *
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 * @retval SEOS_ERROR_ABORTED if the underlying implementation of the algorithm
 *  fails for any reason
 *
 */
seos_err_t
SeosCryptoDigest_update(SeosCryptoDigest*   self,
                        const void*         data,
                        size_t              dataLen);
/**
 * @brief finalizes the computation of the digest providing a new block of data
 *  or padding (when data == NULL).
 *
 * @param self (required) pointer to the SeosCryptoDigest context
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
 * @return an error code.
 *
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 * @retval SEOS_ERROR_ABORTED if the underlying implementation of the algorithm
 *  fails for any reason or the output buffer is not big enough
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL if the size of the digest buffer provided
 *  by the caller is not enough to hold the data generated
 *
 */
seos_err_t
SeosCryptoDigest_finalize(SeosCryptoDigest* self,
                          const void*       data,
                          size_t            len,
                          void**            digest,
                          size_t*           digestSize);
INLINE seos_err_t
SeosCryptoDigest_finalize2(SeosCryptoDigest*    self,
                           const void*          data,
                           size_t               len,
                           void*                digest,
                           size_t               digestSize)
{
    void* pDigest = digest;
    return SeosCryptoDigest_finalize(self,
                                     data,
                                     len,
                                     &pDigest,
                                     &digestSize);
}

INLINE seos_err_t
SeosCryptoDigest_finalizeNoData(SeosCryptoDigest*   self,
                                void**              digest,
                                size_t*             digestSize)
{
    return SeosCryptoDigest_finalize(self, NULL, 0, digest, digestSize);
}

INLINE seos_err_t
SeosCryptoDigest_finalizeNoData2(SeosCryptoDigest*  self,
                                 void*              digest,
                                 size_t             digestSize)
{
    void* pDigest = digest;
    return SeosCryptoDigest_finalizeNoData(self, &pDigest, &digestSize);
}
/**
 * @brief finalizes and verifies the digest
 *
 * @param self (required) pointer to the SeosCryptoDigest context
 *
 * @param data (optional) the data block. When not provided (== NULL) then
 *  padding is done
 * @param len the length of the data block
 * @param expectedDigest (required) the expected result to check the computed
 *  digest against
 *
 * @return an error code.
 *
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 *
 */
seos_err_t
SeosCryptoDigest_verify(SeosCryptoDigest*   self,
                        const void*         data,
                        size_t              len,
                        void*               expectedDigest);
/**
 * @brief gets the size of digest for the selected algorithm of the given
 *  context
 *
 * @param self (required) pointer to the SeosCryptoDigest context
 *
 * @return digest size
 *
 */
size_t
SeosCryptoDigest_getDigestSize(SeosCryptoDigest* self);

INLINE
void SeosCryptoDigest_clone(SeosCryptoDigest* dest,
                            SeosCryptoDigest const* source)
{
    memcpy(dest, source, sizeof(*dest));
}

///@}
