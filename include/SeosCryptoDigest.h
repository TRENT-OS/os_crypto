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

#include "SeosCrypto_Impl.h"
#include "SeosCryptoDigest_Impl.h"

#include "compiler.h"
#include "seos_err.h"

#include <string.h>

/**
 * @brief Initializes a digest context
 *
 */
seos_err_t
SeosCryptoDigest_init(SeosCrypto_MemIf*             memIf,
                      SeosCryptoDigest*             self,
                      SeosCryptoDigest_Algorithm    algorithm);

/**
 * @brief closes a cipher context.
 *
 */
seos_err_t
SeosCryptoDigest_free(SeosCrypto_MemIf*           memIf,
                      SeosCryptoDigest*           self);

/**
 * @brief Updates the computation of the digest providing a new block of data
 *
 */
seos_err_t
SeosCryptoDigest_update(SeosCryptoDigest*   self,
                        const void*         data,
                        size_t              dataLen);

/**
 * @brief Finalizes the computation of the digest
 *
 */
seos_err_t
SeosCryptoDigest_finalize(SeosCryptoDigest* self,
                          void*             digest,
                          size_t*           digestSize);

///@}
