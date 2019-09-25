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
SeosCryptoDigest_init(SeosCryptoDigest*                 self,
                      const SeosCrypto_MemIf*           memIf,
                      const SeosCryptoDigest_Algorithm  algorithm);

/**
 * @brief closes a cipher context.
 *
 */
seos_err_t
SeosCryptoDigest_free(SeosCryptoDigest*         self,
                      const SeosCrypto_MemIf*   memIf);

/**
 * @brief Processes the computation of the digest based on a new block of data
 *
 */
seos_err_t
SeosCryptoDigest_process(SeosCryptoDigest*   self,
                         const void*         data,
                         const size_t        dataLen);

/**
 * @brief Finalizes the computation of the digest
 *
 */
seos_err_t
SeosCryptoDigest_finalize(SeosCryptoDigest* self,
                          void*             digest,
                          size_t*           digestSize);

///@}
