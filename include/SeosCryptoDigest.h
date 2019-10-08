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
 * @brief implements SeosCryptoApi_digestInit()
 *
 */
seos_err_t
SeosCryptoDigest_init(SeosCrypto_MemIf*             memIf,
                      SeosCryptoDigest*             self,
                      SeosCryptoDigest_Algorithm    algorithm);

/**
 * @brief closes a cipher context.
 *
 * @param self (required) pointer to context to initialize
 *
 */
seos_err_t
SeosCryptoDigest_deInit(SeosCrypto_MemIf*           memIf,
                        SeosCryptoDigest*           self);

/**
 * @brief implements SeosCryptoApi_digestUpdate()
 *
 */
seos_err_t
SeosCryptoDigest_update(SeosCryptoDigest*   self,
                        const void*         data,
                        size_t              dataLen);

/**
 * @brief implements SeosCryptoApi_digestFinalize()
 *
 */
seos_err_t
SeosCryptoDigest_finalize(SeosCryptoDigest* self,
                          void*             digest,
                          size_t*           digestSize);

///@}
