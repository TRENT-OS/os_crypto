/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoDigest.h
 *
 * @brief Digest functions
 *
 */

#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoDigest_Impl.h"

#include "compiler.h"
#include "SeosError.h"

#include <string.h>

seos_err_t
SeosCryptoDigest_init(SeosCryptoDigest*                 self,
                      const SeosCrypto_MemIf*           memIf,
                      const SeosCryptoDigest_Algorithm  algorithm);

seos_err_t
SeosCryptoDigest_free(SeosCryptoDigest*         self,
                      const SeosCrypto_MemIf*   memIf);

seos_err_t
SeosCryptoDigest_process(SeosCryptoDigest*   self,
                         const void*         data,
                         const size_t        dataLen);

seos_err_t
SeosCryptoDigest_finalize(SeosCryptoDigest* self,
                          void*             digest,
                          size_t*           digestSize);

/** @} */
