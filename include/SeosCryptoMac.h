/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoMac.h
 *
 * @brief Message authentication code (MAC) functions
 *
 */

#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoMac_Impl.h"

#include "SeosError.h"
#include "compiler.h"

seos_err_t
SeosCryptoMac_init(SeosCryptoMac*                 self,
                   const SeosCrypto_MemIf*        memIf,
                   const SeosCryptoMac_Algorithm  algorithm);

seos_err_t
SeosCryptoMac_free(SeosCryptoMac*           self,
                   const SeosCrypto_MemIf*  memIf);

seos_err_t
SeosCryptoMac_start(SeosCryptoMac*    self,
                    const void*       secret,
                    const size_t      secretSize);

seos_err_t
SeosCryptoMac_process(SeosCryptoMac*    self,
                      const void*       data,
                      const size_t      dataSize);

seos_err_t
SeosCryptoMac_finalize(SeosCryptoMac*   self,
                       void*            mac,
                       size_t*          macSize);

/** @} */
