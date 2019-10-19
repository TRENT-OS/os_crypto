/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoKey_v5.h
 *
 * @brief Key functions and context
 *
 */
#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoKey_Impl_v5.h"

#include "seos_err.h"
#include "compiler.h"

#include <stddef.h>

seos_err_t
SeosCryptoKey_generate_v5(SeosCryptoKey_v5*         self,
                          const SeosCrypto_MemIf*   memIf,
                          SeosCryptoRng*            rng,
                          const SeosCryptoKey_Spec* spec);

seos_err_t
SeosCryptoKey_makePublic_v5(SeosCryptoKey_v5*               self,
                            const SeosCrypto_MemIf*         memIf,
                            const SeosCryptoKey_v5*         prvKey,
                            const SeosCryptoKey_Attribs*    attribs);

seos_err_t
SeosCryptoKey_import_v5(SeosCryptoKey_v5*          self,
                        const SeosCrypto_MemIf*    memIf,
                        const SeosCryptoKey_v5*    wrapKey,
                        const SeosCryptoKey_Data*  keyData);

seos_err_t
SeosCryptoKey_export_v5(SeosCryptoKey_v5*       self,
                        const SeosCryptoKey_v5* wrapKey,
                        SeosCryptoKey_Data*     keyData);

seos_err_t
SeosCryptoKey_getParams_v5(SeosCryptoKey_v5*    self,
                           void*                keyParams,
                           size_t*              paramSize);

seos_err_t
SeosCryptoKey_loadParams_v5(const SeosCryptoKey_ParamName   name,
                            void*                           keyParams,
                            size_t*                         paramSize);

seos_err_t
SeosCryptoKey_free_v5(SeosCryptoKey_v5*        self,
                      const SeosCrypto_MemIf*  memIf);

///@}
