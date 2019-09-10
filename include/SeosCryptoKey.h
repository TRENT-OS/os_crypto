/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoKey.h
 *
 * @brief Key functions and context
 *
 */
#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoKey_Impl.h"

#include "seos_err.h"
#include "compiler.h"

#include <stddef.h>


/**
 * @brief initializes a SeosCryptoKey context
 *
 */
seos_err_t
SeosCryptoKey_init(SeosCrypto_MemIf*            memIf,
                   SeosCryptoKey*               self,
                   unsigned int                 type,
                   SeosCryptoKey_Flag           flags,
                   size_t                       secParam);

seos_err_t
SeosCryptoKey_generate(SeosCryptoKey*           self);

seos_err_t
SeosCryptoKey_generatePair(SeosCryptoKey*       prvKey,
                           SeosCryptoKey*       pubKey);

seos_err_t
SeosCryptoKey_import(SeosCryptoKey*             self,
                     const void*                key,
                     size_t                     keyLen);

seos_err_t
SeosCryptoKey_export(SeosCryptoKey*             self,
                     void**                     key,
                     size_t*                    keyLen);

void
SeosCryptoKey_deInit(SeosCrypto_MemIf*          memIf,
                     SeosCryptoKey*             self);

SeosCryptoKey_RSA_PUBLIC*
SeosCryptoKey_getRsaPublic(const SeosCryptoKey* key);

SeosCryptoKey_RSA_PRIVATE*
SeosCryptoKey_getRsaPrivate(const SeosCryptoKey* key);

SeosCryptoKey_AES*
SeosCryptoKey_getAES(const SeosCryptoKey* key);

// seos_err_t
// SeosCryptoKey_initRsaPublic(SeosCryptoKey*  self,
//                             void*           algoKeyCtx,
//                             const void*     n,
//                             size_t          lenN,
//                             const void*     e,
//                             size_t          lenE);
// seos_err_t
// SeosCryptoKey_initRsaPrivate(SeosCryptoKey* self,
//                              void*          algoKeyCtx,
//                              const void*    n,
//                              size_t         lenN,
//                              const void*    e,
//                              size_t         lenE,
//                              const void*    d,
//                              size_t         lenD,
//                              const void*    p,
//                              size_t         lenP,
//                              const void*    q,
//                              size_t         lenQ);

// seos_err_t
// SeosCryptoKey_initDhPublic(SeosCryptoKey*     self,
//                            void*              algoKeyCtx,
//                            const void*        p,
//                            size_t             lenP,
//                            const void*        g,
//                            size_t             lenG,
//                            const void*        gy,
//                            size_t             lenGY);

// seos_err_t
// SeosCryptoKey_initDhPrivate(SeosCryptoKey*    self,
//                             void*             algoKeyCtx,
//                             const void*       p,
//                             size_t            lenP,
//                             const void*       g,
//                             size_t            lenG,
//                             const void*       x,
//                             size_t            lenX);

// seos_err_t
// SeosCryptoKey_initEcdhPublic(SeosCryptoKey*   self,
//                              void*            algoKeyCtx,
//                              unsigned int     curveId,
//                              const void*      qX,
//                              size_t           lenQX,
//                              const void*      qY,
//                              size_t           lenQY);

// seos_err_t
// SeosCryptoKey_initEcdhPrivate(SeosCryptoKey*  self,
//                               void*           algoKeyCtx,
//                               unsigned int    curveId,
//                               const void*     d,
//                               size_t          lenD);

// INLINE size_t
// SeosCryptoKey_getSize(SeosCryptoKey* self)
// {
//     return self->lenBits / CHAR_BIT
//            + ((self->lenBits % CHAR_BIT) ? 1 : 0);
// }

///@}
