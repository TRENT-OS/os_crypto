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

#include "seos_err.h"

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include "LibUtil/Bitmap.h"
#include "LibDebug/Debug.h"
#include "compiler.h"

typedef enum
{
    SeosCryptoKey_Flags_IS_ALGO_CIPHER,
    SeosCryptoKey_Flags_PRIVATE,

    SeosCryptoKey_Flags_MAX
}
SeosCryptoKey_Flags;

typedef struct
{
    BitMap32                flags;
    unsigned                algorithm;
    void*                   algoKeyCtx;
    unsigned                lenBits;
    char*                   bytes;
}
SeosCryptoKey;

Debug_STATIC_ASSERT(SeosCryptoKey_Flags_MAX\
                    <= sizeof(((SeosCryptoKey*)0)->flags) * CHAR_BIT);

/**
 * @brief initializes a SeosCryptoKey context
 *
 */
seos_err_t
SeosCryptoKey_init(SeosCryptoKey*   self,
                   void*            algKeyCtx,
                   unsigned         algorithm,
                   BitMap32         flags,
                   char*            bytes,
                   size_t           lenBits);

void
SeosCryptoKey_deInit(SeosCryptoKey* self);

seos_err_t
SeosCryptoKey_initRsaPublic(SeosCryptoKey*  self,
                            void*           algoKeyCtx,
                            const char*     n,
                            size_t          lenN,
                            const char*     e,
                            size_t          lenE);
seos_err_t
SeosCryptoKey_initRsaPrivate(SeosCryptoKey* self,
                             void*          algoKeyCtx,
                             const char*    n,
                             size_t         lenN,
                             const char*    e,
                             size_t         lenE,
                             const char*    d,
                             size_t         lenD,
                             const char*    p,
                             size_t         lenP,
                             const char*    q,
                             size_t         lenQ);

seos_err_t
SeosCryptoKey_initDhPublic(SeosCryptoKey*     self,
                           void*              algoKeyCtx,
                           const void*        p,
                           size_t             lenP,
                           const void*        g,
                           size_t             lenG,
                           const void*        gy,
                           size_t             lenGY);

seos_err_t
SeosCryptoKey_initDhPrivate(SeosCryptoKey*    self,
                            void*             algoKeyCtx,
                            const void*       p,
                            size_t            lenP,
                            const void*       g,
                            size_t            lenG,
                            const void*       x,
                            size_t            lenX);

seos_err_t
SeosCryptoKey_initEcdhPublic(SeosCryptoKey*   self,
                             void*            algoKeyCtx,
                             unsigned int     curveId,
                             const void*      qX,
                             size_t           lenQX,
                             const void*      qY,
                             size_t           lenQY);

seos_err_t
SeosCryptoKey_initEcdhPrivate(SeosCryptoKey*  self,
                              void*           algoKeyCtx,
                              unsigned int    curveId,
                              const void*     d,
                              size_t          lenD);

INLINE size_t
SeosCryptoKey_getSize(SeosCryptoKey* self)
{
    return self->lenBits / CHAR_BIT
           + ((self->lenBits % CHAR_BIT) ? 1 : 0);
}

///@}
