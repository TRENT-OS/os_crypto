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
    SeosCryptoKey_Flags_IS_EXPORTABLE = (1 << 0)
}
SeosCryptoKey_Flag;

typedef enum
{
    SeosCryptoKey_Type_AES,
    SeosCryptoKey_Type_RSA_PRIVATE,
    SeosCryptoKey_Type_RSA_PUBLIC,
    SeosCryptoKey_Type_DH_PRIVATE,
    SeosCryptoKey_Type_DH_PUBLIC,
    SeosCryptoKey_Type_EC_SECP256R1_PRIVATE,
    SeosCryptoKey_Type_EC_SECP256R1_PUBLIC
}
SeosCryptoKey_Type;

typedef enum
{
    SeosCryptoKey_PairType_RSA,
    SeosCryptoKey_PairType_DH,
    SeosCryptoKey_PairType_EC_SECP256R1,
}
SeosCryptoKey_PairType;

typedef struct
{
    unsigned int        type;       ///< type of key, see above
    unsigned int        security;   ///< the security parameter (e.g., key size)
    void*               bytes;      ///< pointer to raw key material
    size_t              len;        ///< amount of bytes stored
}
SeosCryptoKey;

#define MAX_KEYBUF_SIZE 64

typedef struct __attribute__((__packed__))
{
    unsigned char   bytes[MAX_KEYBUF_SIZE];
    size_t          len;
}
SeosCryptoKey_AES;

typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[MAX_KEYBUF_SIZE];
    size_t          nLen;
    unsigned char   eBytes[MAX_KEYBUF_SIZE];
    size_t          eLen;
}
SeosCryptoKey_RSA_PUBLIC;
typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[MAX_KEYBUF_SIZE];
    size_t          nLen;
    unsigned char   eBytes[MAX_KEYBUF_SIZE];
    size_t          eLen;
    unsigned char   dBytes[MAX_KEYBUF_SIZE];
    size_t          dLen;
    unsigned char   pBytes[MAX_KEYBUF_SIZE];
    size_t          pLen;
    unsigned char   qBytes[MAX_KEYBUF_SIZE];
    size_t          qLen;
}
SeosCryptoKey_RSA_PRIVATE;

/**
 * @brief initializes a SeosCryptoKey context
 *
 */
seos_err_t
SeosCryptoKey_init(SeosCryptoKey*               self,
//                   const SeosCrypto_MemIf*      memIf,
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
SeosCryptoKey_deInit(SeosCryptoKey*             self);
//                     const SeosCrypto_MemIf*    memIf);

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
