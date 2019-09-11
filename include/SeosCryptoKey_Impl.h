/* Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoKey_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCryptoKey
 *
 */

#pragma once

#include <stddef.h>

#define MAX_KEYBUF_SIZE 64

typedef enum
{
    SeosCryptoKey_Flags_EXPORTABLE_RAW      = (1 << 0),
    SeosCryptoKey_Flags_EXPORTABLE_WRAPPED  = (1 << 1)
}
SeosCryptoKey_Flag;

typedef enum
{
    SeosCryptoKey_Type_NONE,
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
    SeosCryptoKey_PairType_NONE,
    SeosCryptoKey_PairType_RSA,
    SeosCryptoKey_PairType_DH,
    SeosCryptoKey_PairType_EC_SECP256R1,
}
SeosCryptoKey_PairType;

typedef struct
{
    SeosCryptoKey_Flag  flags;      ///< flags, see above
    SeosCryptoKey_Type  type;       ///< type of key, see above
    unsigned int        bits;       ///< the security parameter (e.g., key size)
    void*               keyBytes;   ///< pointer to raw key material
    size_t              keySize;    ///< amount of bytes stored
}
SeosCryptoKey;

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

/** @} */
