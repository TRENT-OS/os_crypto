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
#include <stdbool.h>

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
    bool                empty;      ///< indicate if key material is there
    size_t              keySize;    ///< amount of bytes stored
}
SeosCryptoKey;

typedef struct __attribute__((__packed__))
{
    unsigned char   bytes[32]; ///< raw bytes (max: 256 bits)
    size_t          len;
}
SeosCryptoKey_AES;

typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[1024]; ///< public modulus (max: 8192 bits)
    size_t          nLen;
    unsigned char   eBytes[1024]; ///< public exponent (max: 8192 bits)
    size_t          eLen;
}
SeosCryptoKey_RSA_PUBLIC;
typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[1024]; ///< public modulus n=p*q (max: 8192 bits)
    size_t          nLen;
    unsigned char   dBytes[1024]; ///< private exponent d=e^-1 (max: 8192 bits)
    size_t          dLen;
    unsigned char   pBytes[512]; ///< private prime factor (max: 4096 bits)
    size_t          pLen;
    unsigned char   qBytes[512]; ///< private prime factor (max: 4096 bits)
    size_t          qLen;
}
SeosCryptoKey_RSA_PRIVATE;

typedef struct __attribute__((__packed__))
{
    unsigned char   qxBytes[64]; ///< x coord of public point Q=P*d (max: 512 bits)
    size_t          qxLen;
    unsigned char   qyBytes[64]; ///< y coord of public point Q=P*d (max: 512 bits)
    size_t          qyLen;
}
SeosCryptoKey_EC_SECP256R1_PUBLIC;
typedef struct __attribute__((__packed__))
{
    unsigned char   dBytes[64]; ///<  private scalar (max: 512 bits)
    size_t          dLen;
}
SeosCryptoKey_EC_SECP256R1_PRIVATE;

typedef struct __attribute__((__packed__))
{
    unsigned char   pBytes[1024]; ///< shared prime (max: 8192 bits)
    size_t          pLen;
    unsigned char   gBytes[1024]; ///< shared generator (max: 8192 bits)
    size_t          gLen;
    unsigned char   yBytes[1024]; ///< public key y=g^x mod p (max: 8192 bits)
    size_t          yLen;
}
SeosCryptoKey_DH_PUBLIC;

typedef struct __attribute__((__packed__))
{
    unsigned char   pBytes[1024]; ///< shared prime (max: 8192 bits)
    size_t          pLen;
    unsigned char   gBytes[1024]; ///< shared generator (max: 8192 bits)
    size_t          gLen;
    unsigned char   xBytes[1024]; ///< private exponent (max: 8192 bits)
    size_t          xLen;
}
SeosCryptoKey_DH_PRIVATE;

/** @} */
