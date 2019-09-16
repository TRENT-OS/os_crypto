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

#define SeosCryptoKey_Size_AES              32      ///< max 256 bit
#define SeosCryptoKey_Size_RSA_PRV          512     ///< max 4096 bit
#define SeosCryptoKey_Size_RSA_PUB          512     ///< max 4096 bit
#define SeosCryptoKey_Size_DH_PRV           512     ///< max 4096 bit
#define SeosCryptoKey_Size_DH_PUB           512     ///< max 4096 bit
#define SeosCryptoKey_Size_SECP256R1_PRV    32      ///< always 256 bit
#define SeosCryptoKey_Size_SECP256R1_PUB    32      ///< always 256 bit

typedef enum
{
    SeosCryptoKey_Flags_NONE                = 0,
    SeosCryptoKey_Flags_EXPORTABLE_RAW      = (1 << 0),
    SeosCryptoKey_Flags_EXPORTABLE_WRAPPED  = (1 << 1)
}
SeosCryptoKey_Flag;

typedef enum
{
    SeosCryptoKey_Type_NONE,
    SeosCryptoKey_Type_AES,
    SeosCryptoKey_Type_RSA_PRV,
    SeosCryptoKey_Type_RSA_PUB,
    SeosCryptoKey_Type_DH_PRV,
    SeosCryptoKey_Type_DH_PUB,
    SeosCryptoKey_Type_SECP256R1_PRV,
    SeosCryptoKey_Type_SECP256R1_PUB
}
SeosCryptoKey_Type;

typedef enum
{
    SeosCryptoKey_PairType_NONE,
    SeosCryptoKey_PairType_RSA,
    SeosCryptoKey_PairType_DH,
    SeosCryptoKey_PairType_SECP256R1,
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
    unsigned char   bytes[SeosCryptoKey_Size_AES];
    size_t          len;
}
SeosCryptoKey_AES;

typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[SeosCryptoKey_Size_RSA_PUB]; ///< public modulus
    size_t          nLen;
    unsigned char   eBytes[SeosCryptoKey_Size_RSA_PUB]; ///< public exponent
    size_t          eLen;
}
SeosCryptoKey_RSAPub;
typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[SeosCryptoKey_Size_RSA_PRV]; ///< public modulus n=p*q
    size_t          nLen;
    unsigned char   dBytes[SeosCryptoKey_Size_RSA_PRV]; ///< exponent d=e^-1
    size_t          dLen;
    unsigned char   pBytes[SeosCryptoKey_Size_RSA_PRV / 2]; ///< prime factor
    size_t          pLen;
    unsigned char   qBytes[SeosCryptoKey_Size_RSA_PRV / 2]; ///< prime factor
    size_t          qLen;
}
SeosCryptoKey_RSAPrv;

typedef struct __attribute__((__packed__))
{
    unsigned char   qxBytes[SeosCryptoKey_Size_SECP256R1_PUB]; ///< x of point Q=P*d
    size_t          qxLen;
    unsigned char   qyBytes[SeosCryptoKey_Size_SECP256R1_PUB]; ///< y of point Q=P*d
    size_t          qyLen;
}
SeosCryptoKey_SECP256r1Pub;
typedef struct __attribute__((__packed__))
{
    unsigned char   dBytes[SeosCryptoKey_Size_SECP256R1_PRV]; ///<  private scalar
    size_t          dLen;
}
SeosCryptoKey_SECP256r1Prv;

typedef struct __attribute__((__packed__))
{
    unsigned char   pBytes[SeosCryptoKey_Size_DH_PUB]; ///< shared prime
    size_t          pLen;
    unsigned char   gBytes[SeosCryptoKey_Size_DH_PUB]; ///< shared generator
    size_t          gLen;
    unsigned char   yBytes[SeosCryptoKey_Size_DH_PUB]; ///< public key y=g^x mod p
    size_t          yLen;
}
SeosCryptoKey_DHPub;

typedef struct __attribute__((__packed__))
{
    unsigned char   pBytes[SeosCryptoKey_Size_DH_PRV]; ///< shared prime
    size_t          pLen;
    unsigned char   gBytes[SeosCryptoKey_Size_DH_PRV]; ///< shared generator
    size_t          gLen;
    unsigned char   xBytes[SeosCryptoKey_Size_DH_PRV]; ///< private exponent
    size_t          xLen;
}
SeosCryptoKey_DHPrv;

/** @} */
