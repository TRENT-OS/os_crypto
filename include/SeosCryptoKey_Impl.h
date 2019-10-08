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
#include <stdint.h>

#define SeosCryptoKey_DH_GENERATOR          2       ///< Generator for DH
#define SeosCryptoKey_RSA_EXPONENT          65537   ///< Public exp. 2^16+1

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

typedef struct
{
    SeosCryptoKey_Flag  flags;      ///< flags, see above
    SeosCryptoKey_Type  type;       ///< type of key, see above
    uint32_t            bits;       ///< the security parameter (e.g., key size)
    void*               keyBytes;   ///< pointer to raw key material
    bool                empty;      ///< indicate if key material is there
    size_t              keySize;    ///< amount of bytes stored
}
SeosCryptoKey;

typedef struct __attribute__((__packed__))
{
    unsigned char   bytes[SeosCryptoKey_Size_AES];
    uint32_t        len;
}
SeosCryptoKey_AES;

typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[SeosCryptoKey_Size_RSA_PUB]; ///< public modulus
    uint32_t        nLen;
    unsigned char   eBytes[SeosCryptoKey_Size_RSA_PUB]; ///< public exponent
    uint32_t        eLen;
}
SeosCryptoKey_RSAPub;
typedef struct __attribute__((__packed__))
{
    unsigned char   dBytes[SeosCryptoKey_Size_RSA_PRV]; ///< secret exp.
    uint32_t        dLen;
    unsigned char   eBytes[SeosCryptoKey_Size_RSA_PRV]; ///< public exp.
    uint32_t        eLen;
    unsigned char   pBytes[SeosCryptoKey_Size_RSA_PRV / 2]; ///< prime factor
    uint32_t        pLen;
    unsigned char   qBytes[SeosCryptoKey_Size_RSA_PRV / 2]; ///< prime factor
    uint32_t        qLen;
}
SeosCryptoKey_RSAPrv;

typedef struct __attribute__((__packed__))
{
    unsigned char   qxBytes[SeosCryptoKey_Size_SECP256R1_PUB]; ///< x of point Q=P*d
    uint32_t        qxLen;
    unsigned char   qyBytes[SeosCryptoKey_Size_SECP256R1_PUB]; ///< y of point Q=P*d
    uint32_t        qyLen;
}
SeosCryptoKey_SECP256r1Pub;

typedef struct __attribute__((__packed__))
{
    unsigned char   dBytes[SeosCryptoKey_Size_SECP256R1_PRV]; ///<  private scalar
    uint32_t        dLen;
}
SeosCryptoKey_SECP256r1Prv;

typedef struct __attribute__((__packed__))
{
    unsigned char   pBytes[SeosCryptoKey_Size_DH_PUB]; ///< shared prime
    uint32_t        pLen;
    unsigned char   gBytes[SeosCryptoKey_Size_DH_PUB]; ///< shared generator
    uint32_t        gLen;
    unsigned char   gxBytes[SeosCryptoKey_Size_DH_PUB]; ///< public key g^x mod p
    uint32_t        gxLen;
}
SeosCryptoKey_DHPub;

typedef struct __attribute__((__packed__))
{
    unsigned char   pBytes[SeosCryptoKey_Size_DH_PRV]; ///< shared prime
    uint32_t        pLen;
    unsigned char   gBytes[SeosCryptoKey_Size_DH_PRV]; ///< shared generator
    uint32_t        gLen;
    unsigned char   xBytes[SeosCryptoKey_Size_DH_PRV]; ///< private exponent
    uint32_t        xLen;
}
SeosCryptoKey_DHPrv;

/** @} */
