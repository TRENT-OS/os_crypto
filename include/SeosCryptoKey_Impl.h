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

/**
 * How often do we want to retry finding a suitable prime P and also
 * a suitable X with 2 <= X <= P-2?
 */
#define SeosCryptoKey_DH_GEN_RETRIES 10

#define SeosCryptoKey_DH_GENERATOR   2       ///< Generator for DH
#define SeosCryptoKey_RSA_EXPONENT   65537   ///< Public exp. 2^16+1

#define SeosCryptoKey_Size_AES      32      ///< max 256 bit
#define SeosCryptoKey_Size_RSA      512     ///< max 4096 bit
#define SeosCryptoKey_Size_DH       512     ///< max 4096 bit
#define SeosCryptoKey_Size_ECC      32      ///< always 256 bit

typedef enum
{
    SeosCryptoKey_Flags_NONE                = 0x0000,
    SeosCryptoKey_Flags_EXPORTABLE_RAW      = 0x0001,
    SeosCryptoKey_Flags_EXPORTABLE_WRAPPED  = 0x0002
}
SeosCryptoKey_Flags;

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
    SeosCryptoKey_PairType_NONE         = SeosCryptoKey_Type_NONE,
    SeosCryptoKey_PairType_RSA          = SeosCryptoKey_Type_RSA_PRV,
    SeosCryptoKey_PairType_DH           = SeosCryptoKey_Type_DH_PRV,
    SeosCryptoKey_PairType_SECP256R1    = SeosCryptoKey_Type_SECP256R1_PRV
}
SeosCryptoKey_PairType;

typedef struct
{
    SeosCryptoKey_Flags flags;     ///< flags, see above
    SeosCryptoKey_Type  type;       ///< type of key, see above
    size_t              bits;       ///< the security parameter (e.g., key size)
    void*               keyBytes;   ///< pointer to raw key material
    size_t              keySize;    ///< amount of bytes stored
}
SeosCryptoKey;

// ----------------------------- Symmetric Keys --------------------------------

typedef struct __attribute__((__packed__))
{
    unsigned char   bytes[SeosCryptoKey_Size_AES];
    uint32_t        len;
}
SeosCryptoKey_AES;

// -------------------------------- RSA Keys -----------------------------------

typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[SeosCryptoKey_Size_RSA]; ///< public modulus n=p*q
    uint32_t        nLen;
    unsigned char   eBytes[SeosCryptoKey_Size_RSA]; ///< public exponent
    uint32_t        eLen;
}
SeosCryptoKey_RSAPub;

typedef struct __attribute__((__packed__))
{
    unsigned char   dBytes[SeosCryptoKey_Size_RSA]; ///< secret exp.
    uint32_t        dLen;
    unsigned char   eBytes[SeosCryptoKey_Size_RSA]; ///< public exp.
    uint32_t        eLen;
    unsigned char   pBytes[SeosCryptoKey_Size_RSA / 2]; ///< prime factor of n
    uint32_t        pLen;
    unsigned char   qBytes[SeosCryptoKey_Size_RSA / 2]; ///< prime factor of n
    uint32_t        qLen;
}
SeosCryptoKey_RSAPrv;

// -------------------------------- ECC Keys -----------------------------------

typedef struct __attribute__((__packed__))
{
    unsigned char aBytes[SeosCryptoKey_Size_ECC]; ///< A of Weierstrass curve
    uint32_t      aLen;
    unsigned char bBytes[SeosCryptoKey_Size_ECC]; ///< B of Weierstrass curve
    uint32_t      bLen;
    unsigned char gxBytes[SeosCryptoKey_Size_ECC]; ///< coord x of basepoint G
    uint32_t      gxLen;
    unsigned char gyBytes[SeosCryptoKey_Size_ECC]; ///< coord y of basepoint G
    uint32_t      gyLen;
    unsigned char pBytes[SeosCryptoKey_Size_ECC]; ///< prime P of base field
    uint32_t      pLen;
    unsigned char nBytes[SeosCryptoKey_Size_ECC]; ///< order of G
    uint32_t      nLen;
}
SeosCryptoKey_ECCParams;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_ECCParams params; ///< params of curve: A, B, G, P, n=ord(G)
    unsigned char           qxBytes[SeosCryptoKey_Size_ECC]; ///< x of point Q=P*d
    uint32_t                qxLen;
    unsigned char           qyBytes[SeosCryptoKey_Size_ECC]; ///< y of point Q=P*d
    uint32_t                qyLen;
}
SeosCryptoKey_ECCPub;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_ECCParams params; ///< params of curve: A, B, G, P, n=ord(G)
    unsigned char           dBytes[SeosCryptoKey_Size_ECC]; ///<  private scalar
    uint32_t                dLen;
}
SeosCryptoKey_ECCPrv;

/**
 * Public key for NIST SEPC256r1 curve; does not need to carry the params as the
 * key type already defines everything.
 */
typedef struct __attribute__((__packed__))
{
    unsigned char   qxBytes[SeosCryptoKey_Size_ECC]; ///< x of point Q=P*d
    uint32_t        qxLen;
    unsigned char   qyBytes[SeosCryptoKey_Size_ECC]; ///< y of point Q=P*d
    uint32_t        qyLen;
}
SeosCryptoKey_SECP256r1Pub;

/**
 * Private key for NIST SEPC256r1 curve; does not need to carry the params as the
 * key type already defines everything.
 */
typedef struct __attribute__((__packed__))
{
    unsigned char   dBytes[SeosCryptoKey_Size_ECC]; ///<  private scalar
    uint32_t        dLen;
}
SeosCryptoKey_SECP256r1Prv;

// -------------------------------- DH Keys ------------------------------------

typedef struct __attribute__((__packed__))
{
    unsigned char   pBytes[SeosCryptoKey_Size_DH]; ///< shared prime
    uint32_t        pLen;
    unsigned char   gBytes[SeosCryptoKey_Size_DH]; ///< shared generator
    uint32_t        gLen;
}
SeosCryptoKey_DHParams;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_DHParams params; ///< shared params of DH: generator G and prime P
    unsigned char          gxBytes[SeosCryptoKey_Size_DH]; ///< public key g^x mod p
    uint32_t               gxLen;
}
SeosCryptoKey_DHPub;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_DHParams params; ///< shared params of DH: generator G and prime P
    unsigned char          xBytes[SeosCryptoKey_Size_DH];  ///< private exponent
    uint32_t               xLen;
}
SeosCryptoKey_DHPrv;

/** @} */
