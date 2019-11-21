/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoKey_Impl.h
 *
 * @brief Key data structures and constants
 *
 */

#pragma once

#include "LibDebug/Debug.h"

#include "mbedtls/ecp.h"

/**
 * How often do we want to retry finding a suitable prime P and also
 * a suitable X with 2 <= X <= P-2?
 */
#define SeosCryptoKey_DH_GEN_RETRIES    10

#define SeosCryptoKey_DH_GENERATOR      2       ///< Generator for DH
#define SeosCryptoKey_RSA_EXPONENT      65537   ///< Public exp. 2^16+1

#define SeosCryptoKey_Size_AES_MAX      32      ///< max 256 bit
#define SeosCryptoKey_Size_RSA_MIN      16      ///< min 128 bit
#define SeosCryptoKey_Size_RSA_MAX      512     ///< max 4096 bit
#define SeosCryptoKey_Size_DH_MIN       8       ///< min 64 bit
#define SeosCryptoKey_Size_DH_MAX       512     ///< max 4096 bit
#define SeosCryptoKey_Size_ECC_MAX      32      ///< always 256 bit

// -----------------------------------------------------------------------------

typedef enum
{
    SeosCryptoKey_Param_NONE          = MBEDTLS_ECP_DP_NONE,
    SeosCryptoKey_Param_ECC_SECP192R1 = MBEDTLS_ECP_DP_SECP192R1,
    SeosCryptoKey_Param_ECC_SECP224R1 = MBEDTLS_ECP_DP_SECP224R1,
    SeosCryptoKey_Param_ECC_SECP256R1 = MBEDTLS_ECP_DP_SECP256R1,
} SeosCryptoKey_Param;

// Make sure these hold, otherwise stuff will break!
Debug_STATIC_ASSERT((int)SeosCryptoKey_Param_NONE            ==
                    (int)MBEDTLS_ECP_DP_NONE);
Debug_STATIC_ASSERT((int)SeosCryptoKey_Param_ECC_SECP192R1   ==
                    (int)MBEDTLS_ECP_DP_SECP192R1);
Debug_STATIC_ASSERT((int)SeosCryptoKey_Param_ECC_SECP224R1   ==
                    (int)MBEDTLS_ECP_DP_SECP224R1);
Debug_STATIC_ASSERT((int)SeosCryptoKey_Param_ECC_SECP256R1   ==
                    (int)MBEDTLS_ECP_DP_SECP256R1);

typedef enum
{
    SeosCryptoKey_SpecType_NONE = 0,
    SeosCryptoKey_SpecType_BITS,
    SeosCryptoKey_SpecType_PARAMS,
} SeosCryptoKey_SpecType;

typedef enum
{
    SeosCryptoKey_Flags_NONE                = 0x0000,
    SeosCryptoKey_Flags_EXPORTABLE_RAW      = 0x0001,
    SeosCryptoKey_Flags_EXPORTABLE_WRAPPED  = 0x0002
}
SeosCryptoKey_Flags;

typedef enum
{
    SeosCryptoKey_Type_NONE = 0,
    SeosCryptoKey_Type_AES,
    SeosCryptoKey_Type_RSA_PRV,
    SeosCryptoKey_Type_RSA_PUB,
    SeosCryptoKey_Type_DH_PRV,
    SeosCryptoKey_Type_DH_PUB,
    SeosCryptoKey_Type_SECP256R1_PRV,
    SeosCryptoKey_Type_SECP256R1_PUB,
    SeosCryptoKey_Type_ECC_PRV,
    SeosCryptoKey_Type_ECC_PUB
}
SeosCryptoKey_Type;

typedef struct
{
    SeosCryptoKey_Flags flags;
} SeosCryptoKey_Attribs;

typedef struct
{
    SeosCryptoKey_Type      type;
    SeosCryptoKey_Attribs   attribs;
    void*                   data;
    uint32_t                size;
}
SeosCryptoKey;

// ----------------------------- Symmetric Keys --------------------------------

typedef struct __attribute__((__packed__))
{
    unsigned char   bytes[SeosCryptoKey_Size_AES_MAX];
    uint32_t        len;
}
SeosCryptoKey_AES;

// -------------------------------- RSA Keys -----------------------------------

typedef struct __attribute__((__packed__))
{
    unsigned char   nBytes[SeosCryptoKey_Size_RSA_MAX]; ///< public modulus n=p*q
    uint32_t        nLen;
    unsigned char   eBytes[SeosCryptoKey_Size_RSA_MAX]; ///< public exponent
    uint32_t        eLen;
}
SeosCryptoKey_RSAPub;

typedef struct __attribute__((__packed__))
{
    unsigned char   dBytes[SeosCryptoKey_Size_RSA_MAX]; ///< secret exp.
    uint32_t        dLen;
    unsigned char   eBytes[SeosCryptoKey_Size_RSA_MAX]; ///< public exp.
    uint32_t        eLen;
    unsigned char   pBytes[SeosCryptoKey_Size_RSA_MAX / 2]; ///< prime factor of n
    uint32_t        pLen;
    unsigned char   qBytes[SeosCryptoKey_Size_RSA_MAX / 2]; ///< prime factor of n
    uint32_t        qLen;
}
SeosCryptoKey_RSAPrv;

// -------------------------------- ECC Keys -----------------------------------

typedef struct __attribute__((__packed__))
{
    unsigned char aBytes[SeosCryptoKey_Size_ECC_MAX]; ///< A of Weierstrass curve
    uint32_t      aLen;
    unsigned char bBytes[SeosCryptoKey_Size_ECC_MAX]; ///< B of Weierstrass curve
    uint32_t      bLen;
    unsigned char gxBytes[SeosCryptoKey_Size_ECC_MAX]; ///< coord x of basepoint G
    uint32_t      gxLen;
    unsigned char gyBytes[SeosCryptoKey_Size_ECC_MAX]; ///< coord y of basepoint G
    uint32_t      gyLen;
    unsigned char pBytes[SeosCryptoKey_Size_ECC_MAX]; ///< prime P of base field
    uint32_t      pLen;
    unsigned char nBytes[SeosCryptoKey_Size_ECC_MAX]; ///< order of G
    uint32_t      nLen;
}
SeosCryptoKey_ECCParams;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_ECCParams params; ///< params of curve: A, B, G, P, n=ord(G)
    unsigned char
    qxBytes[SeosCryptoKey_Size_ECC_MAX]; ///< x of point Q=P*d
    uint32_t                qxLen;
    unsigned char
    qyBytes[SeosCryptoKey_Size_ECC_MAX]; ///< y of point Q=P*d
    uint32_t                qyLen;
}
SeosCryptoKey_ECCPub;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_ECCParams params; ///< params of curve: A, B, G, P, n=ord(G)
    unsigned char           dBytes[SeosCryptoKey_Size_ECC_MAX]; ///<  private scalar
    uint32_t                dLen;
}
SeosCryptoKey_ECCPrv;

/**
 * Public key for NIST SEPC256r1 curve; does not need to carry the params as the
 * key type already defines everything.
 */
typedef struct __attribute__((__packed__))
{
    unsigned char   qxBytes[SeosCryptoKey_Size_ECC_MAX]; ///< x of point Q=P*d
    uint32_t        qxLen;
    unsigned char   qyBytes[SeosCryptoKey_Size_ECC_MAX]; ///< y of point Q=P*d
    uint32_t        qyLen;
}
SeosCryptoKey_SECP256r1Pub;

/**
 * Private key for NIST SEPC256r1 curve; does not need to carry the params as the
 * key type already defines everything.
 */
typedef struct __attribute__((__packed__))
{
    unsigned char   dBytes[SeosCryptoKey_Size_ECC_MAX]; ///<  private scalar
    uint32_t        dLen;
}
SeosCryptoKey_SECP256r1Prv;

// -------------------------------- DH Keys ------------------------------------

typedef struct __attribute__((__packed__))
{
    unsigned char   pBytes[SeosCryptoKey_Size_DH_MAX]; ///< shared prime
    uint32_t        pLen;
    unsigned char   gBytes[SeosCryptoKey_Size_DH_MAX]; ///< shared generator
    uint32_t        gLen;
}
SeosCryptoKey_DHParams;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_DHParams params; ///< shared params of DH: generator G and prime P
    unsigned char
    gxBytes[SeosCryptoKey_Size_DH_MAX]; ///< public key g^x mod p
    uint32_t               gxLen;
}
SeosCryptoKey_DHPub;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_DHParams params; ///< shared params of DH: generator G and prime P
    unsigned char          xBytes[SeosCryptoKey_Size_DH_MAX];  ///< private exponent
    uint32_t               xLen;
}
SeosCryptoKey_DHPrv;

// -----------------------------------------------------------------------------

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_SpecType  type;
    struct key
    {
        SeosCryptoKey_Type      type;
        SeosCryptoKey_Attribs   attribs;
        union params
        {
            uint32_t                bits;
            SeosCryptoKey_ECCParams ecc;
            SeosCryptoKey_DHParams  dh;
        } params;
    } key;
}
SeosCryptoKey_Spec;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_Type      type;
    SeosCryptoKey_Attribs   attribs;
    union data
    {
        union ecc
        {
            SeosCryptoKey_ECCPrv prv;
            SeosCryptoKey_ECCPub pub;
        } ecc;
        union secp256r1
        {
            SeosCryptoKey_SECP256r1Prv prv;
            SeosCryptoKey_SECP256r1Pub pub;
        } secp256r1;
        union dh
        {
            SeosCryptoKey_DHPrv prv;
            SeosCryptoKey_DHPub pub;
        } dh;
        union rsa
        {
            SeosCryptoKey_RSAPrv prv;
            SeosCryptoKey_RSAPub pub;
        } rsa;
        SeosCryptoKey_AES aes;
    } data;
}
SeosCryptoKey_Data;

/** @} */
