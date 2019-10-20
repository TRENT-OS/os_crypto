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

#include "mbedtls/ecp.h"

#include "SeosCryptoKey_Impl.h"

/**
 * We map the params we can load here to the constants to mbedTLS, because that
 * is effectively where we get those parameters from.
 */
typedef enum
{
    SeosCryptoKey_Param_NONE = 0,
    SeosCryptoKey_Param_ECC_SECP192R1 = MBEDTLS_ECP_DP_SECP192R1,
    SeosCryptoKey_Param_ECC_SECP224R1 = MBEDTLS_ECP_DP_SECP224R1,
    SeosCryptoKey_Param_ECC_SECP256R1 = MBEDTLS_ECP_DP_SECP256R1,
} SeosCryptoKey_Param;

typedef enum
{
    SeosCryptoKey_SpecType_NONE = 0,
    SeosCryptoKey_SpecType_BITS,
    SeosCryptoKey_SpecType_PARAMS,
} SeosCryptoKey_SpecType;

typedef struct
{
    SeosCryptoKey_Flags flags;
} SeosCryptoKey_Attribs;

typedef struct __attribute__((__packed__))
{
    SeosCryptoKey_SpecType  type;
    struct key
    {
        SeosCryptoKey_Type      type;
        SeosCryptoKey_Attribs   attribs;
        union params
        {
            size_t                  bits;
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

typedef struct
{
    SeosCryptoKey_Type      type;
    SeosCryptoKey_Attribs   attribs;
    void*                   data;
    size_t                  size;
}
SeosCryptoKey_v5;

/** @} */
