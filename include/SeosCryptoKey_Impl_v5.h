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

#include "SeosCryptoKey_Impl.h"

typedef enum
{
    SeosCryptoKey_ParamName_NONE = 0,
    SeosCryptoKey_ParamName_ECC_SECP256R1
} SeosCryptoKey_ParamName;

typedef enum
{
    SeosCryptoKey_SpecType_NONE = 0,
    SeosCryptoKey_SpecType_BITS,
    SeosCryptoKey_SpecType_DH_PARAMS,
    SeosCryptoKey_SpecType_ECC_PARAMS,
} SeosCryptoKey_SpecType;

typedef struct
{
    SeosCryptoKey_Flags flags;
} SeosCryptoKey_Attribs;

typedef struct
{
    SeosCryptoKey_SpecType  type;
    struct spec
    {
        SeosCryptoKey_Type      type;
        SeosCryptoKey_Attribs   attribs;
        union params
        {
            size_t                  bits;
            SeosCryptoKey_ECCParams ecc;
            SeosCryptoKey_DHParams  dh;
        } params;
    } spec;
} SeosCryptoKey_Spec;

typedef struct
{
    SeosCryptoKey_Type      type;
    SeosCryptoKey_Attribs   attribs;
    union key
    {
        SeosCryptoKey_ECCPrv        eccPrv;
        SeosCryptoKey_ECCPub        eccPub;
        SeosCryptoKey_SECP256r1Prv  secp256r1Prv;
        SeosCryptoKey_SECP256r1Pub  secp256r1Pub;
        SeosCryptoKey_DHPrv         dhPrv;
        SeosCryptoKey_DHPub         dhPub;
        SeosCryptoKey_RSAPrv        rsaPrv;
        SeosCryptoKey_RSAPub        rsaPub;
        SeosCryptoKey_AES           aes;
    } key;
} SeosCryptoKey_Data;

typedef struct
{
    SeosCryptoKey_Type      type;
    SeosCryptoKey_Attribs   attribs;
    void*                   data;
    size_t                  size;
}
SeosCryptoKey_v5;

/** @} */
