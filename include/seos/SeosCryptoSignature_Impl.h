/* Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoSignature_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCryptoSignature
 *
 */

#pragma once

#include "compiler.h"
#include "mbedtls/rsa.h"

typedef struct
{
    union
    {
        mbedtls_rsa_context     rsa;
    }
    agorithmCtx;
}
SeosCryptoSignature_Impl;

