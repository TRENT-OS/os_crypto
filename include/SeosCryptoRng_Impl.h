/* Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoRng_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCryptoRng
 *
 */

#pragma once

#include "mbedtls/ctr_drbg.h"

#include <limits.h>

typedef int (SeosCrypto_EntropyFunc)(void* ctx, unsigned char* buf, size_t len);

typedef enum
{
    SeosCryptoRng_Flags_NONE                = 0x0000,
} SeosCryptoRng_Flags ;

typedef struct
{
    mbedtls_ctr_drbg_context    drbg;
}
SeosCryptoRng;

/** @} */
