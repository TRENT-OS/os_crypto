/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoRng_Impl.h
 *
 * @brief RNG data structures and constants
 *
 */

#pragma once

#include "mbedtls/ctr_drbg.h"

#include <limits.h>

typedef enum
{
    SeosCryptoRng_Flags_NONE = 0x0000,
} SeosCryptoRng_Flags;

typedef struct
{
    mbedtls_ctr_drbg_context    drbg;
}
SeosCryptoRng;

/** @} */
