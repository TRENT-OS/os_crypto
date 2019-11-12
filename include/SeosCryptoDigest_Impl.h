/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoDigest_Impl.h
 *
 * @brief Digest data structures
 *
 */

#pragma once

#include "LibDebug/Debug.h"

#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

#include <stdbool.h>

#define SeosCryptoDigest_Size_MD5     16
#define SeosCryptoDigest_Size_SHA256  32

typedef enum
{
    SeosCryptoDigest_Algorithm_NONE = 0,
    SeosCryptoDigest_Algorithm_MD5,
    SeosCryptoDigest_Algorithm_SHA256,
}
SeosCryptoDigest_Algorithm;

typedef struct
{
    union
    {
        mbedtls_md5_context     md5;
        mbedtls_sha256_context  sha256;
    }
    mbedtls;

    SeosCryptoDigest_Algorithm algorithm;
    bool                       processed;
} SeosCryptoDigest;

/** @} */
