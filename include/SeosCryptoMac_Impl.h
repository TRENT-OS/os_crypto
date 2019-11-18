/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoMac_Impl.h
 *
 * @brief Message authentication code (MAC) data structures
 *
 */

#pragma once

#include "LibDebug/Debug.h"

#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

#include <stdbool.h>

#define SeosCryptoMac_Size_HMAC_MD5     16
#define SeosCryptoMac_Size_HMAC_SHA256  32

typedef enum
{
    SeosCryptoMac_Algorithm_NONE = 0,
    SeosCryptoMac_Algorithm_HMAC_MD5,
    SeosCryptoMac_Algorithm_HMAC_SHA256,
}
SeosCryptoMac_Algorithm;

typedef struct
{
    union
    {
        mbedtls_md5_context     md5;
        mbedtls_sha256_context  sha256;
    }
    mbedtls;

    SeosCryptoMac_Algorithm algorithm;
    bool                    started;
    bool                    processed;
    bool                    finalized;
} SeosCryptoMac;

/** @} */
