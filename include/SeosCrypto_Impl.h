/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCrypto_Impl.h
 *
 * @brief Crypto core data structures and constants
 *
 */

#pragma once

#include "SeosCryptoRng_Impl.h"
#include "SeosCryptoCtx.h"

#include "LibUtil/PointerVector.h"

#include <stddef.h>
#include <sys/user.h>

#define SeosCrypto_TO_SEOS_CRYPTO_CTX(self) (&(self)->parent)

#define SeosCrypto_DATAPORT_SIZE    PAGE_SIZE
#define SeosCrypto_BUFFER_SIZE      SeosCrypto_DATAPORT_SIZE

typedef void* (SeosCrypto_MallocFunc)(size_t size);
typedef void  (SeosCrypto_FreeFunc)(void* ptr);
typedef int   (SeosCrypto_EntropyFunc)(void* ctx, unsigned char* buf,
                                       size_t len);

typedef struct
{
    SeosCrypto_MallocFunc*   malloc;
    SeosCrypto_FreeFunc*     free;
    SeosCrypto_EntropyFunc*  entropy;
} SeosCrypto_Callbacks;

typedef struct
{
    SeosCrypto_MallocFunc*   malloc;
    SeosCrypto_FreeFunc*     free;
}
SeosCrypto_MemIf;

typedef struct
{
    SeosCryptoCtx       parent;
    SeosCrypto_MemIf    memIf;
    SeosCryptoRng       cryptoRng;
    PointerVector       keyHandleVector;
    PointerVector       digestHandleVector;
    PointerVector       cipherHandleVector;
    PointerVector       signatureHandleVector;
    PointerVector       agreementHandleVector;
    /**
     * Buffer for outputs produced by crypto
     */
    unsigned char       buffer[SeosCrypto_BUFFER_SIZE];
} SeosCrypto;

/** @} */
