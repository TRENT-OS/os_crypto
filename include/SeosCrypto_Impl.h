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

#define SeosCrypto_Size_DATAPORT    PAGE_SIZE
#define SeosCrypto_Size_BUFFER      SeosCrypto_Size_DATAPORT

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
    PointerVector       macHandleVector;
    PointerVector       digestHandleVector;
    PointerVector       cipherHandleVector;
    PointerVector       signatureHandleVector;
    PointerVector       agreementHandleVector;
    /**
     * When we have a function that takes an input buffer and produces an output
     * buffer, we copy the inputs to this buffer internally, so the caller can
     * use the identical buffer as input/output.
     */
    unsigned char       buffer[SeosCrypto_Size_BUFFER];
} SeosCrypto;

/** @} */
