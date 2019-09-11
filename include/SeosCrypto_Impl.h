/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCrypto_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCrypto
 *
 */
#pragma once

#include "SeosCryptoRng_Impl.h"
#include "SeosCryptoCtx.h"

#include "LibUtil/PointerVector.h"

#include <stddef.h>

#define SeosCrypto_TO_SEOS_CRYPTO_CTX(self) (&(self)->parent)

typedef void* (SeosCrypto_MallocFunc)(size_t size);
typedef void  (SeosCrypto_FreeFunc)(void* ptr);

typedef struct
{
    SeosCrypto_MallocFunc*   malloc;
    SeosCrypto_FreeFunc*     free;
}
SeosCrypto_MemIf;

typedef struct
{
    void*   buf;
    size_t  len;
}
SeosCrypto_StaticBuf;

typedef struct
{
    SeosCryptoCtx   parent;
    union
    {
        SeosCrypto_MemIf        memIf;
        SeosCrypto_StaticBuf    staticBuf;
    }
    mem;

    SeosCryptoRng cryptoRng;
    PointerVector keyHandleVector;
    PointerVector digestHandleVector;
    PointerVector cipherHandleVector;
} SeosCrypto;

/** @} */
