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
#include <sys/user.h>

#define SeosCrypto_TO_SEOS_CRYPTO_CTX(self) (&(self)->parent)

#define INPUT_BUFFER_SIZE PAGE_SIZE

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
    unsigned char       inputBuffer[INPUT_BUFFER_SIZE];
} SeosCrypto;

INLINE void*
get_input_buf_ptr(SeosCrypto* self)
{
    return self->inputBuffer;
}

/** @} */
