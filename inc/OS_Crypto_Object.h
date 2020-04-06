/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"

#include "Crypto_Impl.h"

// Call function from self pointer
#define CALL(s, f, ...)                                         \
    (NULL == (s)) ?                                             \
        SEOS_ERROR_INVALID_PARAMETER :                          \
        (NULL == (s)->impl.vtable->f) ?                         \
            SEOS_ERROR_NOT_SUPPORTED :                          \
            (s)->impl.vtable->f((s)->impl.context, __VA_ARGS__)

// Allocate proxy object and set its API handle to self pointer
#define PROXY_INIT(p, s)                                                \
    if (NULL == &(p) || NULL == (s)) {                                  \
        return SEOS_ERROR_INVALID_PARAMETER;                            \
    }                                                                   \
    if(((p) = s->memIf.malloc(sizeof(OS_Crypto_Object_t))) == NULL) {   \
        return SEOS_ERROR_INSUFFICIENT_SPACE;                           \
    }                                                                   \
    (p)->hCrypto = (s);

// Free proxy object with associated API context's mem IF
#define PROXY_FREE(p)                           \
    if (NULL == (p)) {                          \
        return SEOS_ERROR_INVALID_PARAMETER;    \
    }                                           \
    (p)->hCrypto->memIf.free(p);

// Call function from proxy objects API handle
#define PROXY_CALL(p, f, ...)                               \
    (NULL == (p)) ?                                         \
        SEOS_ERROR_INVALID_PARAMETER :                      \
        (NULL == (p)->hCrypto->impl.vtable->f) ?            \
            SEOS_ERROR_NOT_SUPPORTED :                      \
            (p)->hCrypto->impl.vtable->f(                   \
                (p)->hCrypto->impl.context, __VA_ARGS__     \
            )

// Get object from proxy
#define PROXY_GET_OBJ(p) ((NULL == (p)) ? NULL : (p)->obj)

// Get object specific pointers to object from proxy
#define PROXY_GET_OBJ_PTR(p) ((NULL == (p)) ? NULL : &(p)->obj)

struct OS_Crypto
{
    Crypto_Impl_t impl;
    OS_Crypto_Mode_t mode;
    OS_Crypto_Memory_t memIf;
    void* server;
};

struct OS_Crypto_Object
{
    OS_Crypto_t* hCrypto;
    CryptoLib_Object_ptr obj;
};