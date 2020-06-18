/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"

#include "Crypto_Impl.h"

#include "rpc/CryptoLibServer.h"

// Call LIB or CLI, based on mode of API
#define CALL(s, f, ...)                                                             \
    (NULL == (s)) ?                                                                 \
        OS_ERROR_INVALID_PARAMETER :                                                \
        ((s)->mode == OS_Crypto_MODE_CLIENT_ONLY) ?                                 \
            (NULL == (s)->rpc.client.vtable->f) ?                                   \
                OS_ERROR_NOT_SUPPORTED :                                            \
                (s)->rpc.client.vtable->f((s)->rpc.client.context, __VA_ARGS__) :   \
            (NULL == (s)->library.vtable->f) ?                                      \
                OS_ERROR_NOT_SUPPORTED :                                            \
                (s)->library.vtable->f((s)->library.context, __VA_ARGS__)

// Allocate proxy object from crypto handle and set its impl according to
// the c flag
#define PROXY_INIT(p, s, c)                                                 \
    if (NULL == &(p) || NULL == (s)) {                                      \
        return OS_ERROR_INVALID_PARAMETER;                                  \
    }                                                                       \
    if(((p) = s->memory.calloc(1, sizeof(OS_Crypto_Object_t))) == NULL) {   \
        return OS_ERROR_INSUFFICIENT_SPACE;                                 \
    }                                                                       \
    (p)->parent = (s);                                                      \
    (p)->impl   = (c) ? &(s)->rpc.client : &(s)->library;

// Allocate proxy object from key proxy and simply copy the impl
#define PROXY_INIT_FROM_KEY(p, k)                                                   \
    if (NULL == &(p)) {                                                             \
        return OS_ERROR_INVALID_PARAMETER;                                          \
    } else if (NULL == (k)) {                                                       \
        return OS_ERROR_INVALID_HANDLE;                                             \
    }                                                                               \
    if(((p) = k->parent->memory.calloc(1, sizeof(OS_Crypto_Object_t))) == NULL) {   \
        return OS_ERROR_INSUFFICIENT_SPACE;                                         \
    }                                                                               \
    (p)->parent = (k)->parent;                                                      \
    (p)->impl   = (k)->impl;

// Free proxy object with associated API context's mem IF
#define PROXY_FREE(p)                           \
    if (NULL == (p)) {                          \
        return OS_ERROR_INVALID_PARAMETER;      \
    }                                           \
    (p)->parent->memory.free(p);

// Call function from proxy objects API handle
#define PROXY_CALL(p, f, ...)                       \
    (NULL == (p)) ?                                 \
        OS_ERROR_INVALID_PARAMETER :                \
        (NULL == (p)->impl->vtable->f) ?            \
            OS_ERROR_NOT_SUPPORTED :                \
            (p)->impl->vtable->f(                   \
                (p)->impl->context, __VA_ARGS__     \
            )

// Get object from proxy
#define PROXY_GET_OBJ(p) ((NULL == (p)) ? NULL : (p)->obj)

// Get object specific pointers to object from proxy
#define PROXY_GET_OBJ_PTR(p) ((NULL == (p)) ? NULL : &(p)->obj)

struct OS_Crypto
{
    OS_Crypto_Mode_t mode;
    OS_Crypto_Memory_t memory;
    Crypto_Impl_t library;
    union
    {
        Crypto_Impl_t client;
        CryptoLibServer_t* server;
    } rpc;
};

struct OS_Crypto_Object
{
    OS_Crypto_t* parent;
    Crypto_Impl_t* impl;
    CryptoLib_Object_ptr obj;
};