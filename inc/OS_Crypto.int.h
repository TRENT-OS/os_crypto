/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/CryptoLibCipher.h"
#include "lib/CryptoLibKey.h"
#include "lib/CryptoLibDigest.h"
#include "lib/CryptoLibMac.h"
#include "lib/CryptoLibSignature.h"
#include "lib/CryptoLibAgreement.h"

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

typedef struct
{
    OS_Error_t (*Rng_getBytes)(void*, unsigned int, void*, const size_t);
    OS_Error_t (*Rng_reseed)(void*, const void*, const size_t);
    OS_Error_t (*Mac_init)(void*, CryptoLibMac_t**,  const CryptoLibKey_t*,
                           const OS_CryptoMac_Alg_t);
    OS_Error_t (*Mac_free)(void*, CryptoLibMac_t*);
    OS_Error_t (*Mac_process)(void*, CryptoLibMac_t*, const void*, const size_t);
    OS_Error_t (*Mac_finalize)(void*, CryptoLibMac_t*, void*, size_t*);
    OS_Error_t (*Digest_init)(void*, CryptoLibDigest_t**,
                              const OS_CryptoDigest_Alg_t);
    OS_Error_t (*Digest_free)(void*, CryptoLibDigest_t*);
    OS_Error_t (*Digest_clone)(void*, CryptoLibDigest_t**,
                               const CryptoLibDigest_t*);
    OS_Error_t (*Digest_process)(void*, CryptoLibDigest_t*, const void*,
                                 const size_t);
    OS_Error_t (*Digest_finalize)(void*, CryptoLibDigest_t*, void*, size_t*);
    OS_Error_t (*Key_generate)(void*, CryptoLibKey_t**, const OS_CryptoKey_Spec_t*);
    OS_Error_t (*Key_import)(void*, CryptoLibKey_t**, const OS_CryptoKey_Data_t*);
    OS_Error_t (*Key_makePublic)(void*, CryptoLibKey_t**, const CryptoLibKey_t*,
                                 const OS_CryptoKey_Attrib_t*);
    OS_Error_t (*Key_export)(void*, const CryptoLibKey_t*, OS_CryptoKey_Data_t*);
    OS_Error_t (*Key_getParams)(void*, const CryptoLibKey_t*, void*, size_t*);
    OS_Error_t (*Key_getAttribs)(void*, const CryptoLibKey_t*,
                                 OS_CryptoKey_Attrib_t*);
    OS_Error_t (*Key_free)(void*, CryptoLibKey_t*);
    OS_Error_t (*Key_loadParams)(void*, const OS_CryptoKey_Param_t, void*, size_t*);
    OS_Error_t (*Signature_init)(void*, CryptoLibSignature_t**,
                                 const CryptoLibKey_t*, const CryptoLibKey_t*, const OS_CryptoSignature_Alg_t,
                                 const OS_CryptoDigest_Alg_t);
    OS_Error_t (*Signature_free)(void*, CryptoLibSignature_t*);
    OS_Error_t (*Signature_sign)(void*, CryptoLibSignature_t*, const void*,
                                 const size_t, void*, size_t*);
    OS_Error_t (*Signature_verify)(void*, CryptoLibSignature_t*, const void*,
                                   const size_t, const void*, const size_t);
    OS_Error_t (*Agreement_init)(void*, CryptoLibAgreement_t**,
                                 const CryptoLibKey_t*, const OS_CryptoAgreement_Alg_t);
    OS_Error_t (*Agreement_free)(void*, CryptoLibAgreement_t*);
    OS_Error_t (*Agreement_agree)(void*, CryptoLibAgreement_t*,
                                  const CryptoLibKey_t*, void*, size_t*);
    OS_Error_t (*Cipher_init)(void*, CryptoLibCipher_t**, const CryptoLibKey_t*,
                              const OS_CryptoCipher_Alg_t, const void*, const size_t);
    OS_Error_t (*Cipher_free)(void*, CryptoLibCipher_t*);
    OS_Error_t (*Cipher_process)(void*, CryptoLibCipher_t*, const void*,
                                 const size_t, void*, size_t*);
    OS_Error_t (*Cipher_start)(void*, CryptoLibCipher_t*, const void*,
                               const size_t);
    OS_Error_t (*Cipher_finalize)(void*, CryptoLibCipher_t*, void*, size_t*);
} Crypto_Vtable_t;

typedef struct
{
    const Crypto_Vtable_t* vtable;
    void* context;
} Crypto_Impl_t;

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