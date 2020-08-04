/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "lib/CryptoLibCipher.h"
#include "lib/CryptoLibKey.h"
#include "lib/CryptoLibDigest.h"
#include "lib/CryptoLibMac.h"
#include "lib/CryptoLibSignature.h"
#include "lib/CryptoLibAgreement.h"

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