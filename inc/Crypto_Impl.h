/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "lib/CryptoLibCipher.h"
#include "lib/CryptoLibKey.h"
#include "lib/CryptoLibDigest.h"
#include "lib/CryptoLibMac.h"
#include "lib/CryptoLibSignature.h"
#include "lib/CryptoLibAgreement.h"

// -------------------------------- RNG API ------------------------------------

typedef OS_Error_t
(*Rng_getBytes_func)(
    void*,
    unsigned int,
    void*,
    const size_t);

typedef OS_Error_t
(*Rng_reseed_func)(
    void*,
    const void*,
    const size_t);

// --------------------------------- MAC API -----------------------------------

typedef OS_Error_t
(*Mac_init_func)(
    void*,
    CryptoLibMac_t**,
    const OS_CryptoMac_Alg_t);

typedef OS_Error_t
(*Mac_free_func)(
    void*,
    CryptoLibMac_t*);

typedef OS_Error_t
(*Mac_start_func)(
    void*,
    CryptoLibMac_t*,
    const void*,
    const size_t);

typedef OS_Error_t
(*Mac_process_func)(
    void*,
    CryptoLibMac_t*,
    const void*,
    const size_t);

typedef OS_Error_t
(*Mac_finalize_func)(
    void*,
    CryptoLibMac_t*,
    void*,
    size_t*);

// ------------------------------- Digest API ----------------------------------

typedef OS_Error_t
(*Digest_init_func)(
    void*,
    CryptoLibDigest_t**,
    const OS_CryptoDigest_Alg_t);

typedef OS_Error_t
(*Digest_free_func)(
    void*,
    CryptoLibDigest_t*);

typedef OS_Error_t
(*Digest_clone_func)(
    void*,
    CryptoLibDigest_t*,
    const CryptoLibDigest_t*);

typedef OS_Error_t
(*Digest_process_func)(
    void*,
    CryptoLibDigest_t*,
    const void*,
    const size_t);

typedef OS_Error_t
(*Digest_finalize_func)(
    void*,
    CryptoLibDigest_t*,
    void*,
    size_t*);

// -------------------------------- Key API ------------------------------------

typedef OS_Error_t
(*Key_generate_func)(
    void*,
    CryptoLibKey_t**,
    const OS_CryptoKey_Spec_t*);

typedef OS_Error_t
(*Key_import_func)(
    void*,
    CryptoLibKey_t**,
    const OS_CryptoKey_Data_t*);

typedef OS_Error_t
(*Key_makePublic_func)(
    void*,
    CryptoLibKey_t**,
    const CryptoLibKey_t*,
    const OS_CryptoKey_Attrib_t*);

typedef OS_Error_t
(*Key_export_func)(
    void*,
    const CryptoLibKey_t*,
    OS_CryptoKey_Data_t*);

typedef OS_Error_t
(*Key_getParams_func)(
    void*,
    const CryptoLibKey_t*,
    void*,
    size_t*);

typedef OS_Error_t
(*Key_getAttribs_func)(
    void*,
    const CryptoLibKey_t*,
    OS_CryptoKey_Attrib_t*);

typedef OS_Error_t
(*Key_free_func)(
    void*,
    CryptoLibKey_t*);

typedef OS_Error_t
(*Key_loadParams_func)(
    void*,
    const OS_CryptoKey_Param_t,
    void*,
    size_t*);

// ----------------------------- Signature API ---------------------------------

typedef OS_Error_t
(*Signature_init_func)(
    void*,
    CryptoLibSignature_t**,
    const CryptoLibKey_t*,
    const CryptoLibKey_t*,
    const OS_CryptoSignature_Alg_t,
    const OS_CryptoDigest_Alg_t);

typedef OS_Error_t
(*Signature_free_func)(
    void*,
    CryptoLibSignature_t*);

typedef OS_Error_t
(*Signature_sign_func)(
    void*,
    CryptoLibSignature_t*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef OS_Error_t
(*Signature_verify_func)(
    void*,
    CryptoLibSignature_t*,
    const void*,
    const size_t,
    const void*,
    const size_t);

// ----------------------------- Agreement API ---------------------------------

typedef OS_Error_t
(*Agreement_init_func)(
    void*,
    CryptoLibAgreement_t**,
    const CryptoLibKey_t*,
    const OS_CryptoAgreement_Alg_t);

typedef OS_Error_t
(*Agreement_free_func)(
    void*,
    CryptoLibAgreement_t*);

typedef OS_Error_t
(*Agreement_agree_func)(
    void*,
    CryptoLibAgreement_t*,
    const CryptoLibKey_t*,
    void*,
    size_t*);

// ------------------------------ Cipher API -----------------------------------

typedef OS_Error_t
(*Cipher_init_func)(
    void*,
    CryptoLibCipher_t**,
    const CryptoLibKey_t*,
    const OS_CryptoCipher_Alg_t,
    const void*,
    const size_t);

typedef OS_Error_t
(*Cipher_free_func)(
    void*,
    CryptoLibCipher_t*);

typedef OS_Error_t
(*Cipher_process_func)(
    void*,
    CryptoLibCipher_t*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef OS_Error_t
(*Cipher_start_func)(
    void*,
    CryptoLibCipher_t*,
    const void*,
    const size_t);

typedef OS_Error_t
(*Cipher_finalize_func)(
    void*,
    CryptoLibCipher_t*,
    void*,
    size_t*);

// -----------------------------------------------------------------------------

typedef struct
{
    Rng_getBytes_func Rng_getBytes;
    Rng_reseed_func Rng_reseed;
    Mac_init_func Mac_init;
    Mac_free_func Mac_free;
    Mac_start_func Mac_start;
    Mac_process_func Mac_process;
    Mac_finalize_func Mac_finalize;
    Digest_init_func Digest_init;
    Digest_free_func Digest_free;
    Digest_clone_func Digest_clone;
    Digest_process_func Digest_process;
    Digest_finalize_func Digest_finalize;
    Key_generate_func Key_generate;
    Key_makePublic_func Key_makePublic;
    Key_import_func Key_import;
    Key_export_func Key_export;
    Key_getParams_func Key_getParams;
    Key_getAttribs_func Key_getAttribs;
    Key_loadParams_func Key_loadParams;
    Key_free_func Key_free;
    Signature_init_func Signature_init;
    Signature_free_func Signature_free;
    Signature_sign_func Signature_sign;
    Signature_verify_func Signature_verify;
    Agreement_init_func Agreement_init;
    Agreement_free_func Agreement_free;
    Agreement_agree_func Agreement_agree;
    Cipher_init_func Cipher_init;
    Cipher_free_func Cipher_free;
    Cipher_process_func Cipher_process;
    Cipher_start_func Cipher_start;
    Cipher_finalize_func Cipher_finalize;
} Crypto_Vtable_t;

typedef struct
{
    const Crypto_Vtable_t* vtable;
    void* context;
} Crypto_Impl_t;