/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "lib/CryptoLibCipher.h"
#include "lib/CryptoLibKey.h"
#include "lib/CryptoLibRng.h"
#include "lib/CryptoLibDigest.h"
#include "lib/CryptoLibMac.h"
#include "lib/CryptoLibSignature.h"
#include "lib/CryptoLibAgreement.h"

// -------------------------------- RNG API ------------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Rng_getBytes)(
    void*,
    unsigned int,
    void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Rng_reseed)(
    void*,
    const void*,
    const size_t);

// --------------------------------- MAC API -----------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Mac_init)(
    void*,
    CryptoLibMac_t**,
    const OS_CryptoMac_Alg_t);

typedef seos_err_t
(*OS_CryptoImpl_Mac_exists)(
    void*,
    const CryptoLibMac_t*);

typedef seos_err_t
(*OS_CryptoImpl_Mac_free)(
    void*,
    CryptoLibMac_t*);

typedef seos_err_t
(*OS_CryptoImpl_Mac_start)(
    void*,
    CryptoLibMac_t*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Mac_process)(
    void*,
    CryptoLibMac_t*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Mac_finalize)(
    void*,
    CryptoLibMac_t*,
    void*,
    size_t*);

// ------------------------------- Digest API ----------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Digest_init)(
    void*,
    CryptoLibDigest_t**,
    const OS_CryptoDigest_Alg_t);

typedef seos_err_t
(*OS_CryptoImpl_Digest_exists)(
    void*,
    const CryptoLibDigest_t*);

typedef seos_err_t
(*OS_CryptoImpl_Digest_free)(
    void*,
    CryptoLibDigest_t*);

typedef seos_err_t
(*OS_CryptoImpl_Digest_clone)(
    void*,
    CryptoLibDigest_t*,
    const CryptoLibDigest_t*);

typedef seos_err_t
(*OS_CryptoImpl_Digest_process)(
    void*,
    CryptoLibDigest_t*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Digest_finalize)(
    void*,
    CryptoLibDigest_t*,
    void*,
    size_t*);

// -------------------------------- Key API ------------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Key_generate)(
    void*,
    CryptoLibKey_t**,
    const OS_CryptoKey_Spec_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_import)(
    void*,
    CryptoLibKey_t**,
    const OS_CryptoKey_Data_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_makePublic)(
    void*,
    CryptoLibKey_t**,
    const CryptoLibKey_t*,
    const OS_CryptoKey_Attrib_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_export)(
    void*,
    const CryptoLibKey_t*,
    OS_CryptoKey_Data_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_getParams)(
    void*,
    const CryptoLibKey_t*,
    void*,
    size_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_getAttribs)(
    void*,
    const CryptoLibKey_t*,
    OS_CryptoKey_Attrib_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_exists)(
    void*,
    const CryptoLibKey_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_free)(
    void*,
    CryptoLibKey_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_loadParams)(
    void*,
    const OS_CryptoKey_Param_t,
    void*,
    size_t*);

// ----------------------------- Signature API ---------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Signature_init)(
    void*,
    CryptoLibSignature_t**,
    const OS_CryptoSignature_Alg_t,
    const OS_CryptoDigest_Alg_t,
    const CryptoLibKey_t*,
    const CryptoLibKey_t*);

typedef seos_err_t
(*OS_CryptoImpl_Signature_exists)(
    void*,
    const CryptoLibSignature_t* );

typedef seos_err_t
(*OS_CryptoImpl_Signature_free)(
    void*,
    CryptoLibSignature_t*);

typedef seos_err_t
(*OS_CryptoImpl_Signature_sign)(
    void*,
    CryptoLibSignature_t*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef seos_err_t
(*OS_CryptoImpl_Signature_verify)(
    void*,
    CryptoLibSignature_t*,
    const void*,
    const size_t,
    const void*,
    const size_t);

// ----------------------------- Agreement API ---------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Agreement_init)(
    void*,
    CryptoLibAgreement_t**,
    const OS_CryptoAgreement_Alg_t,
    const CryptoLibKey_t*);

typedef seos_err_t
(*OS_CryptoImpl_Agreement_exists)(
    void*,
    const CryptoLibAgreement_t*);

typedef seos_err_t
(*OS_CryptoImpl_Agreement_free)(
    void*,
    CryptoLibAgreement_t*);

typedef seos_err_t
(*OS_CryptoImpl_Agreement_agree)(
    void*,
    CryptoLibAgreement_t*,
    const CryptoLibKey_t*,
    void*,
    size_t*);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Cipher_init)(
    void*,
    CryptoLibCipher_t**,
    const OS_CryptoCipher_Alg_t,
    const CryptoLibKey_t*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_exists)(
    void*,
    const CryptoLibCipher_t*);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_free)(
    void*,
    CryptoLibCipher_t*);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_process)(
    void*,
    CryptoLibCipher_t*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_start)(
    void*,
    CryptoLibCipher_t*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_finalize)(
    void*,
    CryptoLibCipher_t*,
    void*,
    size_t*);

// -----------------------------------------------------------------------------

typedef struct
{
    OS_CryptoImpl_Rng_getBytes Rng_getBytes;
    OS_CryptoImpl_Rng_reseed Rng_reseed;
    OS_CryptoImpl_Mac_init Mac_init;
    OS_CryptoImpl_Mac_exists Mac_exists;
    OS_CryptoImpl_Mac_free Mac_free;
    OS_CryptoImpl_Mac_start Mac_start;
    OS_CryptoImpl_Mac_process Mac_process;
    OS_CryptoImpl_Mac_finalize Mac_finalize;
    OS_CryptoImpl_Digest_init Digest_init;
    OS_CryptoImpl_Digest_exists Digest_exists;
    OS_CryptoImpl_Digest_free Digest_free;
    OS_CryptoImpl_Digest_clone Digest_clone;
    OS_CryptoImpl_Digest_process Digest_process;
    OS_CryptoImpl_Digest_finalize Digest_finalize;
    OS_CryptoImpl_Key_generate Key_generate;
    OS_CryptoImpl_Key_makePublic Key_makePublic;
    OS_CryptoImpl_Key_import Key_import;
    OS_CryptoImpl_Key_export Key_export;
    OS_CryptoImpl_Key_getParams Key_getParams;
    OS_CryptoImpl_Key_getAttribs Key_getAttribs;
    OS_CryptoImpl_Key_loadParams Key_loadParams;
    OS_CryptoImpl_Key_exists Key_exists;
    OS_CryptoImpl_Key_free Key_free;
    OS_CryptoImpl_Signature_init Signature_init;
    OS_CryptoImpl_Signature_exists Signature_exists;
    OS_CryptoImpl_Signature_free Signature_free;
    OS_CryptoImpl_Signature_sign Signature_sign;
    OS_CryptoImpl_Signature_verify Signature_verify;
    OS_CryptoImpl_Agreement_init Agreement_init;
    OS_CryptoImpl_Agreement_exists Agreement_exists;
    OS_CryptoImpl_Agreement_free Agreement_free;
    OS_CryptoImpl_Agreement_agree Agreement_agree;
    OS_CryptoImpl_Cipher_init Cipher_init;
    OS_CryptoImpl_Cipher_exists Cipher_exists;
    OS_CryptoImpl_Cipher_free Cipher_free;
    OS_CryptoImpl_Cipher_process Cipher_process;
    OS_CryptoImpl_Cipher_start Cipher_start;
    OS_CryptoImpl_Cipher_finalize Cipher_finalize;
} OS_CryptoImpl_Vtable_t;

typedef struct
{
    const OS_CryptoImpl_Vtable_t* vtable;
    void* context;
} OS_CryptoImpl_t;