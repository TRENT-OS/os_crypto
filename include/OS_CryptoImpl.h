/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "lib/OS_CryptoLibCipher.h"
#include "lib/OS_CryptoLibKey.h"
#include "lib/OS_CryptoLibRng.h"
#include "lib/OS_CryptoLibDigest.h"
#include "lib/OS_CryptoLibMac.h"
#include "lib/OS_CryptoLibSignature.h"
#include "lib/OS_CryptoLibAgreement.h"

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
    OS_CryptoLibMac**,
    const OS_CryptoMac_Alg);

typedef seos_err_t
(*OS_CryptoImpl_Mac_exists)(
    void*,
    const OS_CryptoLibMac*);

typedef seos_err_t
(*OS_CryptoImpl_Mac_free)(
    void*,
    OS_CryptoLibMac*);

typedef seos_err_t
(*OS_CryptoImpl_Mac_start)(
    void*,
    OS_CryptoLibMac*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Mac_process)(
    void*,
    OS_CryptoLibMac*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Mac_finalize)(
    void*,
    OS_CryptoLibMac*,
    void*,
    size_t*);

// ------------------------------- Digest API ----------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Digest_init)(
    void*,
    OS_CryptoLibDigest**,
    const OS_CryptoDigest_Alg);

typedef seos_err_t
(*OS_CryptoImpl_Digest_exists)(
    void*,
    const OS_CryptoLibDigest*);

typedef seos_err_t
(*OS_CryptoImpl_Digest_free)(
    void*,
    OS_CryptoLibDigest*);

typedef seos_err_t
(*OS_CryptoImpl_Digest_clone)(
    void*,
    OS_CryptoLibDigest*,
    const OS_CryptoLibDigest*);

typedef seos_err_t
(*OS_CryptoImpl_Digest_process)(
    void*,
    OS_CryptoLibDigest*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Digest_finalize)(
    void*,
    OS_CryptoLibDigest*,
    void*,
    size_t*);

// -------------------------------- Key API ------------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Key_generate)(
    void*,
    OS_CryptoLibKey**,
    const OS_CryptoKey_Spec*);

typedef seos_err_t
(*OS_CryptoImpl_Key_import)(
    void*,
    OS_CryptoLibKey**,
    const OS_CryptoKey_Data*);

typedef seos_err_t
(*OS_CryptoImpl_Key_makePublic)(
    void*,
    OS_CryptoLibKey**,
    const OS_CryptoLibKey*,
    const OS_CryptoKey_Attribs*);

typedef seos_err_t
(*OS_CryptoImpl_Key_export)(
    void*,
    const OS_CryptoLibKey*,
    OS_CryptoKey_Data*);

typedef seos_err_t
(*OS_CryptoImpl_Key_getParams)(
    void*,
    const OS_CryptoLibKey*,
    void*,
    size_t*);

typedef seos_err_t
(*OS_CryptoImpl_Key_getAttribs)(
    void*,
    const OS_CryptoLibKey*,
    OS_CryptoKey_Attribs*);

typedef seos_err_t
(*OS_CryptoImpl_Key_exists)(
    void*,
    const OS_CryptoLibKey*);

typedef seos_err_t
(*OS_CryptoImpl_Key_free)(
    void*,
    OS_CryptoLibKey*);

typedef seos_err_t
(*OS_CryptoImpl_Key_loadParams)(
    void*,
    const OS_CryptoKey_Param,
    void*,
    size_t*);

// ----------------------------- Signature API ---------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Signature_init)(
    void*,
    OS_CryptoLibSignature**,
    const OS_CryptoSignature_Alg,
    const OS_CryptoDigest_Alg,
    const OS_CryptoLibKey*,
    const OS_CryptoLibKey*);

typedef seos_err_t
(*OS_CryptoImpl_Signature_exists)(
    void*,
    const OS_CryptoLibSignature* );

typedef seos_err_t
(*OS_CryptoImpl_Signature_free)(
    void*,
    OS_CryptoLibSignature*);

typedef seos_err_t
(*OS_CryptoImpl_Signature_sign)(
    void*,
    OS_CryptoLibSignature*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef seos_err_t
(*OS_CryptoImpl_Signature_verify)(
    void*,
    OS_CryptoLibSignature*,
    const void*,
    const size_t,
    const void*,
    const size_t);

// ----------------------------- Agreement API ---------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Agreement_init)(
    void*,
    OS_CryptoLibAgreement**,
    const OS_CryptoAgreement_Alg,
    const OS_CryptoLibKey*);

typedef seos_err_t
(*OS_CryptoImpl_Agreement_exists)(
    void*,
    const OS_CryptoLibAgreement*);

typedef seos_err_t
(*OS_CryptoImpl_Agreement_free)(
    void*,
    OS_CryptoLibAgreement*);

typedef seos_err_t
(*OS_CryptoImpl_Agreement_agree)(
    void*,
    OS_CryptoLibAgreement*,
    const OS_CryptoLibKey*,
    void*,
    size_t*);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*OS_CryptoImpl_Cipher_init)(
    void*,
    OS_CryptoLibCipher**,
    const OS_CryptoCipher_Alg,
    const OS_CryptoLibKey*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_exists)(
    void*,
    const OS_CryptoLibCipher*);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_free)(
    void*,
    OS_CryptoLibCipher*);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_process)(
    void*,
    OS_CryptoLibCipher*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_start)(
    void*,
    OS_CryptoLibCipher*,
    const void*,
    const size_t);

typedef seos_err_t
(*OS_CryptoImpl_Cipher_finalize)(
    void*,
    OS_CryptoLibCipher*,
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
} OS_CryptoImpl_Vtable;

typedef struct
{
    const OS_CryptoImpl_Vtable* vtable;
    void* context;
} OS_CryptoImpl;