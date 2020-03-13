/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "lib/SeosCryptoLib_Cipher.h"
#include "lib/SeosCryptoLib_Key.h"
#include "lib/SeosCryptoLib_Rng.h"
#include "lib/SeosCryptoLib_Digest.h"
#include "lib/SeosCryptoLib_Mac.h"
#include "lib/SeosCryptoLib_Signature.h"
#include "lib/SeosCryptoLib_Agreement.h"

// -------------------------------- RNG API ------------------------------------

typedef seos_err_t
(*SeosCryptoImpl_Rng_getBytes)(
    void*,
    unsigned int,
    void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoImpl_Rng_reseed)(
    void*,
    const void*,
    const size_t);

// --------------------------------- MAC API -----------------------------------

typedef seos_err_t
(*SeosCryptoImpl_Mac_init)(
    void*,
    SeosCryptoLib_Mac**,
    const SeosCryptoApi_Mac_Alg);

typedef seos_err_t
(*SeosCryptoImpl_Mac_exists)(
    void*,
    const SeosCryptoLib_Mac*);

typedef seos_err_t
(*SeosCryptoImpl_Mac_free)(
    void*,
    SeosCryptoLib_Mac*);

typedef seos_err_t
(*SeosCryptoImpl_Mac_start)(
    void*,
    SeosCryptoLib_Mac*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoImpl_Mac_process)(
    void*,
    SeosCryptoLib_Mac*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoImpl_Mac_finalize)(
    void*,
    SeosCryptoLib_Mac*,
    void*,
    size_t*);

// ------------------------------- Digest API ----------------------------------

typedef seos_err_t
(*SeosCryptoImpl_Digest_init)(
    void*,
    SeosCryptoLib_Digest**,
    const SeosCryptoApi_Digest_Alg);

typedef seos_err_t
(*SeosCryptoImpl_Digest_exists)(
    void*,
    const SeosCryptoLib_Digest*);

typedef seos_err_t
(*SeosCryptoImpl_Digest_free)(
    void*,
    SeosCryptoLib_Digest*);

typedef seos_err_t
(*SeosCryptoImpl_Digest_clone)(
    void*,
    SeosCryptoLib_Digest*,
    const SeosCryptoLib_Digest*);

typedef seos_err_t
(*SeosCryptoImpl_Digest_process)(
    void*,
    SeosCryptoLib_Digest*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoImpl_Digest_finalize)(
    void*,
    SeosCryptoLib_Digest*,
    void*,
    size_t*);

// -------------------------------- Key API ------------------------------------

typedef seos_err_t
(*SeosCryptoImpl_Key_generate)(
    void*,
    SeosCryptoLib_Key**,
    const SeosCryptoApi_Key_Spec*);

typedef seos_err_t
(*SeosCryptoImpl_Key_import)(
    void*,
    SeosCryptoLib_Key**,
    const SeosCryptoApi_Key_Data*);

typedef seos_err_t
(*SeosCryptoImpl_Key_makePublic)(
    void*,
    SeosCryptoLib_Key**,
    const SeosCryptoLib_Key*,
    const SeosCryptoApi_Key_Attribs*);

typedef seos_err_t
(*SeosCryptoImpl_Key_export)(
    void*,
    const SeosCryptoLib_Key*,
    SeosCryptoApi_Key_Data*);

typedef seos_err_t
(*SeosCryptoImpl_Key_getParams)(
    void*,
    const SeosCryptoLib_Key*,
    void*,
    size_t*);

typedef seos_err_t
(*SeosCryptoImpl_Key_getAttribs)(
    void*,
    const SeosCryptoLib_Key*,
    SeosCryptoApi_Key_Attribs*);

typedef seos_err_t
(*SeosCryptoImpl_Key_exists)(
    void*,
    const SeosCryptoLib_Key*);

typedef seos_err_t
(*SeosCryptoImpl_Key_free)(
    void*,
    SeosCryptoLib_Key*);

typedef seos_err_t
(*SeosCryptoImpl_Key_loadParams)(
    void*,
    const SeosCryptoApi_Key_Param,
    void*,
    size_t*);

// ----------------------------- Signature API ---------------------------------

typedef seos_err_t
(*SeosCryptoImpl_Signature_init)(
    void*,
    SeosCryptoLib_Signature**,
    const SeosCryptoApi_Signature_Alg,
    const SeosCryptoApi_Digest_Alg,
    const SeosCryptoLib_Key*,
    const SeosCryptoLib_Key*);

typedef seos_err_t
(*SeosCryptoImpl_Signature_exists)(
    void*,
    const SeosCryptoLib_Signature* );

typedef seos_err_t
(*SeosCryptoImpl_Signature_free)(
    void*,
    SeosCryptoLib_Signature*);

typedef seos_err_t
(*SeosCryptoImpl_Signature_sign)(
    void*,
    SeosCryptoLib_Signature*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef seos_err_t
(*SeosCryptoImpl_Signature_verify)(
    void*,
    SeosCryptoLib_Signature*,
    const void*,
    const size_t,
    const void*,
    const size_t);

// ----------------------------- Agreement API ---------------------------------

typedef seos_err_t
(*SeosCryptoImpl_Agreement_init)(
    void*,
    SeosCryptoLib_Agreement**,
    const SeosCryptoApi_Agreement_Alg,
    const SeosCryptoLib_Key*);

typedef seos_err_t
(*SeosCryptoImpl_Agreement_exists)(
    void*,
    const SeosCryptoLib_Agreement*);

typedef seos_err_t
(*SeosCryptoImpl_Agreement_free)(
    void*,
    SeosCryptoLib_Agreement*);

typedef seos_err_t
(*SeosCryptoImpl_Agreement_agree)(
    void*,
    SeosCryptoLib_Agreement*,
    const SeosCryptoLib_Key*,
    void*,
    size_t*);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*SeosCryptoImpl_Cipher_init)(
    void*,
    SeosCryptoLib_Cipher**,
    const SeosCryptoApi_Cipher_Alg,
    const SeosCryptoLib_Key*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoImpl_Cipher_exists)(
    void*,
    const SeosCryptoLib_Cipher*);

typedef seos_err_t
(*SeosCryptoImpl_Cipher_free)(
    void*,
    SeosCryptoLib_Cipher*);

typedef seos_err_t
(*SeosCryptoImpl_Cipher_process)(
    void*,
    SeosCryptoLib_Cipher*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef seos_err_t
(*SeosCryptoImpl_Cipher_start)(
    void*,
    SeosCryptoLib_Cipher*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoImpl_Cipher_finalize)(
    void*,
    SeosCryptoLib_Cipher*,
    void*,
    size_t*);

// -----------------------------------------------------------------------------

typedef struct
{
    SeosCryptoImpl_Rng_getBytes Rng_getBytes;
    SeosCryptoImpl_Rng_reseed Rng_reseed;
    SeosCryptoImpl_Mac_init Mac_init;
    SeosCryptoImpl_Mac_exists Mac_exists;
    SeosCryptoImpl_Mac_free Mac_free;
    SeosCryptoImpl_Mac_start Mac_start;
    SeosCryptoImpl_Mac_process Mac_process;
    SeosCryptoImpl_Mac_finalize Mac_finalize;
    SeosCryptoImpl_Digest_init Digest_init;
    SeosCryptoImpl_Digest_exists Digest_exists;
    SeosCryptoImpl_Digest_free Digest_free;
    SeosCryptoImpl_Digest_clone Digest_clone;
    SeosCryptoImpl_Digest_process Digest_process;
    SeosCryptoImpl_Digest_finalize Digest_finalize;
    SeosCryptoImpl_Key_generate Key_generate;
    SeosCryptoImpl_Key_makePublic Key_makePublic;
    SeosCryptoImpl_Key_import Key_import;
    SeosCryptoImpl_Key_export Key_export;
    SeosCryptoImpl_Key_getParams Key_getParams;
    SeosCryptoImpl_Key_getAttribs Key_getAttribs;
    SeosCryptoImpl_Key_loadParams Key_loadParams;
    SeosCryptoImpl_Key_exists Key_exists;
    SeosCryptoImpl_Key_free Key_free;
    SeosCryptoImpl_Signature_init Signature_init;
    SeosCryptoImpl_Signature_exists Signature_exists;
    SeosCryptoImpl_Signature_free Signature_free;
    SeosCryptoImpl_Signature_sign Signature_sign;
    SeosCryptoImpl_Signature_verify Signature_verify;
    SeosCryptoImpl_Agreement_init Agreement_init;
    SeosCryptoImpl_Agreement_exists Agreement_exists;
    SeosCryptoImpl_Agreement_free Agreement_free;
    SeosCryptoImpl_Agreement_agree Agreement_agree;
    SeosCryptoImpl_Cipher_init Cipher_init;
    SeosCryptoImpl_Cipher_exists Cipher_exists;
    SeosCryptoImpl_Cipher_free Cipher_free;
    SeosCryptoImpl_Cipher_process Cipher_process;
    SeosCryptoImpl_Cipher_start Cipher_start;
    SeosCryptoImpl_Cipher_finalize Cipher_finalize;
} SeosCryptoImpl_Vtable;

typedef struct
{
    const SeosCryptoImpl_Vtable* vtable;
    void* context;
} SeosCryptoImpl;