/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

// -------------------------------- RNG API ------------------------------------

typedef seos_err_t
(*SeosCryptoVtable_Rng_getBytesT)(
    void*,
    unsigned int,
    void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoVtable_Rng_reseedT)(
    void*,
    const void*,
    const size_t);

// --------------------------------- MAC API -----------------------------------

typedef seos_err_t
(*SeosCryptoVtable_Mac_initT)(
    void*,
    SeosCryptoLib_Mac**,
    const SeosCryptoApi_Mac_Alg);

typedef seos_err_t
(*SeosCryptoVtable_Mac_freeT)(
    void*,
    SeosCryptoLib_Mac*);

typedef seos_err_t
(*SeosCryptoVtable_Mac_startT)(
    void*,
    SeosCryptoLib_Mac*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoVtable_Mac_processT)(
    void*,
    SeosCryptoLib_Mac*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoVtable_Mac_finalizeT)(
    void*,
    SeosCryptoLib_Mac*,
    void*,
    size_t*);

// ------------------------------- Digest API ----------------------------------

typedef seos_err_t
(*SeosCryptoVtable_Digest_initT)(
    void*,
    SeosCryptoLib_Digest**,
    const SeosCryptoApi_Digest_Alg);

typedef seos_err_t
(*SeosCryptoVtable_Digest_freeT)(
    void*,
    SeosCryptoLib_Digest*);

typedef seos_err_t
(*SeosCryptoVtable_Digest_cloneT)(
    void*,
    SeosCryptoLib_Digest*,
    const SeosCryptoLib_Digest*);

typedef seos_err_t
(*SeosCryptoVtable_Digest_processT)(
    void*,
    SeosCryptoLib_Digest*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoVtable_Digest_finalizeT)(
    void*,
    SeosCryptoLib_Digest*,
    void*,
    size_t*);

// -------------------------------- Key API ------------------------------------

typedef seos_err_t
(*SeosCryptoVtable_Key_generateT)(
    void*,
    SeosCryptoLib_Key**,
    const SeosCryptoApi_Key_Spec*);

typedef seos_err_t
(*SeosCryptoVtable_Key_importT)(
    void*,
    SeosCryptoLib_Key**,
    const SeosCryptoApi_Key_Data*);

typedef seos_err_t
(*SeosCryptoVtable_Key_makePublicT)(
    void*,
    SeosCryptoLib_Key**,
    const SeosCryptoLib_Key*,
    const SeosCryptoApi_Key_Attribs*);

typedef seos_err_t
(*SeosCryptoVtable_Key_exportT)(
    void*,
    const SeosCryptoLib_Key*,
    SeosCryptoApi_Key_Data*);

typedef seos_err_t
(*SeosCryptoVtable_Key_getParamsT)(
    void*,
    const SeosCryptoLib_Key*,
    void*,
    size_t*);

typedef seos_err_t
(*SeosCryptoVtable_Key_freeT)(
    void*,
    SeosCryptoLib_Key*);

typedef seos_err_t
(*SeosCryptoVtable_Key_loadParamsT)(
    void*,
    const SeosCryptoApi_Key_Param,
    void*,
    size_t*);

// ----------------------------- Signature API ---------------------------------

typedef seos_err_t
(*SeosCryptoVtable_Signature_initT)(
    void*,
    SeosCryptoLib_Signature**,
    const SeosCryptoApi_Signature_Alg,
    const SeosCryptoApi_Digest_Alg,
    const SeosCryptoLib_Key*,
    const SeosCryptoLib_Key*);

typedef seos_err_t
(*SeosCryptoVtable_Signature_freeT)(
    void*,
    SeosCryptoLib_Signature* );

typedef seos_err_t
(*SeosCryptoVtable_Signature_signT)(
    void*,
    SeosCryptoLib_Signature*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef seos_err_t
(*SeosCryptoVtable_Signature_verifyT)(
    void*,
    SeosCryptoLib_Signature*,
    const void*,
    const size_t,
    const void*,
    const size_t);

// ----------------------------- Agreement API ---------------------------------

typedef seos_err_t
(*SeosCryptoVtable_Agreement_initT)(
    void*,
    SeosCryptoLib_Agreement**,
    const SeosCryptoApi_Agreement_Alg,
    const SeosCryptoLib_Key*);

typedef seos_err_t
(*SeosCryptoVtable_Agreement_freeT)(
    void*,
    SeosCryptoLib_Agreement*);

typedef seos_err_t
(*SeosCryptoVtable_Agreement_agreeT)(
    void*,
    SeosCryptoLib_Agreement*,
    const SeosCryptoLib_Key*,
    void*,
    size_t*);

// ------------------------------ Cipher API -----------------------------------

typedef seos_err_t
(*SeosCryptoVtable_Cipher_initT)(
    void*,
    SeosCryptoLib_Cipher**,
    const SeosCryptoApi_Cipher_Alg,
    const SeosCryptoLib_Key*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoVtable_Cipher_freeT)(
    void*,
    SeosCryptoLib_Cipher*);

typedef seos_err_t
(*SeosCryptoVtable_Cipher_processT)(
    void*,
    SeosCryptoLib_Cipher*,
    const void*,
    const size_t,
    void*,
    size_t*);

typedef seos_err_t
(*SeosCryptoVtable_Cipher_startT)(
    void*,
    SeosCryptoLib_Cipher*,
    const void*,
    const size_t);

typedef seos_err_t
(*SeosCryptoVtable_Cipher_finalizeT)(
    void*,
    SeosCryptoLib_Cipher*,
    void*,
    size_t*);

// -----------------------------------------------------------------------------

struct SeosCryptoVtable
{
    SeosCryptoVtable_Rng_getBytesT Rng_getBytes;
    SeosCryptoVtable_Rng_reseedT Rng_reseed;
    SeosCryptoVtable_Mac_initT Mac_init;
    SeosCryptoVtable_Mac_freeT Mac_free;
    SeosCryptoVtable_Mac_startT Mac_start;
    SeosCryptoVtable_Mac_processT Mac_process;
    SeosCryptoVtable_Mac_finalizeT Mac_finalize;
    SeosCryptoVtable_Digest_initT Digest_init;
    SeosCryptoVtable_Digest_freeT Digest_free;
    SeosCryptoVtable_Digest_cloneT Digest_clone;
    SeosCryptoVtable_Digest_processT Digest_process;
    SeosCryptoVtable_Digest_finalizeT Digest_finalize;
    SeosCryptoVtable_Key_generateT Key_generate;
    SeosCryptoVtable_Key_makePublicT Key_makePublic;
    SeosCryptoVtable_Key_importT Key_import;
    SeosCryptoVtable_Key_exportT Key_export;
    SeosCryptoVtable_Key_getParamsT Key_getParams;
    SeosCryptoVtable_Key_loadParamsT Key_loadParams;
    SeosCryptoVtable_Key_freeT Key_free;
    SeosCryptoVtable_Signature_initT Signature_init;
    SeosCryptoVtable_Signature_freeT Signature_free;
    SeosCryptoVtable_Signature_signT Signature_sign;
    SeosCryptoVtable_Signature_verifyT Signature_verify;
    SeosCryptoVtable_Agreement_initT Agreement_init;
    SeosCryptoVtable_Agreement_freeT Agreement_free;
    SeosCryptoVtable_Agreement_agreeT Agreement_agree;
    SeosCryptoVtable_Cipher_initT Cipher_init;
    SeosCryptoVtable_Cipher_freeT Cipher_free;
    SeosCryptoVtable_Cipher_processT Cipher_process;
    SeosCryptoVtable_Cipher_startT Cipher_start;
    SeosCryptoVtable_Cipher_finalizeT Cipher_finalize;
};