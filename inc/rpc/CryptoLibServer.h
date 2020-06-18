/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "lib/CryptoLib.h"

// -------------------------- defines/types/variables --------------------------

typedef struct CryptoLibServer CryptoLibServer_t;

// ------------------------------- Init/Free -----------------------------------

OS_Error_t
CryptoLibServer_init(
    CryptoLibServer_t**       ctx,
    const Crypto_Impl_t*      impl,
    const OS_Crypto_Memory_t* memory,
    const OS_Dataport_t*      dataport);

OS_Error_t
CryptoLibServer_free(
    CryptoLibServer_t* self);

// -------------------------------- RNG API ------------------------------------

OS_Error_t
CryptoLibServer_Rng_getBytes(
    unsigned int flags,
    size_t       dataSize);

OS_Error_t
CryptoLibServer_Rng_reseed(
    size_t seedSize);

// -------------------------------- Key API ------------------------------------

typedef CryptoLibKey_t* CryptoLibKey_ptr;
typedef const CryptoLibKey_t* CryptoLibKey_cptr;

OS_Error_t
CryptoLibServer_Key_generate(
    CryptoLibKey_ptr* pKeyPtr);

OS_Error_t
CryptoLibServer_Key_makePublic(
    CryptoLibKey_ptr* pPubKeyPtr,
    CryptoLibKey_cptr prvkeyPtr);

OS_Error_t
CryptoLibServer_Key_import(
    CryptoLibKey_ptr* pPubKeyPtr);

OS_Error_t
CryptoLibServer_Key_export(
    CryptoLibKey_cptr keyPtr);

OS_Error_t
CryptoLibServer_Key_getParams(
    CryptoLibKey_cptr keyPtr,
    size_t*           paramSize);

OS_Error_t
CryptoLibServer_Key_getAttribs(
    CryptoLibKey_cptr keyPtr);

OS_Error_t
CryptoLibServer_Key_loadParams(
    OS_CryptoKey_Param_t name,
    size_t*              paramSize);

OS_Error_t
CryptoLibServer_Key_free(
    CryptoLibKey_ptr keyPtr);

// -------------------------------- MAC API ------------------------------------

typedef CryptoLibMac_t* CryptoLibMac_ptr;
typedef const CryptoLibMac_t* CryptoLibMac_cptr;

OS_Error_t
CryptoLibServer_Mac_init(
    CryptoLibMac_ptr*  pMacPtr,
    CryptoLibKey_cptr  keyPtr,
    OS_CryptoMac_Alg_t algorithm);

OS_Error_t
CryptoLibServer_Mac_free(
    CryptoLibMac_ptr macPtr);

OS_Error_t
CryptoLibServer_Mac_process(
    CryptoLibMac_ptr macPtr,
    size_t           dataSize);

OS_Error_t
CryptoLibServer_Mac_finalize(
    CryptoLibMac_ptr macPtr,
    size_t*          macSize);

// ------------------------------ Digest API -----------------------------------

typedef CryptoLibDigest_t* CryptoLibDigest_ptr;
typedef const CryptoLibDigest_t* CryptoLibDigest_cptr;

OS_Error_t
CryptoLibServer_Digest_init(
    CryptoLibDigest_ptr*  pDigPtr,
    OS_CryptoDigest_Alg_t algorithm);

OS_Error_t
CryptoLibServer_Digest_clone(
    CryptoLibDigest_ptr* pDigPtr,
    CryptoLibDigest_cptr srcDigPtr);

OS_Error_t
CryptoLibServer_Digest_free(
    CryptoLibDigest_ptr digPtr);

OS_Error_t
CryptoLibServer_Digest_process(
    CryptoLibDigest_ptr digPtr,
    size_t              inSize);

OS_Error_t
CryptoLibServer_Digest_finalize(
    CryptoLibDigest_ptr digPtr,
    size_t*             digestSize);

// ----------------------------- Signature API ---------------------------------

typedef CryptoLibSignature_t* CryptoLibSignature_ptr;
typedef const CryptoLibSignature_t* CryptoLibSignature_cptr;

OS_Error_t
CryptoLibServer_Signature_init(
    CryptoLibSignature_ptr*  pSigPtr,
    CryptoLibKey_cptr        prvPtr,
    CryptoLibKey_cptr        pubPtr,
    OS_CryptoSignature_Alg_t algorithm,
    OS_CryptoDigest_Alg_t    digest);

OS_Error_t
CryptoLibServer_Signature_verify(
    CryptoLibSignature_ptr sigPtr,
    size_t                 hashSize,
    size_t                 signatureSize);

OS_Error_t
CryptoLibServer_Signature_sign(
    CryptoLibSignature_ptr sigPtr,
    size_t                 hashSize,
    size_t*                signatureSize);

OS_Error_t
CryptoLibServer_Signature_free(
    CryptoLibSignature_ptr sigPtr);

// ----------------------------- Agreement API ---------------------------------

typedef CryptoLibAgreement_t* CryptoLibAgreement_ptr;
typedef const CryptoLibAgreement_t* CryptoLibAgreement_cptr;

OS_Error_t
CryptoLibServer_Agreement_init(
    CryptoLibAgreement_ptr*  pAgrPtr,
    CryptoLibKey_cptr        prvPtr,
    OS_CryptoAgreement_Alg_t algorithm);

OS_Error_t
CryptoLibServer_Agreement_agree(
    CryptoLibAgreement_ptr agrPtr,
    CryptoLibKey_cptr      pubPtr,
    size_t*                sharedSize);

OS_Error_t
CryptoLibServer_Agreement_free(
    CryptoLibAgreement_ptr agrPtr);

// ------------------------------- Cipher API ----------------------------------

typedef CryptoLibCipher_t* CryptoLibCipher_ptr;
typedef const CryptoLibCipher_t* CryptoLibCipher_cptr;

OS_Error_t
CryptoLibServer_Cipher_init(
    CryptoLibCipher_ptr*  pCipherPtr,
    CryptoLibKey_cptr     keyPtr,
    OS_CryptoCipher_Alg_t algorithm,
    size_t                ivSize);

OS_Error_t
CryptoLibServer_Cipher_free(
    CryptoLibCipher_ptr cipherPtr);

OS_Error_t
CryptoLibServer_Cipher_process(
    CryptoLibCipher_ptr cipherPtr,
    size_t              inputSize,
    size_t*             outputSize);

OS_Error_t
CryptoLibServer_Cipher_start(
    CryptoLibCipher_ptr cipherPtr,
    size_t              len);

OS_Error_t
CryptoLibServer_Cipher_finalize(
    CryptoLibCipher_ptr cipherPtr,
    size_t*             len);