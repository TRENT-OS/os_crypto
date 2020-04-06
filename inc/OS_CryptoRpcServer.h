/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file OS_CryptoRpcServer.h
 *
 * @brief RPC server object and functions to provide a SEOS Crypto API RPC server
 * which can be used from a RPC client instance. Calls to this object are mapped
 * to an implementation (e.g., a crypto library).
 *
 */

#pragma once

#include "lib/CryptoLib.h"

// -------------------------- defines/types/variables --------------------------

typedef struct OS_CryptoRpcServer OS_CryptoRpcServer_t;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
OS_CryptoRpcServer_init(
    OS_CryptoRpcServer_t**             ctx,
    const OS_CryptoImpl_t*             client,
    const OS_Crypto_Memory_t*          memIf,
    const OS_CryptoRpcServer_Config_t* cfg);

seos_err_t
OS_CryptoRpcServer_free(
    OS_CryptoRpcServer_t* self);

// -------------------------------- RNG API ------------------------------------

seos_err_t
OS_CryptoRpcServer_Rng_getBytes(
    unsigned int flags,
    size_t       dataSize);

seos_err_t
OS_CryptoRpcServer_Rng_reseed(
    size_t seedSize);

// -------------------------------- MAC API ------------------------------------

typedef CryptoLibMac_t* CryptoLibMac_ptr;
typedef const CryptoLibMac_t* CryptoLibMac_cptr;

seos_err_t
OS_CryptoRpcServer_Mac_init(
    CryptoLibMac_ptr*  pMacPtr,
    OS_CryptoMac_Alg_t algorithm);

seos_err_t
OS_CryptoRpcServer_Mac_exists(
    CryptoLibMac_cptr macPtr);

seos_err_t
OS_CryptoRpcServer_Mac_free(
    CryptoLibMac_ptr macPtr);

seos_err_t
OS_CryptoRpcServer_Mac_start(
    CryptoLibMac_ptr macPtr,
    size_t           secretSize);

seos_err_t
OS_CryptoRpcServer_Mac_process(
    CryptoLibMac_ptr macPtr,
    size_t           dataSize);

seos_err_t
OS_CryptoRpcServer_Mac_finalize(
    CryptoLibMac_ptr macPtr,
    size_t*          macSize);

// ------------------------------ Digest API -----------------------------------

typedef CryptoLibDigest_t* CryptoLibDigest_ptr;
typedef const CryptoLibDigest_t* CryptoLibDigest_cptr;

seos_err_t
OS_CryptoRpcServer_Digest_init(
    CryptoLibDigest_ptr*  pDigPtr,
    OS_CryptoDigest_Alg_t algorithm);

seos_err_t
OS_CryptoRpcServer_Digest_exists(
    CryptoLibDigest_cptr digestPtr);

seos_err_t
OS_CryptoRpcServer_Digest_free(
    CryptoLibDigest_ptr digPtr);

seos_err_t
OS_CryptoRpcServer_Digest_clone(
    CryptoLibDigest_ptr  dstDigPtr,
    CryptoLibDigest_cptr srcDigPtr);

seos_err_t
OS_CryptoRpcServer_Digest_process(
    CryptoLibDigest_ptr digPtr,
    size_t              inSize);

seos_err_t
OS_CryptoRpcServer_Digest_finalize(
    CryptoLibDigest_ptr digPtr,
    size_t*             digestSize);

// -------------------------------- Key API ------------------------------------

typedef CryptoLibKey_t* CryptoLibKey_ptr;
typedef const CryptoLibKey_t* CryptoLibKey_cptr;

seos_err_t
OS_CryptoRpcServer_Key_generate(
    CryptoLibKey_ptr* pKeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_makePublic(
    CryptoLibKey_ptr* pPubKeyPtr,
    CryptoLibKey_cptr prvkeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_import(
    CryptoLibKey_ptr* pPubKeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_export(
    CryptoLibKey_cptr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_getParams(
    CryptoLibKey_cptr keyPtr,
    size_t*           paramSize);

seos_err_t
OS_CryptoRpcServer_Key_getAttribs(
    CryptoLibKey_cptr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_loadParams(
    OS_CryptoKey_Param_t name,
    size_t*              paramSize);

seos_err_t
OS_CryptoRpcServer_Key_exists(
    CryptoLibKey_cptr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_free(
    CryptoLibKey_ptr keyPtr);

// ----------------------------- Signature API ---------------------------------

typedef CryptoLibSignature_t* CryptoLibSignature_ptr;
typedef const CryptoLibSignature_t* CryptoLibSignature_cptr;

seos_err_t
OS_CryptoRpcServer_Signature_init(
    CryptoLibSignature_ptr*  pSigPtr,
    OS_CryptoSignature_Alg_t algorithm,
    OS_CryptoDigest_Alg_t    digest,
    CryptoLibKey_cptr        prvPtr,
    CryptoLibKey_cptr        pubPtr);

seos_err_t
OS_CryptoRpcServer_Signature_verify(
    CryptoLibSignature_ptr sigPtr,
    size_t                 hashSize,
    size_t                 signatureSize);

seos_err_t
OS_CryptoRpcServer_Signature_sign(
    CryptoLibSignature_ptr sigPtr,
    size_t                 hashSize,
    size_t*                signatureSize);

seos_err_t
OS_CryptoRpcServer_Signature_exists(
    CryptoLibSignature_cptr obj);

seos_err_t
OS_CryptoRpcServer_Signature_free(
    CryptoLibSignature_ptr sigPtr);

// ----------------------------- Agreement API ---------------------------------

typedef CryptoLibAgreement_t* CryptoLibAgreement_ptr;
typedef const CryptoLibAgreement_t* CryptoLibAgreement_cptr;

seos_err_t
OS_CryptoRpcServer_Agreement_init(
    CryptoLibAgreement_ptr*  pAgrPtr,
    OS_CryptoAgreement_Alg_t algorithm,
    CryptoLibKey_cptr        prvPtr);

seos_err_t
OS_CryptoRpcServer_Agreement_agree(
    CryptoLibAgreement_ptr agrPtr,
    CryptoLibKey_cptr      pubPtr,
    size_t*                sharedSize);

seos_err_t
OS_CryptoRpcServer_Agreement_exists(
    CryptoLibAgreement_cptr agrPtr);

seos_err_t
OS_CryptoRpcServer_Agreement_free(
    CryptoLibAgreement_ptr agrPtr);

// ------------------------------- Cipher API ----------------------------------

typedef CryptoLibCipher_t* CryptoLibCipher_ptr;
typedef const CryptoLibCipher_t* CryptoLibCipher_cptr;

seos_err_t
OS_CryptoRpcServer_Cipher_init(
    CryptoLibCipher_ptr*  pCipherPtr,
    OS_CryptoCipher_Alg_t algorithm,
    CryptoLibKey_cptr     keyPtr,
    size_t                ivSize);

seos_err_t
OS_CryptoRpcServer_Cipher_exists(
    CryptoLibCipher_cptr cipherPtr);

seos_err_t
OS_CryptoRpcServer_Cipher_free(
    CryptoLibCipher_ptr cipherPtr);

seos_err_t
OS_CryptoRpcServer_Cipher_process(
    CryptoLibCipher_ptr cipherPtr,
    size_t              inputSize,
    size_t*             outputSize);

seos_err_t
OS_CryptoRpcServer_Cipher_start(
    CryptoLibCipher_ptr cipherPtr,
    size_t              len);

seos_err_t
OS_CryptoRpcServer_Cipher_finalize(
    CryptoLibCipher_ptr cipherPtr,
    size_t*             len);

/** @} */