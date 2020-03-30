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

#include "OS_CryptoLib.h"

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

typedef OS_CryptoLibMac_t* OS_CryptoLibMac_ptr;
typedef const OS_CryptoLibMac_t* OS_CryptoLibMac_cptr;

seos_err_t
OS_CryptoRpcServer_Mac_init(
    OS_CryptoLibMac_ptr* pMacPtr,
    OS_CryptoMac_Alg_t   algorithm);

seos_err_t
OS_CryptoRpcServer_Mac_exists(
    OS_CryptoLibMac_cptr macPtr);

seos_err_t
OS_CryptoRpcServer_Mac_free(
    OS_CryptoLibMac_ptr macPtr);

seos_err_t
OS_CryptoRpcServer_Mac_start(
    OS_CryptoLibMac_ptr macPtr,
    size_t              secretSize);

seos_err_t
OS_CryptoRpcServer_Mac_process(
    OS_CryptoLibMac_ptr macPtr,
    size_t              dataSize);

seos_err_t
OS_CryptoRpcServer_Mac_finalize(
    OS_CryptoLibMac_ptr macPtr,
    size_t*             macSize);

// ------------------------------ Digest API -----------------------------------

typedef OS_CryptoLibDigest_t* OS_CryptoLibDigest_ptr;
typedef const OS_CryptoLibDigest_t* OS_CryptoLibDigest_cptr;

seos_err_t
OS_CryptoRpcServer_Digest_init(
    OS_CryptoLibDigest_ptr* pDigPtr,
    OS_CryptoDigest_Alg_t   algorithm);

seos_err_t
OS_CryptoRpcServer_Digest_exists(
    OS_CryptoLibDigest_cptr digestPtr);

seos_err_t
OS_CryptoRpcServer_Digest_free(
    OS_CryptoLibDigest_ptr digPtr);

seos_err_t
OS_CryptoRpcServer_Digest_clone(
    OS_CryptoLibDigest_ptr  dstDigPtr,
    OS_CryptoLibDigest_cptr srcDigPtr);

seos_err_t
OS_CryptoRpcServer_Digest_process(
    OS_CryptoLibDigest_ptr digPtr,
    size_t                 inSize);

seos_err_t
OS_CryptoRpcServer_Digest_finalize(
    OS_CryptoLibDigest_ptr digPtr,
    size_t*                digestSize);

// -------------------------------- Key API ------------------------------------

typedef OS_CryptoLibKey_t* OS_CryptoLibKey_ptr;
typedef const OS_CryptoLibKey_t* OS_CryptoLibKey_cptr;

seos_err_t
OS_CryptoRpcServer_Key_generate(
    OS_CryptoLibKey_ptr* pKeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_makePublic(
    OS_CryptoLibKey_ptr* pPubKeyPtr,
    OS_CryptoLibKey_cptr prvkeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_import(
    OS_CryptoLibKey_ptr* pPubKeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_export(
    OS_CryptoLibKey_cptr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_getParams(
    OS_CryptoLibKey_cptr keyPtr,
    size_t*              paramSize);

seos_err_t
OS_CryptoRpcServer_Key_getAttribs(
    OS_CryptoLibKey_cptr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_loadParams(
    OS_CryptoKey_Param_t name,
    size_t*              paramSize);

seos_err_t
OS_CryptoRpcServer_Key_exists(
    OS_CryptoLibKey_cptr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_free(
    OS_CryptoLibKey_ptr keyPtr);

// ----------------------------- Signature API ---------------------------------

typedef OS_CryptoLibSignature_t* OS_CryptoLibSignature_ptr;
typedef const OS_CryptoLibSignature_t* OS_CryptoLibSignature_cptr;

seos_err_t
OS_CryptoRpcServer_Signature_init(
    OS_CryptoLibSignature_ptr* pSigPtr,
    OS_CryptoSignature_Alg_t   algorithm,
    OS_CryptoDigest_Alg_t      digest,
    OS_CryptoLibKey_cptr       prvPtr,
    OS_CryptoLibKey_cptr       pubPtr);

seos_err_t
OS_CryptoRpcServer_Signature_verify(
    OS_CryptoLibSignature_ptr sigPtr,
    size_t                    hashSize,
    size_t                    signatureSize);

seos_err_t
OS_CryptoRpcServer_Signature_sign(
    OS_CryptoLibSignature_ptr sigPtr,
    size_t                    hashSize,
    size_t*                   signatureSize);

seos_err_t
OS_CryptoRpcServer_Signature_exists(
    OS_CryptoLibSignature_cptr obj);

seos_err_t
OS_CryptoRpcServer_Signature_free(
    OS_CryptoLibSignature_ptr sigPtr);

// ----------------------------- Agreement API ---------------------------------

typedef OS_CryptoLibAgreement_t* OS_CryptoLibAgreement_ptr;
typedef const OS_CryptoLibAgreement_t* OS_CryptoLibAgreement_cptr;

seos_err_t
OS_CryptoRpcServer_Agreement_init(
    OS_CryptoLibAgreement_ptr* pAgrPtr,
    OS_CryptoAgreement_Alg_t   algorithm,
    OS_CryptoLibKey_cptr       prvPtr);

seos_err_t
OS_CryptoRpcServer_Agreement_agree(
    OS_CryptoLibAgreement_ptr agrPtr,
    OS_CryptoLibKey_cptr      pubPtr,
    size_t*                   sharedSize);

seos_err_t
OS_CryptoRpcServer_Agreement_exists(
    OS_CryptoLibAgreement_cptr agrPtr);

seos_err_t
OS_CryptoRpcServer_Agreement_free(
    OS_CryptoLibAgreement_ptr agrPtr);

// ------------------------------- Cipher API ----------------------------------

typedef OS_CryptoLibCipher_t* OS_CryptoLibCipher_ptr;
typedef const OS_CryptoLibCipher_t* OS_CryptoLibCipher_cptr;

seos_err_t
OS_CryptoRpcServer_Cipher_init(
    OS_CryptoLibCipher_ptr* pCipherPtr,
    OS_CryptoCipher_Alg_t   algorithm,
    OS_CryptoLibKey_cptr    keyPtr,
    size_t                  ivSize);

seos_err_t
OS_CryptoRpcServer_Cipher_exists(
    OS_CryptoLibCipher_cptr cipherPtr);

seos_err_t
OS_CryptoRpcServer_Cipher_free(
    OS_CryptoLibCipher_ptr cipherPtr);

seos_err_t
OS_CryptoRpcServer_Cipher_process(
    OS_CryptoLibCipher_ptr cipherPtr,
    size_t                 inputSize,
    size_t*                outputSize);

seos_err_t
OS_CryptoRpcServer_Cipher_start(
    OS_CryptoLibCipher_ptr cipherPtr,
    size_t                 len);

seos_err_t
OS_CryptoRpcServer_Cipher_finalize(
    OS_CryptoLibCipher_ptr cipherPtr,
    size_t*                len);

/** @} */