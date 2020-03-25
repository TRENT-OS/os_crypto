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

typedef struct OS_CryptoRpcServer OS_CryptoRpcServer;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
OS_CryptoRpcServer_init(
    OS_CryptoRpcServer**             ctx,
    const OS_CryptoImpl*             client,
    const OS_Crypto_Memory*          memIf,
    const OS_CryptoRpcServer_Config* cfg);

seos_err_t
OS_CryptoRpcServer_free(
    OS_CryptoRpcServer* self);

// -------------------------------- RNG API ------------------------------------

seos_err_t
OS_CryptoRpcServer_Rng_getBytes(
    unsigned int flags,
    size_t       dataSize);

seos_err_t
OS_CryptoRpcServer_Rng_reseed(
    size_t seedSize);

// -------------------------------- MAC API ------------------------------------

typedef OS_CryptoLibMac* OS_CryptoLibMac_Ptr;
typedef const OS_CryptoLibMac* OS_CryptoLibMac_CPtr;

seos_err_t
OS_CryptoRpcServer_Mac_init(
    OS_CryptoLibMac_Ptr* pMacPtr,
    OS_CryptoMac_Alg     algorithm);

seos_err_t
OS_CryptoRpcServer_Mac_exists(
    OS_CryptoLibMac_CPtr macPtr);

seos_err_t
OS_CryptoRpcServer_Mac_free(
    OS_CryptoLibMac_Ptr macPtr);

seos_err_t
OS_CryptoRpcServer_Mac_start(
    OS_CryptoLibMac_Ptr macPtr,
    size_t              secretSize);

seos_err_t
OS_CryptoRpcServer_Mac_process(
    OS_CryptoLibMac_Ptr macPtr,
    size_t              dataSize);

seos_err_t
OS_CryptoRpcServer_Mac_finalize(
    OS_CryptoLibMac_Ptr macPtr,
    size_t*             macSize);

// ------------------------------ Digest API -----------------------------------

typedef OS_CryptoLibDigest* OS_CryptoLibDigest_Ptr;
typedef const OS_CryptoLibDigest* OS_CryptoLibDigest_CPtr;

seos_err_t
OS_CryptoRpcServer_Digest_init(
    OS_CryptoLibDigest_Ptr* pDigPtr,
    OS_CryptoDigest_Alg     algorithm);

seos_err_t
OS_CryptoRpcServer_Digest_exists(
    OS_CryptoLibDigest_CPtr digestPtr);

seos_err_t
OS_CryptoRpcServer_Digest_free(
    OS_CryptoLibDigest_Ptr digPtr);

seos_err_t
OS_CryptoRpcServer_Digest_clone(
    OS_CryptoLibDigest_Ptr  dstDigPtr,
    OS_CryptoLibDigest_CPtr srcDigPtr);

seos_err_t
OS_CryptoRpcServer_Digest_process(
    OS_CryptoLibDigest_Ptr digPtr,
    size_t                 inSize);

seos_err_t
OS_CryptoRpcServer_Digest_finalize(
    OS_CryptoLibDigest_Ptr digPtr,
    size_t*                digestSize);

// -------------------------------- Key API ------------------------------------

typedef OS_CryptoLibKey* OS_CryptoLibKey_Ptr;
typedef const OS_CryptoLibKey* OS_CryptoLibKey_CPtr;

seos_err_t
OS_CryptoRpcServer_Key_generate(
    OS_CryptoLibKey_Ptr* pKeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_makePublic(
    OS_CryptoLibKey_Ptr* pPubKeyPtr,
    OS_CryptoLibKey_CPtr prvkeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_import(
    OS_CryptoLibKey_Ptr* pPubKeyPtr);

seos_err_t
OS_CryptoRpcServer_Key_export(
    OS_CryptoLibKey_CPtr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_getParams(
    OS_CryptoLibKey_CPtr keyPtr,
    size_t*              paramSize);

seos_err_t
OS_CryptoRpcServer_Key_getAttribs(
    OS_CryptoLibKey_CPtr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_loadParams(
    OS_CryptoKey_Param name,
    size_t*            paramSize);

seos_err_t
OS_CryptoRpcServer_Key_exists(
    OS_CryptoLibKey_CPtr keyPtr);

seos_err_t
OS_CryptoRpcServer_Key_free(
    OS_CryptoLibKey_Ptr keyPtr);

// ----------------------------- Signature API ---------------------------------

typedef OS_CryptoLibSignature* OS_CryptoLibSignature_Ptr;
typedef const OS_CryptoLibSignature* OS_CryptoLibSignature_CPtr;

seos_err_t
OS_CryptoRpcServer_Signature_init(
    OS_CryptoLibSignature_Ptr* pSigPtr,
    OS_CryptoSignature_Alg     algorithm,
    OS_CryptoDigest_Alg        digest,
    OS_CryptoLibKey_CPtr       prvPtr,
    OS_CryptoLibKey_CPtr       pubPtr);

seos_err_t
OS_CryptoRpcServer_Signature_verify(
    OS_CryptoLibSignature_Ptr sigPtr,
    size_t                    hashSize,
    size_t                    signatureSize);

seos_err_t
OS_CryptoRpcServer_Signature_sign(
    OS_CryptoLibSignature_Ptr sigPtr,
    size_t                    hashSize,
    size_t*                   signatureSize);

seos_err_t
OS_CryptoRpcServer_Signature_exists(
    OS_CryptoLibSignature_CPtr obj);

seos_err_t
OS_CryptoRpcServer_Signature_free(
    OS_CryptoLibSignature_Ptr sigPtr);

// ----------------------------- Agreement API ---------------------------------

typedef OS_CryptoLibAgreement* OS_CryptoLibAgreement_Ptr;
typedef const OS_CryptoLibAgreement* OS_CryptoLibAgreement_CPtr;

seos_err_t
OS_CryptoRpcServer_Agreement_init(
    OS_CryptoLibAgreement_Ptr* pAgrPtr,
    OS_CryptoAgreement_Alg     algorithm,
    OS_CryptoLibKey_CPtr       prvPtr);

seos_err_t
OS_CryptoRpcServer_Agreement_agree(
    OS_CryptoLibAgreement_Ptr agrPtr,
    OS_CryptoLibKey_CPtr      pubPtr,
    size_t*                   sharedSize);

seos_err_t
OS_CryptoRpcServer_Agreement_exists(
    OS_CryptoLibAgreement_CPtr agrPtr);

seos_err_t
OS_CryptoRpcServer_Agreement_free(
    OS_CryptoLibAgreement_Ptr agrPtr);

// ------------------------------- Cipher API ----------------------------------

typedef OS_CryptoLibCipher* OS_CryptoLibCipher_Ptr;
typedef const OS_CryptoLibCipher* OS_CryptoLibCipher_CPtr;

seos_err_t
OS_CryptoRpcServer_Cipher_init(
    OS_CryptoLibCipher_Ptr* pCipherPtr,
    OS_CryptoCipher_Alg     algorithm,
    OS_CryptoLibKey_CPtr    keyPtr,
    size_t                  ivSize);

seos_err_t
OS_CryptoRpcServer_Cipher_exists(
    OS_CryptoLibCipher_CPtr cipherPtr);

seos_err_t
OS_CryptoRpcServer_Cipher_free(
    OS_CryptoLibCipher_Ptr cipherPtr);

seos_err_t
OS_CryptoRpcServer_Cipher_process(
    OS_CryptoLibCipher_Ptr cipherPtr,
    size_t                 inputSize,
    size_t*                outputSize);

seos_err_t
OS_CryptoRpcServer_Cipher_start(
    OS_CryptoLibCipher_Ptr cipherPtr,
    size_t                 len);

seos_err_t
OS_CryptoRpcServer_Cipher_finalize(
    OS_CryptoLibCipher_Ptr cipherPtr,
    size_t*                len);

/** @} */