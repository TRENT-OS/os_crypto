/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file SeosCryptoRpc_Server.h
 *
 * @brief RPC server object and functions to provide a SEOS Crypto API RPC server
 * which can be used from a RPC client instance. Calls to this object are mapped
 * to an implementation (e.g., a crypto library).
 *
 */

#pragma once

#include "SeosCryptoApi.h"

// Internal types/defines/enums ------------------------------------------------

typedef struct
{
    /**
     * The server's address of the dataport shared with the client
     */
    void* dataPort;
    /**
     * Function table implementing crypto functionality
     */
    const SeosCryptoVtable* vtable;
    void* context;
} SeosCryptoRpc_Server;

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoRpc_Server_init(
    SeosCryptoRpc_Server*                 self,
    const SeosCryptoApi_Impl*             impl,
    const SeosCryptoApi_RpcServer_Config* cfg);

seos_err_t
SeosCryptoRpc_Server_free(
    SeosCryptoRpc_Server* self);

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpc_Server_Rng_getBytes(
    unsigned int flags,
    size_t       dataSize);

seos_err_t
SeosCryptoRpc_Server_Rng_reseed(
    size_t seedSize);

// -------------------------------- MAC API ------------------------------------

typedef SeosCryptoLib_Mac* SeosCryptoLib_Mac_Ptr;
typedef const SeosCryptoLib_Mac* SeosCryptoLib_Mac_CPtr;

seos_err_t
SeosCryptoRpc_Server_Mac_init(
    SeosCryptoLib_Mac_Ptr* pMacPtr,
    SeosCryptoApi_Mac_Alg  algorithm);

seos_err_t
SeosCryptoRpc_Server_Mac_exists(
    SeosCryptoLib_Mac_CPtr macPtr);

seos_err_t
SeosCryptoRpc_Server_Mac_free(
    SeosCryptoLib_Mac_Ptr macPtr);

seos_err_t
SeosCryptoRpc_Server_Mac_start(
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t                secretSize);

seos_err_t
SeosCryptoRpc_Server_Mac_process(
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t                dataSize);

seos_err_t
SeosCryptoRpc_Server_Mac_finalize(
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t*               macSize);

// ------------------------------ Digest API -----------------------------------

typedef SeosCryptoLib_Digest* SeosCryptoLib_Digest_Ptr;
typedef const SeosCryptoLib_Digest* SeosCryptoLib_Digest_CPtr;

seos_err_t
SeosCryptoRpc_Server_Digest_init(
    SeosCryptoLib_Digest_Ptr* pDigPtr,
    SeosCryptoApi_Digest_Alg  algorithm);

seos_err_t
SeosCryptoRpc_Server_Digest_exists(
    SeosCryptoLib_Digest_CPtr digestPtr);

seos_err_t
SeosCryptoRpc_Server_Digest_free(
    SeosCryptoLib_Digest_Ptr digPtr);

seos_err_t
SeosCryptoRpc_Server_Digest_clone(
    SeosCryptoLib_Digest_Ptr  dstDigPtr,
    SeosCryptoLib_Digest_CPtr srcDigPtr);

seos_err_t
SeosCryptoRpc_Server_Digest_process(
    SeosCryptoLib_Digest_Ptr digPtr,
    size_t                   inSize);

seos_err_t
SeosCryptoRpc_Server_Digest_finalize(
    SeosCryptoLib_Digest_Ptr digPtr,
    size_t*                  digestSize);

// -------------------------------- Key API ------------------------------------

typedef SeosCryptoLib_Key* SeosCryptoLib_Key_Ptr;
typedef const SeosCryptoLib_Key* SeosCryptoLib_Key_CPtr;

seos_err_t
SeosCryptoRpc_Server_Key_generate(
    SeosCryptoLib_Key_Ptr* pKeyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_makePublic(
    SeosCryptoLib_Key_Ptr* pPubKeyPtr,
    SeosCryptoLib_Key_CPtr prvkeyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_import(
    SeosCryptoLib_Key_Ptr* pPubKeyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_export(
    SeosCryptoLib_Key_CPtr keyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_getParams(
    SeosCryptoLib_Key_CPtr keyPtr,
    size_t*                paramSize);

seos_err_t
SeosCryptoRpc_Server_Key_getAttribs(
    SeosCryptoLib_Key_CPtr keyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_loadParams(
    SeosCryptoApi_Key_Param name,
    size_t*                 paramSize);

seos_err_t
SeosCryptoRpc_Server_Key_exists(
    SeosCryptoLib_Key_CPtr keyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_free(
    SeosCryptoLib_Key_Ptr keyPtr);

// ----------------------------- Signature API ---------------------------------

typedef SeosCryptoLib_Signature* SeosCryptoLib_Signature_Ptr;
typedef const SeosCryptoLib_Signature* SeosCryptoLib_Signature_CPtr;

seos_err_t
SeosCryptoRpc_Server_Signature_init(
    SeosCryptoLib_Signature_Ptr* pSigPtr,
    SeosCryptoApi_Signature_Alg  algorithm,
    SeosCryptoApi_Digest_Alg     digest,
    SeosCryptoLib_Key_CPtr       prvPtr,
    SeosCryptoLib_Key_CPtr       pubPtr);

seos_err_t
SeosCryptoRpc_Server_Signature_verify(
    SeosCryptoLib_Signature_Ptr sigPtr,
    size_t                      hashSize,
    size_t                      signatureSize);

seos_err_t
SeosCryptoRpc_Server_Signature_sign(
    SeosCryptoLib_Signature_Ptr sigPtr,
    size_t                      hashSize,
    size_t*                     signatureSize);

seos_err_t
SeosCryptoRpc_Server_Signature_exists(
    SeosCryptoLib_Signature_CPtr obj);

seos_err_t
SeosCryptoRpc_Server_Signature_free(
    SeosCryptoLib_Signature_Ptr sigPtr);

// ----------------------------- Agreement API ---------------------------------

typedef SeosCryptoLib_Agreement* SeosCryptoLib_Agreement_Ptr;
typedef const SeosCryptoLib_Agreement* SeosCryptoLib_Agreement_CPtr;

seos_err_t
SeosCryptoRpc_Server_Agreement_init(
    SeosCryptoLib_Agreement_Ptr* pAgrPtr,
    SeosCryptoApi_Agreement_Alg  algorithm,
    SeosCryptoLib_Key_CPtr       prvPtr);

seos_err_t
SeosCryptoRpc_Server_Agreement_agree(
    SeosCryptoLib_Agreement_Ptr agrPtr,
    SeosCryptoLib_Key_CPtr      pubPtr,
    size_t*                     sharedSize);

seos_err_t
SeosCryptoRpc_Server_Agreement_exists(
    SeosCryptoLib_Agreement_CPtr agrPtr);

seos_err_t
SeosCryptoRpc_Server_Agreement_free(
    SeosCryptoLib_Agreement_Ptr agrPtr);

// ------------------------------- Cipher API ----------------------------------

typedef SeosCryptoLib_Cipher* SeosCryptoLib_Cipher_Ptr;
typedef const SeosCryptoLib_Cipher* SeosCryptoLib_Cipher_CPtr;

seos_err_t
SeosCryptoRpc_Server_Cipher_init(
    SeosCryptoLib_Cipher_Ptr* pCipherPtr,
    SeosCryptoApi_Cipher_Alg  algorithm,
    SeosCryptoLib_Key_CPtr    keyPtr,
    size_t                    ivSize);

seos_err_t
SeosCryptoRpc_Server_Cipher_exists(
    SeosCryptoLib_Cipher_CPtr cipherPtr);

seos_err_t
SeosCryptoRpc_Server_Cipher_free(
    SeosCryptoLib_Cipher_Ptr cipherPtr);

seos_err_t
SeosCryptoRpc_Server_Cipher_process(
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t                   inputSize,
    size_t*                  outputSize);

seos_err_t
SeosCryptoRpc_Server_Cipher_start(
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t                   len);

seos_err_t
SeosCryptoRpc_Server_Cipher_finalize(
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t*                  len);

/** @} */