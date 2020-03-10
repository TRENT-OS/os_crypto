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
    SeosCryptoApi_Ptr api,
    unsigned int      flags,
    size_t            dataSize);

seos_err_t
SeosCryptoRpc_Server_Rng_reseed(
    SeosCryptoApi_Ptr api,
    size_t            seedSize);

// -------------------------------- MAC API ------------------------------------

typedef SeosCryptoLib_Mac* SeosCryptoLib_Mac_Ptr;
typedef const SeosCryptoLib_Mac* SeosCryptoLib_Mac_CPtr;

seos_err_t
SeosCryptoRpc_Server_Mac_init(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Mac_Ptr* pMacPtr,
    SeosCryptoApi_Mac_Alg  algorithm);

seos_err_t
SeosCryptoRpc_Server_Mac_exists(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Mac_CPtr macPtr);

seos_err_t
SeosCryptoRpc_Server_Mac_free(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macPtr);

seos_err_t
SeosCryptoRpc_Server_Mac_start(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t                secretSize);

seos_err_t
SeosCryptoRpc_Server_Mac_process(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t                dataSize);

seos_err_t
SeosCryptoRpc_Server_Mac_finalize(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t*               macSize);

// ------------------------------ Digest API -----------------------------------

typedef SeosCryptoLib_Digest* SeosCryptoLib_Digest_Ptr;
typedef const SeosCryptoLib_Digest* SeosCryptoLib_Digest_CPtr;

seos_err_t
SeosCryptoRpc_Server_Digest_init(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_Ptr* pDigPtr,
    SeosCryptoApi_Digest_Alg  algorithm);

seos_err_t
SeosCryptoRpc_Server_Digest_exists(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_CPtr digestPtr);

seos_err_t
SeosCryptoRpc_Server_Digest_free(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digPtr);

seos_err_t
SeosCryptoRpc_Server_Digest_clone(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_Ptr  dstDigPtr,
    SeosCryptoLib_Digest_CPtr srcDigPtr);

seos_err_t
SeosCryptoRpc_Server_Digest_process(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digPtr,
    size_t                   inSize);

seos_err_t
SeosCryptoRpc_Server_Digest_finalize(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digPtr,
    size_t*                  digestSize);

// -------------------------------- Key API ------------------------------------

typedef SeosCryptoLib_Key* SeosCryptoLib_Key_Ptr;
typedef const SeosCryptoLib_Key* SeosCryptoLib_Key_CPtr;

seos_err_t
SeosCryptoRpc_Server_Key_generate(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pKeyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_makePublic(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pPubKeyPtr,
    SeosCryptoLib_Key_CPtr prvkeyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_import(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pPubKeyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_export(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_getParams(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyPtr,
    size_t*                paramSize);

seos_err_t
SeosCryptoRpc_Server_Key_getAttribs(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_loadParams(
    SeosCryptoApi_Ptr       api,
    SeosCryptoApi_Key_Param name,
    size_t*                 paramSize);

seos_err_t
SeosCryptoRpc_Server_Key_exists(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyPtr);

seos_err_t
SeosCryptoRpc_Server_Key_free(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Key_Ptr keyPtr);

// ----------------------------- Signature API ---------------------------------

typedef SeosCryptoLib_Signature* SeosCryptoLib_Signature_Ptr;
typedef const SeosCryptoLib_Signature* SeosCryptoLib_Signature_CPtr;

seos_err_t
SeosCryptoRpc_Server_Signature_init(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Signature_Ptr* pSigPtr,
    SeosCryptoApi_Signature_Alg  algorithm,
    SeosCryptoApi_Digest_Alg     digest,
    SeosCryptoLib_Key_CPtr       prvPtr,
    SeosCryptoLib_Key_CPtr       pubPtr);

seos_err_t
SeosCryptoRpc_Server_Signature_verify(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr sigPtr,
    size_t                      hashSize,
    size_t                      signatureSize);

seos_err_t
SeosCryptoRpc_Server_Signature_sign(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr sigPtr,
    size_t                      hashSize,
    size_t*                     signatureSize);

seos_err_t
SeosCryptoRpc_Server_Signature_exists(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Signature_CPtr obj);

seos_err_t
SeosCryptoRpc_Server_Signature_free(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr sigPtr);

// ----------------------------- Agreement API ---------------------------------

typedef SeosCryptoLib_Agreement* SeosCryptoLib_Agreement_Ptr;
typedef const SeosCryptoLib_Agreement* SeosCryptoLib_Agreement_CPtr;

seos_err_t
SeosCryptoRpc_Server_Agreement_init(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Agreement_Ptr* pAgrPtr,
    SeosCryptoApi_Agreement_Alg  algorithm,
    SeosCryptoLib_Key_CPtr       prvPtr);

seos_err_t
SeosCryptoRpc_Server_Agreement_agree(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Agreement_Ptr agrPtr,
    SeosCryptoLib_Key_CPtr      pubPtr,
    size_t*                     sharedSize);

seos_err_t
SeosCryptoRpc_Server_Agreement_exists(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Agreement_CPtr agrPtr);

seos_err_t
SeosCryptoRpc_Server_Agreement_free(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Agreement_Ptr agrPtr);

// ------------------------------- Cipher API ----------------------------------

typedef SeosCryptoLib_Cipher* SeosCryptoLib_Cipher_Ptr;
typedef const SeosCryptoLib_Cipher* SeosCryptoLib_Cipher_CPtr;

seos_err_t
SeosCryptoRpc_Server_Cipher_init(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Cipher_Ptr* pCipherPtr,
    SeosCryptoApi_Cipher_Alg  algorithm,
    SeosCryptoLib_Key_CPtr    keyPtr,
    size_t                    ivSize);

seos_err_t
SeosCryptoRpc_Server_Cipher_exists(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Cipher_CPtr cipherPtr);

seos_err_t
SeosCryptoRpc_Server_Cipher_free(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherPtr);

seos_err_t
SeosCryptoRpc_Server_Cipher_process(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t                   inputSize,
    size_t*                  outputSize);

seos_err_t
SeosCryptoRpc_Server_Cipher_start(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t                   len);

seos_err_t
SeosCryptoRpc_Server_Cipher_finalize(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t*                  len);

/** @} */