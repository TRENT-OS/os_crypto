/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Server
 * @{
 *
 * @file SeosCryptoRpcServer.h
 *
 * @brief RPC functions to handle the requests of a SEOS crypto client on the
 * server's side
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
} SeosCryptoRpcServer;

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoRpcServer_init(
    SeosCryptoRpcServer*                  self,
    const SeosCryptoApi_Impl*             impl,
    const SeosCryptoApi_RpcServer_Config* cfg);

seos_err_t
SeosCryptoRpcServer_free(
    SeosCryptoRpcServer* self);

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpcServer_Rng_getBytes(
    SeosCryptoApi_Ptr api,
    unsigned int      flags,
    size_t            dataSize);

seos_err_t
SeosCryptoRpcServer_Rng_reseed(
    SeosCryptoApi_Ptr api,
    size_t            seedSize);

// -------------------------------- MAC API ------------------------------------

typedef SeosCryptoLib_Mac* SeosCryptoLib_Mac_Ptr;

seos_err_t
SeosCryptoRpcServer_Mac_init(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Mac_Ptr* pMacPtr,
    SeosCryptoApi_Mac_Alg  algorithm);

seos_err_t
SeosCryptoRpcServer_Mac_free(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macPtr);

seos_err_t
SeosCryptoRpcServer_Mac_start(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t                secretSize);

seos_err_t
SeosCryptoRpcServer_Mac_process(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t                dataSize);

seos_err_t
SeosCryptoRpcServer_Mac_finalize(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t*               macSize);

// ------------------------------ Digest API -----------------------------------

typedef SeosCryptoLib_Digest* SeosCryptoLib_Digest_Ptr;
typedef const SeosCryptoLib_Digest* SeosCryptoLib_Digest_CPtr;

seos_err_t
SeosCryptoRpcServer_Digest_init(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_Ptr* pDigPtr,
    SeosCryptoApi_Digest_Alg  algorithm);

seos_err_t
SeosCryptoRpcServer_Digest_free(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digPtr);

seos_err_t
SeosCryptoRpcServer_Digest_clone(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Digest_Ptr  dstDigPtr,
    SeosCryptoLib_Digest_CPtr srcDigPtr);

seos_err_t
SeosCryptoRpcServer_Digest_process(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digPtr,
    size_t                   inSize);

seos_err_t
SeosCryptoRpcServer_Digest_finalize(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Digest_Ptr digPtr,
    size_t*                  digestSize);

// -------------------------------- Key API ------------------------------------

typedef SeosCryptoLib_Key* SeosCryptoLib_Key_Ptr;
typedef const SeosCryptoLib_Key* SeosCryptoLib_Key_CPtr;

seos_err_t
SeosCryptoRpcServer_Key_generate(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pKeyPtr);

seos_err_t
SeosCryptoRpcServer_Key_makePublic(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pPubKeyPtr,
    SeosCryptoLib_Key_CPtr prvkeyPtr);

seos_err_t
SeosCryptoRpcServer_Key_import(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_Ptr* pPubKeyPtr,
    SeosCryptoLib_Key_CPtr wrapKeyPtr);

seos_err_t
SeosCryptoRpcServer_Key_export(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyPtr,
    SeosCryptoLib_Key_CPtr wrapKeyPtr);

seos_err_t
SeosCryptoRpcServer_Key_getParams(
    SeosCryptoApi_Ptr      api,
    SeosCryptoLib_Key_CPtr keyPtr,
    size_t*                paramSize);

seos_err_t
SeosCryptoRpcServer_Key_loadParams(
    SeosCryptoApi_Ptr       api,
    SeosCryptoApi_Key_Param name,
    size_t*                 paramSize);

seos_err_t
SeosCryptoRpcServer_Key_free(
    SeosCryptoApi_Ptr     api,
    SeosCryptoLib_Key_Ptr keyPtr);

// ----------------------------- Signature API ---------------------------------

typedef SeosCryptoLib_Signature* SeosCryptoLib_Signature_Ptr;

seos_err_t
SeosCryptoRpcServer_Signature_init(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Signature_Ptr* pSigPtr,
    SeosCryptoApi_Signature_Alg  algorithm,
    SeosCryptoApi_Digest_Alg     digest,
    SeosCryptoLib_Key_CPtr       prvPtr,
    SeosCryptoLib_Key_CPtr       pubPtr);

seos_err_t
SeosCryptoRpcServer_Signature_verify(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr sigPtr,
    size_t                      hashSize,
    size_t                      signatureSize);

seos_err_t
SeosCryptoRpcServer_Signature_sign(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr sigPtr,
    size_t                      hashSize,
    size_t*                     signatureSize);

seos_err_t
SeosCryptoRpcServer_Signature_free(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Signature_Ptr sigPtr);

// ----------------------------- Agreement API ---------------------------------

typedef SeosCryptoLib_Agreement* SeosCryptoLib_Agreement_Ptr;

seos_err_t
SeosCryptoRpcServer_Agreement_init(
    SeosCryptoApi_Ptr            api,
    SeosCryptoLib_Agreement_Ptr* pAgrPtr,
    SeosCryptoApi_Agreement_Alg  algorithm,
    SeosCryptoLib_Key_CPtr       prvPtr);

seos_err_t
SeosCryptoRpcServer_Agreement_agree(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Agreement_Ptr agrPtr,
    SeosCryptoLib_Key_CPtr      pubPtr,
    size_t*                     sharedSize);

seos_err_t
SeosCryptoRpcServer_Agreement_free(
    SeosCryptoApi_Ptr           api,
    SeosCryptoLib_Agreement_Ptr agrPtr);

// ------------------------------- Cipher API ----------------------------------

typedef SeosCryptoLib_Cipher* SeosCryptoLib_Cipher_Ptr;

seos_err_t
SeosCryptoRpcServer_Cipher_init(
    SeosCryptoApi_Ptr         api,
    SeosCryptoLib_Cipher_Ptr* pCipherPtr,
    SeosCryptoApi_Cipher_Alg  algorithm,
    SeosCryptoLib_Key_CPtr    keyPtr,
    size_t                    ivSize);

seos_err_t
SeosCryptoRpcServer_Cipher_free(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherPtr);

seos_err_t
SeosCryptoRpcServer_Cipher_process(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t                   inputSize,
    size_t*                  outputSize);

seos_err_t
SeosCryptoRpcServer_Cipher_start(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t                   len);

seos_err_t
SeosCryptoRpcServer_Cipher_finalize(
    SeosCryptoApi_Ptr        api,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t*                  len);

/** @} */