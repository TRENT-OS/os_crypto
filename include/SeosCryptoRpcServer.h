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
#include "SeosCryptoCtx.h"

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoRpcServer
{
    /**
     * crypto context to be used by the RPC object
     */
    SeosCryptoApi_Context* seosCryptoApi;
    /**
     * the server's address of the dataport shared with the client
     */
    void* serverDataport;
};

// Internal functions ----------------------------------------------------------

/**
 * @brief constructor of a seos crypto RPC object
 *
 * @param self (required) pointer to the seos crypto rpc object to be
 *  constructed
 * @param seosCryptoApiCtx the SeosCryptoLib context needed to allocate the
 *  resources
 * @param serverDataport pointer to the dataport connected to the client
 *
 * @return an error code.
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_ABORTED if there is no way to allocate needed resources
 *
 */
seos_err_t
SeosCryptoRpcServer_init(
    SeosCryptoRpcServer* self,
    SeosCryptoLib*       seosCryptoApiCtx,
    void*                serverDataport);
/**
 * @brief constructor of a seos crypto RPC object
 *
 * @param self (required) pointer to the seos crypto rpc object to be
 *  destructed
 *
 */
seos_err_t
SeosCryptoRpcServer_free(
    SeosCryptoRpcServer* self);

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoRpcServer_Rng_getBytes(
    SeosCryptoRpcServer* self,
    unsigned int         flags,
    size_t               dataLen);

seos_err_t
SeosCryptoRpcServer_Rng_reseed(
    SeosCryptoRpcServer* self,
    size_t               seedLen);

// -------------------------------- MAC API ------------------------------------

typedef SeosCryptoLib_Mac* SeosCryptoLib_Mac_Ptr;

seos_err_t
SeosCryptoRpcServer_Mac_init(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Mac_Ptr* pMacPtr,
    SeosCryptoApi_Mac_Alg  algorithm);

seos_err_t
SeosCryptoRpcServer_Mac_free(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Mac_Ptr macPtr);

seos_err_t
SeosCryptoRpcServer_Mac_start(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t                secretSize);

seos_err_t
SeosCryptoRpcServer_Mac_process(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t                dataSize);

seos_err_t
SeosCryptoRpcServer_Mac_finalize(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Mac_Ptr macPtr,
    size_t*               macSize);

// ------------------------------ Digest API -----------------------------------

typedef SeosCryptoLib_Digest* SeosCryptoLib_Digest_Ptr;
typedef const SeosCryptoLib_Digest* SeosCryptoLib_Digest_CPtr;

seos_err_t
SeosCryptoRpcServer_Digest_init(
    SeosCryptoRpcServer*      self,
    SeosCryptoLib_Digest_Ptr* pDigPtr,
    SeosCryptoApi_Digest_Alg  algorithm);

seos_err_t
SeosCryptoRpcServer_Digest_free(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Digest_Ptr digPtr);

seos_err_t
SeosCryptoRpcServer_Digest_clone(
    SeosCryptoRpcServer*      self,
    SeosCryptoLib_Digest_Ptr  dstDigPtr,
    SeosCryptoLib_Digest_CPtr srcDigPtr);

seos_err_t
SeosCryptoRpcServer_Digest_process(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Digest_Ptr digPtr,
    size_t                   inLen);

seos_err_t
SeosCryptoRpcServer_Digest_finalize(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Digest_Ptr digPtr,
    size_t*                  digestSize);

// -------------------------------- Key API ------------------------------------

typedef SeosCryptoLib_Key* SeosCryptoLib_Key_Ptr;
typedef const SeosCryptoLib_Key* SeosCryptoLib_Key_CPtr;

seos_err_t
SeosCryptoRpcServer_Key_generate(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_Ptr* pKeyPtr);

seos_err_t
SeosCryptoRpcServer_Key_makePublic(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_Ptr* pPubKeyPtr,
    SeosCryptoLib_Key_CPtr prvkeyPtr);

seos_err_t
SeosCryptoRpcServer_Key_import(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_Ptr* pPubKeyPtr,
    SeosCryptoLib_Key_CPtr wrapKeyPtr);

seos_err_t
SeosCryptoRpcServer_Key_export(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_CPtr keyPtr,
    SeosCryptoLib_Key_CPtr wrapKeyPtr);

seos_err_t
SeosCryptoRpcServer_Key_getParams(
    SeosCryptoRpcServer*   self,
    SeosCryptoLib_Key_CPtr keyPtr,
    size_t*                paramSize);

seos_err_t
SeosCryptoRpcServer_Key_loadParams(
    SeosCryptoRpcServer*    self,
    SeosCryptoApi_Key_Param name,
    size_t*                 paramSize);

seos_err_t
SeosCryptoRpcServer_Key_free(
    SeosCryptoRpcServer*  self,
    SeosCryptoLib_Key_Ptr keyPtr);

// ----------------------------- Signature API ---------------------------------

typedef SeosCryptoLib_Signature* SeosCryptoLib_Signature_Ptr;

seos_err_t
SeosCryptoRpcServer_Signature_init(
    SeosCryptoRpcServer*         self,
    SeosCryptoLib_Signature_Ptr* pSigPtr,
    SeosCryptoApi_Signature_Alg  algorithm,
    SeosCryptoApi_Digest_Alg     digest,
    SeosCryptoLib_Key_CPtr       prvPtr,
    SeosCryptoLib_Key_CPtr       pubPtr);

seos_err_t
SeosCryptoRpcServer_Signature_verify(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Signature_Ptr sigPtr,
    size_t                      hashSize,
    size_t                      signatureSize);

seos_err_t
SeosCryptoRpcServer_Signature_sign(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Signature_Ptr sigPtr,
    size_t                      hashSize,
    size_t*                     signatureSize);

seos_err_t
SeosCryptoRpcServer_Signature_free(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Signature_Ptr sigPtr);


// ----------------------------- Agreement API ---------------------------------

typedef SeosCryptoLib_Agreement* SeosCryptoLib_Agreement_Ptr;

seos_err_t
SeosCryptoRpcServer_Agreement_init(
    SeosCryptoRpcServer*         self,
    SeosCryptoLib_Agreement_Ptr* pAgrPtr,
    SeosCryptoApi_Agreement_Alg  algorithm,
    SeosCryptoLib_Key_CPtr       prvPtr);

seos_err_t
SeosCryptoRpcServer_Agreement_agree(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Agreement_Ptr agrPtr,
    SeosCryptoLib_Key_CPtr      pubPtr,
    size_t*                     sharedSize);

seos_err_t
SeosCryptoRpcServer_Agreement_free(
    SeosCryptoRpcServer*        self,
    SeosCryptoLib_Agreement_Ptr agrPtr);

// ------------------------------- Cipher API ----------------------------------

typedef SeosCryptoLib_Cipher* SeosCryptoLib_Cipher_Ptr;

seos_err_t
SeosCryptoRpcServer_Cipher_init(
    SeosCryptoRpcServer*      self,
    SeosCryptoLib_Cipher_Ptr* pCipherPtr,
    SeosCryptoApi_Cipher_Alg  algorithm,
    SeosCryptoLib_Key_CPtr    keyPtr,
    size_t                    ivLen);

seos_err_t
SeosCryptoRpcServer_Cipher_free(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Cipher_Ptr cipherPtr);

seos_err_t
SeosCryptoRpcServer_Cipher_process(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t                   inputLen,
    size_t*                  outputSize);

seos_err_t
SeosCryptoRpcServer_Cipher_start(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t                   len);

seos_err_t
SeosCryptoRpcServer_Cipher_finalize(
    SeosCryptoRpcServer*     self,
    SeosCryptoLib_Cipher_Ptr cipherPtr,
    size_t*                  len);

/** @} */