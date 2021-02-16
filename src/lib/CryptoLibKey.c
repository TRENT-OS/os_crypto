/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibKey.h"

#include "lib_debug/Debug.h"

#include "lib_macros/Check.h"

#include <string.h>
#include <stddef.h>
#include <stdint.h>

// Internal types/defines/enums ------------------------------------------------

// How often do we want to retry finding a suitable prime P and also a suitable
// X with 2 <= X <= P-2? For generate_DHPrv, the worst case scenario is a 1/2
// probability of X not being in the range at each try. 100 retries should be
// enough.
#define CryptoLibKey_DH_GEN_RETRIES    100
// Default values for RSA/DH
#define CryptoLibKey_DH_GENERATOR      2       ///< Generator for DH
#define CryptoLibKey_RSA_EXPONENT      65537   ///< Public exp. 2^16+1

struct CryptoLibKey
{
    OS_CryptoKey_Type_t type;
    OS_CryptoKey_Attrib_t attribs;
    void* data;
    uint32_t size;
};

// Private static functions ----------------------------------------------------

// This implementation should never be optimized out by the compiler
static void* (*const volatile memset_func)( void*, int, size_t ) = memset;
static void
zeroizeMemory(
    void*  buf,
    size_t len)
{
    if ( len > 0 )
    {
        memset_func( buf, 0, len );
    }
}

// Get topmost bit, i.e., to determine the bitsize of a prime
static size_t
getMpiLen(
    const unsigned char* xVal,
    const size_t         xLen)
{
    mbedtls_mpi x;
    size_t n;

    mbedtls_mpi_init(&x);
    mbedtls_mpi_read_binary(&x, xVal, xLen);
    n = mbedtls_mpi_bitlen(&x);
    mbedtls_mpi_free(&x);

    return n;
}

// -------------------------------- DH Keys ------------------------------------

static OS_Error_t
generate_DHParams(
    const size_t             bits,
    OS_CryptoKey_DhParams_t* params,
    CryptoLibRng_t*          rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    mbedtls_mpi P, G;
    size_t retries;

    mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&P);

    // Generator is fixed
    mbedtls_mpi_lset(&G, CryptoLibKey_DH_GENERATOR);

    // Generate a "safe prime" P such that Q=(P-1)/2 is also prime. Then make
    // sure that for this prime P our generator generates the full group and
    // not just a sub-group. We only need to check P mod 8 is either 1 or 7
    for (retries = CryptoLibKey_DH_GEN_RETRIES; retries > 0; retries--)
    {
        if (!mbedtls_mpi_gen_prime(&P, bits, MBEDTLS_MPI_GEN_PRIME_FLAG_DH,
                                   CryptoLibRng_getBytesMbedtls, rng))
        {
            mbedtls_mpi_uint mod;
            mbedtls_mpi_mod_int(&mod, &P, 8);
            if (mod == 1u || mod == 7u)
            {
                break;
            }
        }
    }

    if (retries > 0)
    {
        params->pLen = mbedtls_mpi_size(&P);
        params->gLen = mbedtls_mpi_size(&G);
        err = mbedtls_mpi_write_binary(&P, params->pBytes, params->pLen) != 0 ||
              mbedtls_mpi_write_binary(&G, params->gBytes, params->gLen) != 0 ?
              OS_ERROR_ABORTED : OS_SUCCESS;
    }
    else
    {
        err = OS_ERROR_ABORTED;
    }

    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&G);

    return err;
}

static OS_Error_t
generate_DHPrv(
    OS_CryptoKey_DhPrv_t* key,
    CryptoLibRng_t*       rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    mbedtls_mpi X, GX, G, P;
    size_t retries, p_bit_length, x_bit_length;

    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&GX);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&P);

    // Set group params: generator G and prime P
    if (mbedtls_mpi_read_binary(&G, key->params.gBytes, key->params.gLen) != 0 ||
        mbedtls_mpi_read_binary(&P, key->params.pBytes, key->params.pLen) != 0)
    {
        err = OS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        p_bit_length = mbedtls_mpi_bitlen(&P);
        // Generate an X as large as possible as private scalar
        for (retries = CryptoLibKey_DH_GEN_RETRIES; retries > 0; retries--)
        {
            // Create random X and make sure it is smaller than P
            if (mbedtls_mpi_fill_random(&X, mbedtls_mpi_size(&P),
                                        CryptoLibRng_getBytesMbedtls, rng) != 0)
            {
                continue;
            }

            x_bit_length = mbedtls_mpi_bitlen(&X);
            if (x_bit_length > p_bit_length)
            {
                //We Mask the upper part of X
                for (size_t i = x_bit_length; i >  p_bit_length; i--)
                {
                    //The argument pos in mbedtls_mpi_set_bit is a Zero based
                    //index we use i - 1
                    mbedtls_mpi_set_bit(&X, i - 1, 0);
                }
            }

            // Check X is in range, generate GX = G^X mod P and check that, too
            if ((dhm_check_range(&X, &P) != 0) ||
                (mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL) != 0) ||
                (dhm_check_range(&GX, &P) != 0))
            {
                continue;
            }
            break;
        }
        if (retries == 0)
        {
            err = OS_ERROR_ABORTED;
        }
        else
        {
            key->xLen = mbedtls_mpi_size(&X);
            err = mbedtls_mpi_write_binary(&X, key->xBytes, key->xLen) != 0 ?
                  OS_ERROR_ABORTED : OS_SUCCESS;
        }
    }

    mbedtls_mpi_free(&GX);
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&P);

    return err;
}

static OS_Error_t
make_DHPub(
    OS_CryptoKey_DhPub_t*       pubKey,
    const OS_CryptoKey_DhPrv_t* prvKey)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    const OS_CryptoKey_DhParams_t* params = &prvKey->params;
    mbedtls_mpi GX, X, P, G;

    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&GX);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&P);

    // Set group params: generator G and prime P
    if (mbedtls_mpi_read_binary(&X, prvKey->xBytes, prvKey->xLen) != 0 ||
        mbedtls_mpi_read_binary(&P, params->pBytes, params->pLen) != 0 ||
        mbedtls_mpi_read_binary(&G, params->gBytes, params->gLen) != 0)
    {
        err = OS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    // Check X is in range, generate GX = G^X mod P and check that, too
    if ((dhm_check_range(&X, &P) == 0) &&
        (mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL) == 0) &&
        (dhm_check_range(&GX, &P) == 0))
    {
        memcpy(&pubKey->params, params, sizeof(OS_CryptoKey_DhParams_t));
        pubKey->gxLen = mbedtls_mpi_size(&GX);
        err = mbedtls_mpi_write_binary(&GX, pubKey->gxBytes, pubKey->gxLen) != 0 ?
              OS_ERROR_ABORTED : OS_SUCCESS;
    }
    else
    {
        err = OS_ERROR_ABORTED;
    }

exit:
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&GX);
    mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&P);

    return err;
}

// -------------------------------- RSA Keys -----------------------------------

static OS_Error_t
generate_RsaPrv(
    OS_CryptoKey_RsaRrv_t* key,
    const size_t           bits,
    CryptoLibRng_t*        rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    mbedtls_rsa_context rsa;

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);

    if (mbedtls_rsa_gen_key(&rsa, CryptoLibRng_getBytesMbedtls, rng, bits,
                            CryptoLibKey_RSA_EXPONENT) != 0)
    {
        err = OS_ERROR_ABORTED;
        goto exit;
    }

    key->eLen = mbedtls_mpi_size(&rsa.E);
    key->qLen = mbedtls_mpi_size(&rsa.Q);
    key->pLen = mbedtls_mpi_size(&rsa.P);
    key->dLen = mbedtls_mpi_size(&rsa.D);
    err = mbedtls_mpi_write_binary(&rsa.P, key->pBytes, key->pLen) ||
          mbedtls_mpi_write_binary(&rsa.Q, key->qBytes, key->qLen) ||
          mbedtls_mpi_write_binary(&rsa.D, key->dBytes, key->dLen) ||
          mbedtls_mpi_write_binary(&rsa.E, key->eBytes, key->eLen) ?
          OS_ERROR_ABORTED : OS_SUCCESS;

exit:
    mbedtls_rsa_free(&rsa);

    return err;
}

static OS_Error_t
make_RsaPub(
    OS_CryptoKey_RsaRub_t*       pubKey,
    const OS_CryptoKey_RsaRrv_t* prvKey)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    mbedtls_mpi P, Q, N;

    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&N);

    if (mbedtls_mpi_read_binary(&P, prvKey->pBytes, prvKey->pLen) != 0 ||
        mbedtls_mpi_read_binary(&Q, prvKey->qBytes, prvKey->qLen) != 0)
    {
        err = OS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    if (mbedtls_mpi_mul_mpi(&N, &P, &Q) != 0)
    {
        err = OS_ERROR_ABORTED;
        goto exit;
    }

    memcpy(pubKey->eBytes, prvKey->eBytes, prvKey->eLen);
    pubKey->eLen = prvKey->eLen;
    pubKey->nLen = mbedtls_mpi_size(&N);
    err = mbedtls_mpi_write_binary(&N, pubKey->nBytes, pubKey->nLen) ?
          OS_ERROR_ABORTED : OS_SUCCESS;

exit:
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&N);

    return err;
}

// ----------------------------- SECP256r1 Keys --------------------------------

static OS_Error_t
generate_SECP256r1Prv(
    OS_CryptoKey_Secp256r1Prv_t* key,
    CryptoLibRng_t*              rng)
{
    OS_Error_t err;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        mbedtls_ecp_gen_privkey(&grp, &d, CryptoLibRng_getBytesMbedtls, rng) != 0)
    {
        err = OS_ERROR_ABORTED;
        goto exit;
    }

    key->dLen = mbedtls_mpi_size(&d);
    err = mbedtls_mpi_write_binary(&d, key->dBytes, key->dLen) ?
          OS_ERROR_ABORTED : OS_SUCCESS;

exit:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    return err;
}

static OS_Error_t
make_SECP256r1Pub(
    OS_CryptoKey_Secp256r1Pub_t*       pubKey,
    const OS_CryptoKey_Secp256r1Prv_t* prvKey,
    CryptoLibRng_t*                    rng)
{
    OS_Error_t err;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    if (mbedtls_mpi_read_binary(&d, prvKey->dBytes, prvKey->dLen) != 0)
    {
        err = OS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, CryptoLibRng_getBytesMbedtls, rng) != 0)
    {
        err = OS_ERROR_ABORTED;
        goto exit;
    }

    pubKey->qxLen = mbedtls_mpi_size(&Q.X);
    pubKey->qyLen = mbedtls_mpi_size(&Q.Y);
    err = mbedtls_mpi_write_binary(&Q.X, pubKey->qxBytes, pubKey->qxLen) ||
          mbedtls_mpi_write_binary(&Q.Y, pubKey->qyBytes, pubKey->qyLen) ?
          OS_ERROR_ABORTED : OS_SUCCESS;

exit:
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    return err;
}

// -----------------------------------------------------------------------------
// This function muxes a selection with a big switch-case construct. Those
// kind of functions, when decomposed, often result in a less readable code.
// Therefore we suppress the cyclomatic complexity analysis for this function.
// metrix++: suppress std.code.complexity:cyclomatic
static OS_Error_t
initImpl(
    CryptoLibKey_t**             self,
    const OS_CryptoKey_Type_t    type,
    const OS_CryptoKey_Attrib_t* attribs,
    const OS_Crypto_Memory_t*    memory)
{
    size_t size;
    OS_Error_t err;
    CryptoLibKey_t* key;

    switch (type)
    {
    case OS_CryptoKey_TYPE_AES:
        size = sizeof(OS_CryptoKey_Aes_t);
        break;
    case OS_CryptoKey_TYPE_MAC:
        size = sizeof(OS_CryptoKey_Mac_t);
        break;
    case OS_CryptoKey_TYPE_RSA_PRV:
        size = sizeof(OS_CryptoKey_RsaRrv_t);
        break;
    case OS_CryptoKey_TYPE_RSA_PUB:
        size = sizeof(OS_CryptoKey_RsaRub_t);
        break;
    case OS_CryptoKey_TYPE_DH_PRV:
        size = sizeof(OS_CryptoKey_DhPrv_t);
        break;
    case OS_CryptoKey_TYPE_DH_PUB:
        size = sizeof(OS_CryptoKey_DhPub_t);
        break;
    case OS_CryptoKey_TYPE_SECP256R1_PRV:
        size = sizeof(OS_CryptoKey_Secp256r1Prv_t);
        break;
    case OS_CryptoKey_TYPE_SECP256R1_PUB:
        size = sizeof(OS_CryptoKey_Secp256r1Pub_t);
        break;
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    if ((key = memory->calloc(1, sizeof(CryptoLibKey_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(key, 0, sizeof(CryptoLibKey_t));
    key->attribs = *attribs;
    key->type    = type;
    key->size    = size;

    err = (key->data = memory->calloc(1, size)) == NULL ?
          OS_ERROR_INSUFFICIENT_SPACE : OS_SUCCESS;
    if (err != OS_SUCCESS)
    {
        memory->free(key);
    }

    *self = key;

    return err;
}

// This function muxes a selection with a big switch-case construct. Those
// kind of functions, when decomposed, often result in a less readable code.
// Therefore we suppress the cyclomatic complexity analysis for this function.
// metrix++: suppress std.code.complexity:cyclomatic
static OS_Error_t
generateImpl(
    CryptoLibKey_t*            self,
    const OS_CryptoKey_Spec_t* spec,
    CryptoLibRng_t*            rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    switch (spec->key.type)
    {
    case OS_CryptoKey_TYPE_AES:
    {
        OS_CryptoKey_Aes_t* key = (OS_CryptoKey_Aes_t*) self->data;
        if ((OS_CryptoKey_SPECTYPE_BITS != spec->type)
            || ((128 != spec->key.params.bits)
                && (192 != spec->key.params.bits)
                && (256 != spec->key.params.bits)))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        key->len = spec->key.params.bits >> 3;
        return CryptoLibRng_getBytes(rng, 0, key->bytes, key->len);
    }

    case OS_CryptoKey_TYPE_MAC:
    {
        OS_CryptoKey_Mac_t* key = (OS_CryptoKey_Mac_t*) self->data;
        if ((OS_CryptoKey_SPECTYPE_BITS != spec->type)
            || (spec->key.params.bits > (OS_CryptoKey_SIZE_MAC_MAX * 8)))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        key->len = spec->key.params.bits >> 3;
        return CryptoLibRng_getBytes(rng, 0, key->bytes, key->len);
    }

    case OS_CryptoKey_TYPE_RSA_PRV:
        if ((OS_CryptoKey_SPECTYPE_BITS != spec->type)
            || (spec->key.params.bits < (OS_CryptoKey_SIZE_AES_MIN * 8))
            || (spec->key.params.bits > (OS_CryptoKey_SIZE_RSA_MAX * 8)))
        {
            return OS_ERROR_NOT_SUPPORTED;
        }
        return generate_RsaPrv(self->data, spec->key.params.bits, rng);

    case OS_CryptoKey_TYPE_SECP256R1_PRV:
        // We can ignore all of the spec params, because the keytype defines
        // everything already..
        return generate_SECP256r1Prv(self->data, rng);

    case OS_CryptoKey_TYPE_DH_PRV:
    {
        OS_CryptoKey_DhPrv_t* key = (OS_CryptoKey_DhPrv_t*) self->data;
        size_t bits;

        switch (spec->type)
        {
        case OS_CryptoKey_SPECTYPE_PARAMS:
            bits = getMpiLen(spec->key.params.dh.pBytes, spec->key.params.dh.pLen);
            break;
        case OS_CryptoKey_SPECTYPE_BITS:
            bits = spec->key.params.bits;
            break;
        default:
            return OS_ERROR_NOT_SUPPORTED;
        }
        if (bits > (OS_CryptoKey_SIZE_DH_MAX * 8)
            || bits < (OS_CryptoKey_SIZE_DH_MIN * 8))
        {
            return OS_ERROR_NOT_SUPPORTED;
        }
        if (OS_CryptoKey_SPECTYPE_PARAMS == spec->type)
        {
            memcpy(&key->params, &spec->key.params, sizeof(OS_CryptoKey_DhParams_t));
            err = OS_SUCCESS;
        }
        else
        {
            err = generate_DHParams(bits, &key->params, rng);
        }
        return (err == OS_SUCCESS) ?
               generate_DHPrv(key, rng) : err;
    }

    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static OS_Error_t
makeImpl(
    CryptoLibKey_t*       self,
    const CryptoLibKey_t* prvKey,
    CryptoLibRng_t*       rng)
{
    switch (self->type)
    {
    case OS_CryptoKey_TYPE_RSA_PUB:
        return make_RsaPub(self->data, prvKey->data);
    case OS_CryptoKey_TYPE_SECP256R1_PUB:
        return make_SECP256r1Pub(self->data, prvKey->data, rng);
    case OS_CryptoKey_TYPE_DH_PUB:
        return make_DHPub(self->data, prvKey->data);
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }
}

// This function muxes a selection with a big switch-case construct. Those
// kind of functions, when decomposed, often result in a less readable code.
// Therefore we suppress the cyclomatic complexity analysis for this function.
// metrix++: suppress std.code.complexity:cyclomatic
static OS_Error_t
importImpl(
    CryptoLibKey_t*            self,
    const OS_CryptoKey_Data_t* key)
{
    size_t bits;

    switch (key->type)
    {
    case OS_CryptoKey_TYPE_RSA_PUB:
        if ((key->data.rsa.pub.eLen > sizeof(key->data.rsa.pub.eBytes))
            || (key->data.rsa.pub.nLen > sizeof(key->data.rsa.pub.nBytes)))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        bits = getMpiLen(key->data.rsa.pub.nBytes, key->data.rsa.pub.nLen);
        if (bits < (OS_CryptoKey_SIZE_RSA_MIN * 8)
            || bits > (OS_CryptoKey_SIZE_RSA_MAX * 8))
        {
            return OS_ERROR_NOT_SUPPORTED;
        }
        break;

    case OS_CryptoKey_TYPE_RSA_PRV:
        if ((key->data.rsa.pub.eLen > sizeof(key->data.rsa.pub.eBytes))
            || (key->data.rsa.prv.pLen > sizeof(key->data.rsa.prv.pBytes))
            || (key->data.rsa.prv.qLen > sizeof(key->data.rsa.prv.qBytes))
            || (key->data.rsa.prv.dLen > sizeof(key->data.rsa.prv.dBytes)))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        bits = getMpiLen(key->data.rsa.prv.pBytes, key->data.rsa.prv.pLen)
               + getMpiLen(key->data.rsa.prv.qBytes, key->data.rsa.prv.qLen);
        if (bits < (OS_CryptoKey_SIZE_RSA_MIN * 8)
            || bits > (OS_CryptoKey_SIZE_RSA_MAX * 8))
        {
            return OS_ERROR_NOT_SUPPORTED;
        }
        break;

    case OS_CryptoKey_TYPE_SECP256R1_PUB:
        if ((key->data.secp256r1.pub.qxLen > sizeof(key->data.secp256r1.pub.qxBytes))
            || (key->data.secp256r1.pub.qyLen > sizeof(key->data.secp256r1.pub.qyBytes)))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        break;

    case OS_CryptoKey_TYPE_SECP256R1_PRV:
        if ((key->data.secp256r1.prv.dLen > sizeof(key->data.secp256r1.prv.dBytes)))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        break;

    case OS_CryptoKey_TYPE_DH_PUB:
        if ((key->data.dh.pub.gxLen > sizeof(key->data.dh.pub.gxBytes))
            || (key->data.dh.pub.params.gLen > sizeof(key->data.dh.pub.params.gBytes))
            || (key->data.dh.pub.params.pLen > sizeof(key->data.dh.pub.params.pBytes)))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        bits = getMpiLen(key->data.dh.pub.params.pBytes, key->data.dh.pub.params.pLen);
        if (bits < OS_CryptoKey_SIZE_DH_MIN * 8
            || bits > OS_CryptoKey_SIZE_DH_MAX * 8)
        {
            return OS_ERROR_NOT_SUPPORTED;
        }
        break;

    case OS_CryptoKey_TYPE_DH_PRV:
        if ((key->data.dh.prv.xLen > sizeof(key->data.dh.prv.xBytes))
            || (key->data.dh.prv.params.gLen > sizeof(key->data.dh.prv.params.gBytes))
            || (key->data.dh.prv.params.pLen > sizeof(key->data.dh.prv.params.pBytes)))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        bits = getMpiLen(key->data.dh.prv.params.pBytes, key->data.dh.prv.params.pLen);
        if (bits < OS_CryptoKey_SIZE_DH_MIN * 8
            || bits > OS_CryptoKey_SIZE_DH_MAX * 8)
        {
            return OS_ERROR_NOT_SUPPORTED;
        }
        break;

    case OS_CryptoKey_TYPE_AES:
        if (key->data.aes.len > sizeof(key->data.aes.bytes))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        bits = key->data.aes.len * 8;
        if (bits != 128 && bits != 192 && bits != 256)
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        break;

    case OS_CryptoKey_TYPE_MAC:
        if (key->data.mac.len > sizeof(key->data.mac.bytes))
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        break;

    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    // Type and attribs have been set during key init
    memcpy(self->data, &key->data, self->size);

    return OS_SUCCESS;
}

static OS_Error_t
exportImpl(
    const CryptoLibKey_t* self,
    OS_CryptoKey_Data_t*  keyData)
{
    memcpy(&keyData->data, self->data, self->size);
    memcpy(&keyData->attribs, &self->attribs, sizeof(OS_CryptoKey_Attrib_t));
    keyData->type = self->type;

    return OS_SUCCESS;
}

static OS_Error_t
getParamsImpl(
    const CryptoLibKey_t* self,
    void*                 keyParams,
    size_t*               paramSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    size_t size;
    void* params = NULL;

    switch (self->type)
    {
    case OS_CryptoKey_TYPE_DH_PUB:
    case OS_CryptoKey_TYPE_DH_PRV:
        size = sizeof(OS_CryptoKey_DhParams_t);
        params = (self->type == OS_CryptoKey_TYPE_DH_PUB) ?
                 &CryptoLibKey_getDhPub(self)->params :
                 &CryptoLibKey_getDhPrv(self)->params;
        break;
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    if (*paramSize < size)
    {
        err = OS_ERROR_BUFFER_TOO_SMALL;
    }
    else
    {
        memcpy(keyParams, params, size);
        err = OS_SUCCESS;
    }

    *paramSize = size;

    return err;
}

static OS_Error_t
getAttribsImpl(
    const CryptoLibKey_t*  self,
    OS_CryptoKey_Attrib_t* attribs)
{
    memcpy(attribs, &self->attribs, sizeof(OS_CryptoKey_Attrib_t));
    return OS_SUCCESS;
}

static OS_Error_t
loadParamsImpl(
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    size_t size;

    switch (name)
    {
    case OS_CryptoKey_PARAM_ECC_SECP192R1:
    case OS_CryptoKey_PARAM_ECC_SECP224R1:
    case OS_CryptoKey_PARAM_ECC_SECP256R1:
    {
        OS_CryptoKey_EccParams_t* params = (OS_CryptoKey_EccParams_t*) keyParams;
        mbedtls_ecp_group grp;

        size = sizeof(OS_CryptoKey_EccParams_t);
        if (*paramSize < size)
        {
            err = OS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            // Just extract the full range of params from mbedTLS.
            mbedtls_ecp_group_init(&grp);
            mbedtls_ecp_group_load(&grp, name);
            params->aLen = mbedtls_mpi_size(&grp.A);
            params->bLen = mbedtls_mpi_size(&grp.B);
            params->pLen = mbedtls_mpi_size(&grp.P);
            params->nLen = mbedtls_mpi_size(&grp.N);
            params->gxLen = mbedtls_mpi_size(&grp.G.X);
            params->gyLen = mbedtls_mpi_size(&grp.G.Y);
            err = mbedtls_mpi_write_binary(&grp.A, params->aBytes, params->aLen) != 0 ||
                  mbedtls_mpi_write_binary(&grp.B, params->bBytes, params->bLen) != 0 ||
                  mbedtls_mpi_write_binary(&grp.P, params->pBytes, params->pLen) != 0 ||
                  mbedtls_mpi_write_binary(&grp.N, params->nBytes, params->nLen) != 0 ||
                  mbedtls_mpi_write_binary(&grp.G.X, params->gxBytes, params->gxLen) != 0 ||
                  mbedtls_mpi_write_binary(&grp.G.Y, params->gyBytes, params->gyLen) ?
                  OS_ERROR_ABORTED : OS_SUCCESS;
            mbedtls_ecp_group_free(&grp);
        }
        break;
    }
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    *paramSize = size;

    return err;
}

static OS_Error_t
freeImpl(
    CryptoLibKey_t*           self,
    const OS_Crypto_Memory_t* memory)
{
    // We may have stored sensitive key data here, better make sure to remove it.
    zeroizeMemory(self->data, self->size);

    memory->free(self->data);
    memory->free(self);

    return OS_SUCCESS;
}

// Public functions ------------------------------------------------------------

OS_Error_t
CryptoLibKey_generate(
    CryptoLibKey_t**           self,
    const OS_CryptoKey_Spec_t* spec,
    const OS_Crypto_Memory_t*  memory,
    CryptoLibRng_t*            rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(spec);
    CHECK_PTR_NOT_NULL(memory);
    CHECK_PTR_NOT_NULL(rng);

    if ((err = initImpl(self, spec->key.type, &spec->key.attribs,
                        memory)) == OS_SUCCESS)
    {
        if ((err = generateImpl(*self, spec, rng)) != OS_SUCCESS)
        {
            freeImpl(*self, memory);
        }
    }

    return err;
}

OS_Error_t
CryptoLibKey_makePublic(
    CryptoLibKey_t**             self,
    const CryptoLibKey_t*        prvKey,
    const OS_CryptoKey_Attrib_t* attribs,
    const OS_Crypto_Memory_t*    memory,
    CryptoLibRng_t*              rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    OS_CryptoKey_Type_t type;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);
    CHECK_PTR_NOT_NULL(prvKey);
    CHECK_PTR_NOT_NULL(attribs);
    CHECK_PTR_NOT_NULL(rng);

    switch (prvKey->type)
    {
    case OS_CryptoKey_TYPE_DH_PRV:
        type = OS_CryptoKey_TYPE_DH_PUB;
        break;
    case OS_CryptoKey_TYPE_RSA_PRV:
        type = OS_CryptoKey_TYPE_RSA_PUB;
        break;
    case OS_CryptoKey_TYPE_SECP256R1_PRV:
        type = OS_CryptoKey_TYPE_SECP256R1_PUB;
        break;
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    if ((err = initImpl(self, type, attribs, memory)) == OS_SUCCESS)
    {
        if ((err = makeImpl(*self, prvKey, rng)) != OS_SUCCESS)
        {
            freeImpl(*self, memory);
        }
    }

    return err;
}

OS_Error_t
CryptoLibKey_import(
    CryptoLibKey_t**           self,
    const OS_CryptoKey_Data_t* keyData,
    const OS_Crypto_Memory_t*  memory)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);
    CHECK_PTR_NOT_NULL(keyData);

    if ((err = initImpl(self, keyData->type, &keyData->attribs,
                        memory)) == OS_SUCCESS)
    {
        if ((err = importImpl(*self, keyData)) != OS_SUCCESS)
        {
            freeImpl(*self, memory);
        }
    }

    return err;
}

OS_Error_t
CryptoLibKey_free(
    CryptoLibKey_t*           self,
    const OS_Crypto_Memory_t* memory)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);

    return freeImpl(self, memory);
}

OS_Error_t
CryptoLibKey_export(
    const CryptoLibKey_t* self,
    OS_CryptoKey_Data_t*  keyData)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(keyData);

    return exportImpl(self, keyData);
}

OS_Error_t
CryptoLibKey_getParams(
    const CryptoLibKey_t* self,
    void*                 keyParams,
    size_t*               paramSize)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(keyParams);
    CHECK_PTR_NOT_NULL(paramSize);

    return getParamsImpl(self, keyParams, paramSize);
}

OS_Error_t
CryptoLibKey_getAttribs(
    const CryptoLibKey_t*  self,
    OS_CryptoKey_Attrib_t* attribs)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(attribs);

    return getAttribsImpl(self, attribs);
}

OS_Error_t
CryptoLibKey_loadParams(
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize)
{
    CHECK_PTR_NOT_NULL(keyParams);
    CHECK_PTR_NOT_NULL(paramSize);

    return loadParamsImpl(name, keyParams, paramSize);
}

// Conversion functions --------------------------------------------------------

OS_Error_t
CryptoLibKey_writeRsaPub(
    const CryptoLibKey_t* key,
    mbedtls_rsa_context*  rsa)
{
    OS_CryptoKey_RsaRub_t* pubKey = CryptoLibKey_getRsaPub(key);
    return (mbedtls_rsa_import_raw(rsa,
                                   pubKey->nBytes, pubKey->nLen,
                                   NULL, 0, NULL, 0, NULL, 0,
                                   pubKey->eBytes, pubKey->eLen) != 0)
           || (mbedtls_rsa_complete(rsa) != 0)
           || (mbedtls_rsa_check_pubkey(rsa) != 0) ?
           OS_ERROR_INVALID_PARAMETER : OS_SUCCESS;
}

OS_Error_t
CryptoLibKey_writeRsaPrv(
    const CryptoLibKey_t* key,
    mbedtls_rsa_context*  rsa)
{
    OS_CryptoKey_RsaRrv_t* prvKey = CryptoLibKey_getRsaPrv(key);
    return (mbedtls_rsa_import_raw(rsa,
                                   NULL, 0,
                                   prvKey->pBytes, prvKey->pLen,
                                   prvKey->qBytes, prvKey->qLen,
                                   prvKey->dBytes, prvKey->dLen,
                                   prvKey->eBytes, prvKey->eLen) != 0)
           || (mbedtls_rsa_complete(rsa) != 0)
           || (mbedtls_rsa_check_privkey(rsa) != 0) ?
           OS_ERROR_INVALID_PARAMETER : OS_SUCCESS;
}

OS_Error_t
CryptoLibKey_writeDhPub(
    const CryptoLibKey_t* key,
    mbedtls_dhm_context*  dh)
{
    OS_CryptoKey_DhPub_t* dhKey = CryptoLibKey_getDhPub(key);
    return mbedtls_mpi_read_binary(&dh->P, dhKey->params.pBytes,
                                   dhKey->params.pLen) != 0
           || mbedtls_mpi_read_binary(&dh->G, dhKey->params.gBytes,
                                      dhKey->params.gLen) != 0
           || mbedtls_mpi_read_binary(&dh->GY, dhKey->gxBytes, dhKey->gxLen) != 0
           || dhm_check_range(&dh->GY, &dh->P) != 0 ?
           OS_ERROR_INVALID_PARAMETER : OS_SUCCESS;
}

OS_Error_t
CryptoLibKey_writeDhPrv(
    const CryptoLibKey_t* key,
    mbedtls_dhm_context*  dh)
{
    OS_CryptoKey_DhPrv_t* dhKey = CryptoLibKey_getDhPrv(key);
    return mbedtls_mpi_read_binary(&dh->P, dhKey->params.pBytes,
                                   dhKey->params.pLen) != 0
           || mbedtls_mpi_read_binary(&dh->G, dhKey->params.gBytes,
                                      dhKey->params.gLen) != 0
           || mbedtls_mpi_read_binary(&dh->X, dhKey->xBytes, dhKey->xLen) != 0
           || dhm_check_range(&dh->X, &dh->P) != 0 ?
           OS_ERROR_INVALID_PARAMETER : OS_SUCCESS;
}

OS_Error_t
CryptoLibKey_writeSecp256r1Pub(
    const CryptoLibKey_t* key,
    mbedtls_ecdh_context* ecdh)
{
    OS_CryptoKey_Secp256r1Pub_t* ecKey = CryptoLibKey_getSecp256r1Pub(key);
    return mbedtls_mpi_read_binary(&ecdh->Qp.X, ecKey->qxBytes, ecKey->qxLen) != 0
           || mbedtls_mpi_read_binary(&ecdh->Qp.Y, ecKey->qyBytes, ecKey->qyLen) != 0
           || mbedtls_mpi_lset(&ecdh->Qp.Z, 1) != 0
           || mbedtls_ecp_check_pubkey(&ecdh->grp, &ecdh->Qp) != 0 ?
           OS_ERROR_INVALID_PARAMETER : OS_SUCCESS;
}

OS_Error_t
CryptoLibKey_writeSecp256r1Prv(
    const CryptoLibKey_t* key,
    mbedtls_ecdh_context* ecdh)
{
    OS_CryptoKey_Secp256r1Prv_t* ecKey = CryptoLibKey_getSecp256r1Prv(key);
    return mbedtls_ecp_group_load(&ecdh->grp, MBEDTLS_ECP_DP_SECP256R1) != 0
           || mbedtls_mpi_read_binary(&ecdh->d, ecKey->dBytes, ecKey->dLen) != 0
           || mbedtls_ecp_check_privkey(&ecdh->grp, &ecdh->d) != 0 ?
           OS_ERROR_INVALID_PARAMETER : OS_SUCCESS;
}

OS_CryptoKey_Type_t
CryptoLibKey_getType(
    const CryptoLibKey_t* key)
{
    return key->type;
}

OS_CryptoKey_RsaRub_t*
CryptoLibKey_getRsaPub(
    const CryptoLibKey_t* key)
{
    return (OS_CryptoKey_RsaRub_t*) key->data;
}

OS_CryptoKey_RsaRrv_t*
CryptoLibKey_getRsaPrv(
    const CryptoLibKey_t* key)
{
    return (OS_CryptoKey_RsaRrv_t*) key->data;
}

OS_CryptoKey_Secp256r1Pub_t*
CryptoLibKey_getSecp256r1Pub(
    const CryptoLibKey_t* key)
{
    return (OS_CryptoKey_Secp256r1Pub_t*) key->data;
}

OS_CryptoKey_Secp256r1Prv_t*
CryptoLibKey_getSecp256r1Prv(
    const CryptoLibKey_t* key)
{
    return (OS_CryptoKey_Secp256r1Prv_t*) key->data;
}

OS_CryptoKey_DhPub_t*
CryptoLibKey_getDhPub(
    const CryptoLibKey_t* key)
{
    return (OS_CryptoKey_DhPub_t*) key->data;
}

OS_CryptoKey_DhPrv_t*
CryptoLibKey_getDhPrv(
    const CryptoLibKey_t* key)
{
    return (OS_CryptoKey_DhPrv_t*) key->data;
}

OS_CryptoKey_Aes_t*
CryptoLibKey_getAes(
    const CryptoLibKey_t* key)
{
    return (OS_CryptoKey_Aes_t*) key->data;
}

OS_CryptoKey_Mac_t*
CryptoLibKey_getMac(
    const CryptoLibKey_t* key)
{
    return (OS_CryptoKey_Mac_t*) key->data;
}
