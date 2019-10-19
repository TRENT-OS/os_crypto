/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoKey_v5.h"
#include "SeosCryptoRng.h"

#include "LibDebug/Debug.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"

#include <string.h>

// Private static functions ----------------------------------------------------

// This implementation should never be optimized out by the compiler
static void* (* const volatile memset_func)( void*, int, size_t ) = memset;
static void
zeroizeMemory(void*   buf,
              size_t  len)
{
    if ( len > 0 )
    {
        memset_func( buf, 0, len );
    }
}

// Get topmost bit, i.e., to determine the bitsize of a prime
static size_t
getMpiLen(const unsigned char*  xVal,
          const size_t          xLen)
{
    mbedtls_mpi x;
    size_t n;

    mbedtls_mpi_init(&x);
    mbedtls_mpi_read_binary(&x, xVal, xLen);
    n = mbedtls_mpi_bitlen(&x);
    mbedtls_mpi_free(&x);

    return n;
}

// Check if param is within range: 2 < param < P - 2
static seos_err_t
checkMpiRange(const mbedtls_mpi* param,
              const mbedtls_mpi* P)
{
    mbedtls_mpi L, U;
    int ret = SEOS_SUCCESS;

    mbedtls_mpi_init(&L);
    mbedtls_mpi_init(&U);

    if (mbedtls_mpi_lset(&L, 2) != 0 || mbedtls_mpi_sub_int(&U, P, 2) != 0)
    {
        ret = SEOS_ERROR_ABORTED;
        goto cleanup;
    }

    if (mbedtls_mpi_cmp_mpi(param, &L) < 0 || mbedtls_mpi_cmp_mpi(param, &U) > 0)
    {
        ret = SEOS_ERROR_INVALID_PARAMETER;
    }

cleanup:
    mbedtls_mpi_free(&U);
    mbedtls_mpi_free(&L);

    return ret;
}

// -------------------------------- DH Keys ------------------------------------

static seos_err_t
generate_DHParams(SeosCryptoRng*          rng,
                  const size_t            bits,
                  SeosCryptoKey_DHParams* params)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    mbedtls_mpi Q, T, G, P;
    size_t retries;

    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&P);

    // Generator is fixed
    mbedtls_mpi_lset(&G, SeosCryptoKey_DH_GENERATOR);

    // Generate a "safe prime" P such that Q=(P-1)/2 is also prime. Then make
    // sure that for this prime P our generator generates the full group and
    // not just a sub-group. We only need to check in two steps, see below.
    for (retries = SeosCryptoKey_DH_GEN_RETRIES; retries > 0; retries--)
    {
        if (!mbedtls_mpi_gen_prime(&P, bits, MBEDTLS_MPI_GEN_PRIME_FLAG_DH,
                                   SeosCryptoRng_getBytesMbedtls, rng))
        {
            // Check 1: g^2 mod P != 1
            mbedtls_mpi_lset(&T, 2);
            mbedtls_mpi_exp_mod(&T, &G, &T, &P, NULL);
            if (mbedtls_mpi_cmp_int(&T, 1) == 0)
            {
                continue;
            }

            // Compute Q=(P-1)/2
            mbedtls_mpi_copy(&Q, &P);
            mbedtls_mpi_shift_r(&Q, 1);
            // Check 2: g^Q mod P != 1
            mbedtls_mpi_exp_mod(&T, &G, &T, &Q, NULL);
            if (mbedtls_mpi_cmp_int(&T, 1) == 0)
            {
                continue;
            }

            break;
        }
    }

    if (retries > 0)
    {
        params->pLen = mbedtls_mpi_size(&P);
        params->gLen = mbedtls_mpi_size(&G);
        retval = mbedtls_mpi_write_binary(&P, params->pBytes, params->pLen) != 0 ||
                 mbedtls_mpi_write_binary(&G, params->gBytes, params->gLen) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }
    else
    {
        retval = SEOS_ERROR_ABORTED;
    }

    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);

    return retval;
}

static seos_err_t
generate_DHPrv(SeosCryptoKey_DHPrv* key,
               SeosCryptoRng*       rng)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    mbedtls_mpi X, GX, G, P;
    size_t retries;

    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&GX);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&P);

    // Set group params: generator G and prime P
    if (mbedtls_mpi_read_binary(&G, key->params.gBytes, key->params.gLen) != 0 ||
        mbedtls_mpi_read_binary(&P, key->params.pBytes, key->params.pLen) != 0)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    // Generate an X as large as possible as private scalar
    for (retries = SeosCryptoKey_DH_GEN_RETRIES; retries > 0; retries--)
    {
        // Create random X and make sure it is smaller than P
        if (mbedtls_mpi_fill_random(&X, mbedtls_mpi_size(&P),
                                    SeosCryptoRng_getBytesMbedtls, rng) != 0)
        {
            continue;
        }
        while (mbedtls_mpi_cmp_mpi(&X, &P) >= 0)
        {
            mbedtls_mpi_shift_r(&X, 1);
        }

        // Check X is in range, generate GX = G^X mod P and check that, too
        if ((checkMpiRange(&X, &P) != 0) ||
            (mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL) != 0) ||
            (checkMpiRange(&GX, &P) != 0))
        {
            continue;
        }

        break;
    }

    if (retries > 0)
    {
        key->xLen = mbedtls_mpi_size(&X);
        retval = mbedtls_mpi_write_binary(&X, key->xBytes, key->xLen) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }
    else
    {
        retval = SEOS_ERROR_ABORTED;
    }

exit:
    mbedtls_mpi_free(&GX);
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&P);

    return retval;
}

static seos_err_t
make_DHPub(SeosCryptoKey_DHPub*       pubKey,
           const SeosCryptoKey_DHPrv* prvKey)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    const SeosCryptoKey_DHParams* params = &prvKey->params;
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
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    // Check X is in range, generate GX = G^X mod P and check that, too
    if ((checkMpiRange(&X, &P) == 0) &&
        (mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL) == 0) &&
        (checkMpiRange(&GX, &P) == 0))
    {
        memcpy(&pubKey->params, params, sizeof(SeosCryptoKey_DHParams));
        pubKey->gxLen = mbedtls_mpi_size(&GX);
        retval = mbedtls_mpi_write_binary(&GX, pubKey->gxBytes, pubKey->gxLen) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }
    else
    {
        retval = SEOS_ERROR_ABORTED;
    }

exit:
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&GX);
    mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&P);

    return retval;
}

// -------------------------------- RSA Keys -----------------------------------

static seos_err_t
generate_RSAPrv(SeosCryptoKey_RSAPrv* key,
                SeosCryptoRng*        rng,
                const size_t          bits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    mbedtls_rsa_context rsa;

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    if (mbedtls_rsa_gen_key(&rsa, SeosCryptoRng_getBytesMbedtls, rng, bits,
                            SeosCryptoKey_RSA_EXPONENT) != 0)
    {
        retval = SEOS_ERROR_ABORTED;
        goto exit;
    }

    key->eLen = mbedtls_mpi_size(&rsa.E);
    key->qLen = mbedtls_mpi_size(&rsa.Q);
    key->pLen = mbedtls_mpi_size(&rsa.P);
    key->dLen = mbedtls_mpi_size(&rsa.D);
    retval = mbedtls_mpi_write_binary(&rsa.P, key->pBytes, key->pLen) ||
             mbedtls_mpi_write_binary(&rsa.Q, key->qBytes, key->qLen) ||
             mbedtls_mpi_write_binary(&rsa.D, key->dBytes, key->dLen) ||
             mbedtls_mpi_write_binary(&rsa.E, key->eBytes, key->eLen) ?
             SEOS_ERROR_ABORTED : SEOS_SUCCESS;

exit:
    mbedtls_rsa_free(&rsa);

    return retval;
}

static seos_err_t
make_RSAPub(SeosCryptoKey_RSAPub*       pubKey,
            const SeosCryptoKey_RSAPrv* prvKey)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    mbedtls_mpi P, Q, N;

    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&N);

    if (mbedtls_mpi_read_binary(&P, prvKey->pBytes, prvKey->pLen) != 0 ||
        mbedtls_mpi_read_binary(&Q, prvKey->qBytes, prvKey->qLen) != 0)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    else if (mbedtls_mpi_mul_mpi(&N, &P, &Q) != 0)
    {
        retval = SEOS_ERROR_ABORTED;
        goto exit;
    }

    memcpy(pubKey->eBytes, prvKey->eBytes, prvKey->eLen);
    pubKey->eLen = prvKey->eLen;
    pubKey->nLen = mbedtls_mpi_size(&N);
    retval = mbedtls_mpi_write_binary(&N, pubKey->nBytes, pubKey->nLen) ?
             SEOS_ERROR_ABORTED : SEOS_SUCCESS;

exit:
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&N);

    return retval;
}

// ----------------------------- SECP256r1 Keys --------------------------------

static seos_err_t
generate_SECP256r1Prv(SeosCryptoKey_SECP256r1Prv* key,
                      SeosCryptoRng*              rng)
{
    seos_err_t retval;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        mbedtls_ecp_gen_privkey(&grp, &d, SeosCryptoRng_getBytesMbedtls, rng) != 0)
    {
        retval = SEOS_ERROR_ABORTED;
        goto exit;
    }

    key->dLen = mbedtls_mpi_size(&d);
    retval = mbedtls_mpi_write_binary(&d, key->dBytes, key->dLen) ?
             SEOS_ERROR_ABORTED : SEOS_SUCCESS;

exit:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    return retval;
}

static seos_err_t
make_SECP256r1Pub(SeosCryptoKey_SECP256r1Pub*       pubKey,
                  const SeosCryptoKey_SECP256r1Prv* prvKey)
{
    seos_err_t retval;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    if (mbedtls_mpi_read_binary(&d, prvKey->dBytes, prvKey->dLen) != 0)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    else if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
             mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL) != 0)
    {
        retval = SEOS_ERROR_ABORTED;
        goto exit;
    }

    pubKey->qxLen = mbedtls_mpi_size(&Q.X);
    pubKey->qyLen = mbedtls_mpi_size(&Q.Y);
    retval = mbedtls_mpi_write_binary(&Q.X, pubKey->qxBytes, pubKey->qxLen) ||
             mbedtls_mpi_write_binary(&Q.Y, pubKey->qyBytes, pubKey->qyLen) ?
             SEOS_ERROR_ABORTED : SEOS_SUCCESS;

exit:
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    return retval;
}

// -----------------------------------------------------------------------------

static seos_err_t
initImpl(SeosCryptoKey_v5*              self,
         const SeosCrypto_MemIf*        memIf,
         const SeosCryptoKey_Type       type,
         const SeosCryptoKey_Attribs*   attribs)
{
    size_t size;

    switch (type)
    {
    case SeosCryptoKey_Type_AES:
        size = sizeof(SeosCryptoKey_AES);
        break;
    case SeosCryptoKey_Type_RSA_PRV:
        size = sizeof(SeosCryptoKey_RSAPrv);
        break;
    case SeosCryptoKey_Type_RSA_PUB:
        size = sizeof(SeosCryptoKey_RSAPub);
        break;
    case SeosCryptoKey_Type_DH_PRV:
        size = sizeof(SeosCryptoKey_DHPrv);
        break;
    case SeosCryptoKey_Type_DH_PUB:
        size = sizeof(SeosCryptoKey_DHPub);
        break;
    case SeosCryptoKey_Type_SECP256R1_PRV:
        size = sizeof(SeosCryptoKey_SECP256r1Prv);
        break;
    case SeosCryptoKey_Type_SECP256R1_PUB:
        size = sizeof(SeosCryptoKey_SECP256r1Pub);
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    memset(self, 0, sizeof(SeosCryptoKey_v5));

    memcpy(&self->attribs, attribs, sizeof(SeosCryptoKey_Attribs));
    self->type = type;
    self->size = size;
    self->data = memIf->malloc(size);

    return (self->data != NULL) ? SEOS_SUCCESS : SEOS_ERROR_INSUFFICIENT_SPACE;
}

static seos_err_t
generateImpl(SeosCryptoKey_v5*         self,
             SeosCryptoRng*            rng,
             const SeosCryptoKey_Spec* spec)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (spec->spec.type)
    {
    case SeosCryptoKey_Type_AES:
    {
        SeosCryptoKey_AES* key = (SeosCryptoKey_AES*) self->data;
        if ((SeosCryptoKey_SpecType_BITS != spec->type)
            || ((128 != spec->spec.params.bits)
                && (192 != spec->spec.params.bits)
                && (256 != spec->spec.params.bits)))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        key->len = spec->spec.params.bits >> 3;
        return SeosCryptoRng_getBytes(rng, 0, key->bytes, key->len);
    }

    case SeosCryptoKey_Type_RSA_PRV:
        if ((SeosCryptoKey_SpecType_BITS != spec->type)
            || (spec->spec.params.bits < 128)
            || (spec->spec.params.bits > (SeosCryptoKey_Size_RSA * 8)))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        return generate_RSAPrv(self->data, rng, spec->spec.params.bits);

    case SeosCryptoKey_Type_SECP256R1_PRV:
        // We can ignore all of the spec params, because the keytype defines
        // everything already..
        return generate_SECP256r1Prv(self->data, rng);

    case SeosCryptoKey_Type_DH_PRV:
    {
        SeosCryptoKey_DHPrv* key = (SeosCryptoKey_DHPrv*) self->data;
        size_t bits;

        switch (spec->type)
        {
        case SeosCryptoKey_SpecType_DH_PARAMS:
            bits = getMpiLen(spec->spec.params.dh.pBytes, spec->spec.params.dh.pLen);
            break;
        case SeosCryptoKey_SpecType_BITS:
            bits = spec->spec.params.bits;
            break;
        default:
            return SEOS_ERROR_NOT_SUPPORTED;
        }
        if (bits > (SeosCryptoKey_Size_DH * 8) || bits < 64)
        {
            return SEOS_ERROR_NOT_SUPPORTED;
        }
        if (SeosCryptoKey_SpecType_DH_PARAMS == spec->type)
        {
            memcpy(&key->params, &spec->spec.params, sizeof(SeosCryptoKey_DHParams));
            retval = SEOS_SUCCESS;
        }
        else
        {
            retval = generate_DHParams(rng, bits, &key->params);
        }
        return (retval == SEOS_SUCCESS) ?
               generate_DHPrv(key, rng) : retval;
    }

    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
makeImpl(SeosCryptoKey_v5*          self,
         const SeosCryptoKey_v5*    prvKey)
{
    switch (self->type)
    {
    case SeosCryptoKey_Type_RSA_PUB:
        return make_RSAPub(self->data, prvKey->data);
    case SeosCryptoKey_Type_SECP256R1_PUB:
        return make_SECP256r1Pub(self->data, prvKey->data);
    case SeosCryptoKey_Type_DH_PUB:
        return make_DHPub(self->data, prvKey->data);
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }
}

static seos_err_t
freeImpl(SeosCryptoKey_v5*          self,
         const SeosCrypto_MemIf*    memIf)
{
    // We may have stored sensitive key data here, better make sure to remove it.
    zeroizeMemory(self->data, self->size);
    memIf->free(self->data);

    return SEOS_SUCCESS;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoKey_generate_v5(SeosCryptoKey_v5*         self,
                          const SeosCrypto_MemIf*   memIf,
                          SeosCryptoRng*            rng,
                          const SeosCryptoKey_Spec* spec)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == rng || NULL == memIf || NULL == spec)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = initImpl(self, memIf, spec->spec.type,
                           &spec->spec.attribs)) == SEOS_SUCCESS)
    {
        if ((retval = generateImpl(self, rng, spec)) != SEOS_SUCCESS)
        {
            freeImpl(self, memIf);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoKey_makePublic_v5(SeosCryptoKey_v5*               self,
                            const SeosCrypto_MemIf*         memIf,
                            const SeosCryptoKey_v5*         prvKey,
                            const SeosCryptoKey_Attribs*    attribs)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoKey_Type type;

    if (NULL == self || NULL == memIf || NULL == prvKey || NULL == attribs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (prvKey->type)
    {
    case SeosCryptoKey_Type_DH_PRV:
        type = SeosCryptoKey_Type_DH_PUB;
        break;
    case SeosCryptoKey_Type_RSA_PRV:
        type = SeosCryptoKey_Type_RSA_PUB;
        break;
    case SeosCryptoKey_Type_SECP256R1_PRV:
        type = SeosCryptoKey_Type_SECP256R1_PUB;
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    if ((retval = initImpl(self, memIf, type, attribs)) == SEOS_SUCCESS)
    {
        if ((retval = makeImpl(self, prvKey)) != SEOS_SUCCESS)
        {
            freeImpl(self, memIf);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoKey_import_v5(SeosCryptoKey_v5*          self,
                        const SeosCrypto_MemIf*    memIf,
                        const SeosCryptoKey_v5*    wrapKey,
                        const SeosCryptoKey_Data*  keyData)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_export_v5(SeosCryptoKey_v5*       self,
                        const SeosCryptoKey_v5* wrapKey,
                        SeosCryptoKey_Data*     keyData)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_getParams_v5(SeosCryptoKey_v5*    self,
                           void*                keyParams,
                           size_t*              paramSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_loadParams_v5(const SeosCryptoKey_ParamName   name,
                            void*                           keyParams,
                            size_t*                         paramSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_free_v5(SeosCryptoKey_v5*        self,
                      const SeosCrypto_MemIf*  memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}
