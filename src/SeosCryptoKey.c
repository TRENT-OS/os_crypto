/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoKey.h"
#include "SeosCryptoRng.h"

#include "LibDebug/Debug.h"

#include "mbedtls/ecp.h"

#include <string.h>

// Private static functions ----------------------------------------------------

/*
 * This implementation should never be optimized out by the compiler
 *
 * This implementation for mbedtls_platform_zeroizeMemory() was inspired from
 * Colin Percival's blog article at:
 *
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 *
 * It uses a volatile function pointer to the standard memset(). Because the
 * pointer is volatile the compiler expects it to change at
 * any time and will not optimize out the call that could potentially perform
 * other operations on the input buffer instead of just setting it to 0.
 * Nevertheless, as pointed out by davidtgoldblatt on Hacker News
 * (refer to http://www.daemonology.net/blog/2014-09-05-erratum.html for
 * details), optimizations of the following form are still possible:
 *
 * if( memset_func != memset )
 *     memset_func( buf, 0, len );
 *
 */
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

/*
 * Verify sanity of parameter with regards to P
 *
 * Parameter should be: 2 <= public_param <= P - 2
 *
 * This means that we need to return an error if
 *              public_param < 2 or public_param > P-2
 *
 * For more information on the attack, see:
 *  http://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf
 *  http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-2643
 */
static int
checkDhRange(const mbedtls_mpi*     param,
             const mbedtls_mpi*     P)
{
    mbedtls_mpi L, U;
    int ret = 0;

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

static size_t
getEffectiveKeylength(const SeosCryptoKey_Type  type,
                      const void*               keyBytes)
{
    switch (type)
    {
    case SeosCryptoKey_Type_RSA_PUB:
    {
        SeosCryptoKey_RSAPub* key = (SeosCryptoKey_RSAPub*) keyBytes;
        return getMpiLen(key->nBytes, key->nLen);
    }
    case SeosCryptoKey_Type_RSA_PRV:
    {
        SeosCryptoKey_RSAPrv* key = (SeosCryptoKey_RSAPrv*) keyBytes;
        return getMpiLen(key->pBytes, key->pLen) + getMpiLen(key->qBytes, key->qLen);
    }
    case SeosCryptoKey_Type_SECP256R1_PUB:
    case SeosCryptoKey_Type_SECP256R1_PRV:
        // Effective keylength is already determined by the curve
        return 256;
    case SeosCryptoKey_Type_DH_PUB:
    {
        SeosCryptoKey_DHPub* key = (SeosCryptoKey_DHPub*) keyBytes;
        return getMpiLen(key->pBytes, key->pLen);
    }
    case SeosCryptoKey_Type_DH_PRV:
    {
        SeosCryptoKey_DHPrv* key = (SeosCryptoKey_DHPrv*) keyBytes;
        return getMpiLen(key->pBytes, key->pLen);
    }
    case SeosCryptoKey_Type_AES:
    {
        SeosCryptoKey_AES* key = (SeosCryptoKey_AES*) keyBytes;
        return key->len * 8;
    }
    default:
        return 0;
    }
}

static seos_err_t
checkFlags(const SeosCryptoKey_Flags flags)
{
    return (flags == ((flags & SeosCryptoKey_Flags_NONE) |
                      (flags & SeosCryptoKey_Flags_EXPORTABLE_RAW) |
                      (flags & SeosCryptoKey_Flags_EXPORTABLE_WRAPPED))) ?
           SEOS_SUCCESS : SEOS_ERROR_INVALID_PARAMETER;
}

static seos_err_t
initImpl(SeosCryptoKey*             self,
         const SeosCrypto_MemIf*    memIf,
         const SeosCryptoKey_Type   type,
         const SeosCryptoKey_Flags  flags,
         const size_t               bits)
{
    size_t keySize;

    memset(self, 0, sizeof(*self));

    switch (type)
    {
    case SeosCryptoKey_Type_AES:
        if (!((128 == bits) || (192 == bits) || (256 == bits)))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_AES);
        break;
    case SeosCryptoKey_Type_RSA_PRV:
        if (bits > (SeosCryptoKey_Size_RSA_PRV * 8) || bits < 128)
        {
            return SEOS_ERROR_NOT_SUPPORTED;
        }
        keySize = sizeof(SeosCryptoKey_RSAPrv);
        break;
    case SeosCryptoKey_Type_RSA_PUB:
        if (bits > (SeosCryptoKey_Size_RSA_PUB * 8) || bits < 128)
        {
            return SEOS_ERROR_NOT_SUPPORTED;
        }
        keySize = sizeof(SeosCryptoKey_RSAPub);
        break;
    case SeosCryptoKey_Type_DH_PRV:
        if (bits > (SeosCryptoKey_Size_DH_PRV * 8) || bits < 64)
        {
            return SEOS_ERROR_NOT_SUPPORTED;
        }
        keySize = sizeof(SeosCryptoKey_DHPrv);
        break;
    case SeosCryptoKey_Type_DH_PUB:
        if (bits > (SeosCryptoKey_Size_DH_PUB * 8) || bits < 64)
        {
            return SEOS_ERROR_NOT_SUPPORTED;
        }
        keySize = sizeof(SeosCryptoKey_DHPub);
        break;
    case SeosCryptoKey_Type_SECP256R1_PRV:
        if (bits != (SeosCryptoKey_Size_SECP256R1_PRV * 8))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_SECP256r1Prv);
        break;
    case SeosCryptoKey_Type_SECP256R1_PUB:
        if (bits != (SeosCryptoKey_Size_SECP256R1_PUB * 8))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_SECP256r1Pub);
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    self->type      = type;
    self->bits      = bits;
    self->flags     = flags;
    self->keySize   = keySize;
    self->keyBytes  = memIf->malloc(keySize);

    return (self->keyBytes != NULL) ?
           SEOS_SUCCESS : SEOS_ERROR_INSUFFICIENT_SPACE;
}

static seos_err_t
freeImpl(SeosCryptoKey*             self,
         const SeosCrypto_MemIf*    memIf)
{
    // We may have stored sensitive key data here, better make sure to remove it.
    zeroizeMemory(self->keyBytes, self->keySize);
    memIf->free(self->keyBytes);

    return SEOS_SUCCESS;
}

static seos_err_t
genImpl(SeosCryptoKey*      self,
        SeosCryptoRng*      rng)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->type)
    {
    case SeosCryptoKey_Type_AES:
    {
        SeosCryptoKey_AES* key = (SeosCryptoKey_AES*) self->keyBytes;
        key->len = self->bits >> 3;
        retval = SeosCryptoRng_getBytes(rng, 0, key->bytes, key->len);
        break;
    }
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
genRSAPairImpl(SeosCryptoKey*  prvKey,
               SeosCryptoKey*  pubKey,
               SeosCryptoRng*  rng)
{
    seos_err_t retval;
    SeosCryptoKey_RSAPrv* prvRsa = (SeosCryptoKey_RSAPrv*) prvKey->keyBytes;
    SeosCryptoKey_RSAPub* pubRsa = (SeosCryptoKey_RSAPub*) pubKey->keyBytes;
    mbedtls_rsa_context rsa;

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);

    if (mbedtls_rsa_gen_key(&rsa, SeosCryptoRng_getBytesMbedtls, rng, prvKey->bits,
                            SeosCryptoKey_RSA_EXPONENT) != 0)
    {
        retval = SEOS_ERROR_ABORTED;
    }
    else
    {
        pubRsa->nLen = mbedtls_mpi_size(&rsa.N);
        pubRsa->eLen = mbedtls_mpi_size(&rsa.E);
        prvRsa->eLen = mbedtls_mpi_size(&rsa.E);
        prvRsa->qLen = mbedtls_mpi_size(&rsa.Q);
        prvRsa->pLen = mbedtls_mpi_size(&rsa.P);
        prvRsa->dLen = mbedtls_mpi_size(&rsa.D);
        retval = mbedtls_mpi_write_binary(&rsa.N, pubRsa->nBytes, pubRsa->nLen) ||
                 mbedtls_mpi_write_binary(&rsa.E, pubRsa->eBytes, pubRsa->eLen) ||
                 mbedtls_mpi_write_binary(&rsa.P, prvRsa->pBytes, prvRsa->pLen) ||
                 mbedtls_mpi_write_binary(&rsa.Q, prvRsa->qBytes, prvRsa->qLen) ||
                 mbedtls_mpi_write_binary(&rsa.D, prvRsa->dBytes, prvRsa->dLen) ||
                 mbedtls_mpi_write_binary(&rsa.E, prvRsa->eBytes, prvRsa->eLen) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }

    mbedtls_rsa_free(&rsa);

    return retval;
}

static seos_err_t
genDHPairImpl(SeosCryptoKey*  prvKey,
              SeosCryptoKey*  pubKey,
              SeosCryptoRng*  rng)
{
    seos_err_t retval;
    SeosCryptoKey_DHPrv* prvDh = (SeosCryptoKey_DHPrv*) prvKey->keyBytes;
    SeosCryptoKey_DHPub* pubDh = (SeosCryptoKey_DHPub*) pubKey->keyBytes;
    mbedtls_dhm_context dh;
    mbedtls_mpi X, GX;
    void* rngFunc = SeosCryptoRng_getBytesMbedtls;
    size_t retries;

    mbedtls_dhm_init(&dh);
    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&GX);

    // Generate a "safe prime" P such that Q=(P-1)/2 is also prime
    retval = SEOS_ERROR_ABORTED;
    if (0 == mbedtls_mpi_gen_prime(&dh.P, prvKey->bits,
                                   MBEDTLS_MPI_GEN_PRIME_FLAG_DH, rngFunc, rng))
    {
        // Generate an X as large as possible
        retries = 10;
        while (retries > 0)
        {
            if (mbedtls_mpi_fill_random(&X, mbedtls_mpi_size(&dh.P), rngFunc, rng) != 0)
            {
                break;
            }
            while (mbedtls_mpi_cmp_mpi(&X, &dh.P) >= 0)
            {
                mbedtls_mpi_shift_r(&X, 1);
            }
            if (checkDhRange(&X, &dh.P) == 0)
            {
                retval = SEOS_SUCCESS;
                break;
            }
            retries--;
        }

        // Generate GX = G^X mod P and store it all
        if (SEOS_SUCCESS == retval
            && mbedtls_mpi_lset(&dh.G, SeosCryptoKey_DH_GENERATOR) == 0
            && mbedtls_mpi_exp_mod(&GX, &dh.G, &X, &dh.P, &dh.RP) == 0
            && checkDhRange(&GX, &dh.P) == 0)
        {
            prvDh->pLen  = mbedtls_mpi_size(&dh.P);
            prvDh->gLen  = mbedtls_mpi_size(&dh.G);
            prvDh->xLen  = mbedtls_mpi_size(&X);
            pubDh->pLen  = mbedtls_mpi_size(&dh.P);
            pubDh->gLen  = mbedtls_mpi_size(&dh.G);
            pubDh->gxLen = mbedtls_mpi_size(&GX);
            retval = mbedtls_mpi_write_binary(&X,    prvDh->xBytes,  prvDh->xLen) != 0 ||
                     mbedtls_mpi_write_binary(&GX,   pubDh->gxBytes, pubDh->gxLen) != 0 ||
                     mbedtls_mpi_write_binary(&dh.P, prvDh->pBytes,  prvDh->pLen) != 0 ||
                     mbedtls_mpi_write_binary(&dh.G, prvDh->gBytes,  prvDh->gLen) != 0 ||
                     mbedtls_mpi_write_binary(&dh.G, pubDh->gBytes,  pubDh->gLen) != 0 ||
                     mbedtls_mpi_write_binary(&dh.P, pubDh->pBytes,  pubDh->pLen) != 0 ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
    }

    mbedtls_mpi_free(&GX);
    mbedtls_mpi_free(&X);
    mbedtls_dhm_free(&dh);

    return retval;
}

static seos_err_t
genSECP256r1PairImpl(SeosCryptoKey*  prvKey,
                     SeosCryptoKey*  pubKey,
                     SeosCryptoRng*  rng)
{
    seos_err_t retval;
    SeosCryptoKey_SECP256r1Prv* prvEc = (SeosCryptoKey_SECP256r1Prv*)
                                        prvKey->keyBytes;
    SeosCryptoKey_SECP256r1Pub* pubEc = (SeosCryptoKey_SECP256r1Pub*)
                                        pubKey->keyBytes;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        mbedtls_ecp_gen_keypair(&grp, &d, &Q, SeosCryptoRng_getBytesMbedtls, rng) != 0)
    {
        retval = SEOS_ERROR_ABORTED;
    }
    else
    {
        pubEc->qxLen = mbedtls_mpi_size(&Q.X);
        pubEc->qyLen = mbedtls_mpi_size(&Q.Y);
        prvEc->dLen = mbedtls_mpi_size(&d);
        retval = mbedtls_mpi_write_binary(&Q.X, pubEc->qxBytes, pubEc->qxLen) != 0 ||
                 mbedtls_mpi_write_binary(&Q.Y, pubEc->qyBytes, pubEc->qyLen) != 0 ||
                 mbedtls_mpi_write_binary(&d, prvEc->dBytes, prvEc->dLen) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);

    return retval;
}

static seos_err_t
genPairImpl(SeosCryptoKey*  prvKey,
            SeosCryptoKey*  pubKey,
            SeosCryptoRng*  rng)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (prvKey->type)
    {
    case SeosCryptoKey_Type_RSA_PRV:
        retval = (pubKey->type != SeosCryptoKey_Type_RSA_PUB) ?
                 SEOS_ERROR_INVALID_PARAMETER : genRSAPairImpl(prvKey, pubKey, rng);
        break;
    case SeosCryptoKey_Type_SECP256R1_PRV:
        retval = (pubKey->type != SeosCryptoKey_Type_SECP256R1_PUB) ?
                 SEOS_ERROR_INVALID_PARAMETER : genSECP256r1PairImpl(prvKey, pubKey, rng);
        break;
    case SeosCryptoKey_Type_DH_PRV:
        retval = (pubKey->type != SeosCryptoKey_Type_DH_PUB) ?
                 SEOS_ERROR_INVALID_PARAMETER : genDHPairImpl(prvKey, pubKey, rng);
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
importImpl(SeosCryptoKey*       self,
           const SeosCryptoKey* wrapKey,
           const void*          keyBytes,
           const size_t         keySize)
{
    if (NULL != wrapKey)
    {
        // Todo: Implement key unwrapping algorithm
        return SEOS_ERROR_NOT_SUPPORTED;
    }
    else if (self->keySize != keySize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->keyBytes, keyBytes, keySize);

    return SEOS_SUCCESS;
}

static seos_err_t
exportImpl(SeosCryptoKey*       self,
           const SeosCryptoKey* wrapKey,
           SeosCryptoKey_Type*  type,
           SeosCryptoKey_Flags* flags,
           void*                buf,
           size_t*              bufSize)
{
    if (NULL != wrapKey)
    {
        // Todo: Implement key wrapping algorithm
        return SEOS_ERROR_NOT_SUPPORTED;
    }
    else if (*bufSize < self->keySize)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(buf, self->keyBytes, self->keySize);

    *type       = self->type;
    *flags      = self->flags;
    *bufSize    = self->keySize;

    return SEOS_SUCCESS;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoKey_generate(SeosCryptoKey*            self,
                       SeosCryptoRng*            rng,
                       const SeosCrypto_MemIf*   memIf,
                       const SeosCryptoKey_Type  type,
                       const SeosCryptoKey_Flags flags,
                       const size_t              bits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == rng || NULL == memIf
        || SEOS_SUCCESS !=  checkFlags(flags))
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((retval = initImpl(self, memIf, type, flags, bits)) == SEOS_SUCCESS)
    {
        if ((retval = genImpl(self, rng)) != SEOS_SUCCESS)
        {
            freeImpl(self, memIf);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoKey_generatePair(SeosCryptoKey*               prvKey,
                           SeosCryptoKey*               pubKey,
                           SeosCryptoRng*               rng,
                           const SeosCrypto_MemIf*      memIf,
                           const SeosCryptoKey_PairType type,
                           const SeosCryptoKey_Flags    prvFlags,
                           const SeosCryptoKey_Flags    pubFlags,
                           const size_t                 bits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoKey_Type prvType, pubType;

    if (NULL == prvKey || NULL == pubKey || NULL == rng || NULL == memIf ||
        SEOS_SUCCESS != checkFlags(prvFlags) || SEOS_SUCCESS != checkFlags(pubFlags))
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (type)
    {
    case SeosCryptoKey_PairType_DH:
        prvType = SeosCryptoKey_Type_DH_PRV;
        pubType = SeosCryptoKey_Type_DH_PUB;
        break;
    case SeosCryptoKey_PairType_RSA:
        prvType = SeosCryptoKey_Type_RSA_PRV;
        pubType = SeosCryptoKey_Type_RSA_PUB;
        break;
    case SeosCryptoKey_PairType_SECP256R1:
        prvType = SeosCryptoKey_Type_SECP256R1_PRV;
        pubType = SeosCryptoKey_Type_SECP256R1_PUB;
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    if (((retval = initImpl(prvKey, memIf, prvType, prvFlags,
                            bits)) == SEOS_SUCCESS)
        && ((retval = initImpl(pubKey, memIf, pubType, pubFlags,
                               bits)) == SEOS_SUCCESS))
    {
        if ((retval = genPairImpl(prvKey, pubKey, rng)) != SEOS_SUCCESS)
        {
            freeImpl(prvKey, memIf);
            freeImpl(pubKey, memIf);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoKey_import(SeosCryptoKey*             self,
                     const SeosCrypto_MemIf*    memIf,
                     const SeosCryptoKey*       wrapKey,
                     const SeosCryptoKey_Type   type,
                     const SeosCryptoKey_Flags  flags,
                     const void*                keyBytes,
                     const size_t               keySize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    size_t bits;

    if (NULL == self ||  NULL == memIf || SEOS_SUCCESS != checkFlags(flags)
        || NULL == keyBytes || 0 == keySize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if ((bits = getEffectiveKeylength(type, keyBytes)) == 0)
    {
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    if ((retval = initImpl(self, memIf, type, flags, bits)) == SEOS_SUCCESS)
    {
        if ((retval = importImpl(self, wrapKey, keyBytes, keySize)) != SEOS_SUCCESS)
        {
            freeImpl(self, memIf);
        }
    }

    return retval;
}

seos_err_t
SeosCryptoKey_export(SeosCryptoKey*           self,
                     const SeosCryptoKey*     wrapKey,
                     SeosCryptoKey_Type*      type,
                     SeosCryptoKey_Flags*     flags,
                     void*                  buf,
                     size_t*                bufSize)
{
    if (NULL == self || NULL == type || NULL == flags || NULL == buf
        || NULL == bufSize || 0 == *bufSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!(self->flags & SeosCryptoKey_Flags_EXPORTABLE_RAW))
    {
        return SEOS_ERROR_ACCESS_DENIED;
    }
    else if (NULL != wrapKey)
    {
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return exportImpl(self, wrapKey, type, flags, buf, bufSize);
}

seos_err_t
SeosCryptoKey_free(SeosCryptoKey*             self,
                   const SeosCrypto_MemIf*    memIf)
{
    if (NULL == memIf || NULL == self || NULL == self->keyBytes)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoKey_writeRSAPub(const SeosCryptoKey* key,
                          mbedtls_rsa_context* rsa)
{
    SeosCryptoKey_RSAPub* pubKey;
    return (pubKey = SeosCryptoKey_getRSAPub(key)) == NULL
           || (mbedtls_rsa_import_raw(rsa,
                                      pubKey->nBytes, pubKey->nLen,
                                      NULL, 0, NULL, 0, NULL, 0,
                                      pubKey->eBytes, pubKey->eLen) != 0)
           || (mbedtls_rsa_complete(rsa) != 0)
           || (mbedtls_rsa_check_pubkey(rsa) != 0) ?
           SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
}

seos_err_t
SeosCryptoKey_writeRSAPrv(const SeosCryptoKey* key,
                          mbedtls_rsa_context* rsa)
{
    SeosCryptoKey_RSAPrv* prvKey;

    return (prvKey = SeosCryptoKey_getRSAPrv(key)) == NULL
           || (mbedtls_rsa_import_raw(rsa,
                                      NULL, 0,
                                      prvKey->pBytes, prvKey->pLen,
                                      prvKey->qBytes, prvKey->qLen,
                                      prvKey->dBytes, prvKey->dLen,
                                      prvKey->eBytes, prvKey->eLen) != 0)
           || (mbedtls_rsa_complete(rsa) != 0)
           || (mbedtls_rsa_check_privkey(rsa) != 0) ?
           SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
}

seos_err_t
SeosCryptoKey_writeDHPub(const SeosCryptoKey* key,
                         mbedtls_dhm_context* dh)
{
    SeosCryptoKey_DHPub* dhKey;
    return (dhKey = SeosCryptoKey_getDHPub(key)) == NULL
           || mbedtls_mpi_read_binary(&dh->GY, dhKey->gxBytes, dhKey->gxLen) != 0
           || checkDhRange(&dh->GY, &dh->P) != 0 ?
           SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
}

seos_err_t
SeosCryptoKey_writeDHPrv(const SeosCryptoKey* key,
                         mbedtls_dhm_context* dh)
{
    SeosCryptoKey_DHPrv* dhKey;
    return (dhKey = SeosCryptoKey_getDHPrv(key)) == NULL
           || mbedtls_mpi_read_binary(&dh->P, dhKey->pBytes, dhKey->pLen) != 0
           || mbedtls_mpi_read_binary(&dh->G, dhKey->gBytes, dhKey->gLen) != 0
           || mbedtls_mpi_read_binary(&dh->X, dhKey->xBytes, dhKey->xLen) != 0
           || checkDhRange(&dh->X, &dh->P) != 0 ?
           SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
}

seos_err_t
SeosCryptoKey_writeSECP256r1Pub(const SeosCryptoKey*    key,
                                mbedtls_ecdh_context* ecdh)
{
    SeosCryptoKey_SECP256r1Pub* ecKey;
    return  (ecKey = SeosCryptoKey_getSECP256r1Pub(key)) == NULL
            || mbedtls_mpi_read_binary(&ecdh->Qp.X, ecKey->qxBytes, ecKey->qxLen) != 0
            || mbedtls_mpi_read_binary(&ecdh->Qp.Y, ecKey->qyBytes, ecKey->qyLen) != 0
            || mbedtls_mpi_lset(&ecdh->Qp.Z, 1) != 0
            || mbedtls_ecp_check_pubkey(&ecdh->grp, &ecdh->Qp) != 0 ?
            SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
}

seos_err_t
SeosCryptoKey_writeSECP256r1Prv(const SeosCryptoKey*    key,
                                mbedtls_ecdh_context* ecdh)
{
    SeosCryptoKey_SECP256r1Prv* ecKey;
    return (ecKey = SeosCryptoKey_getSECP256r1Prv(key)) == NULL
           || mbedtls_ecp_group_load(&ecdh->grp, MBEDTLS_ECP_DP_SECP256R1) != 0
           || mbedtls_mpi_read_binary(&ecdh->d, ecKey->dBytes, ecKey->dLen) != 0
           || mbedtls_ecp_check_privkey(&ecdh->grp, &ecdh->d) != 0 ?
           SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
}