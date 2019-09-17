/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoKey.h"
#include "SeosCryptoRng.h"

#include "LibDebug/Debug.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"

#include <string.h>

// Private static functions ----------------------------------------------------

/*
 * This implementation should never be optimized out by the compiler
 *
 * This implementation for mbedtls_platform_zeroize() was inspired from
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
zeroize( void* buf, size_t len )
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
static int dhm_check_range(const mbedtls_mpi* param, const mbedtls_mpi* P)
{
    mbedtls_mpi L, U;
    int ret = 0;

    mbedtls_mpi_init( &L );
    mbedtls_mpi_init( &U );

    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &L, 2 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &U, P, 2 ) );

    if ( mbedtls_mpi_cmp_mpi( param, &L ) < 0 ||
         mbedtls_mpi_cmp_mpi( param, &U ) > 0 )
    {
        ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }

cleanup:
    mbedtls_mpi_free( &L );
    mbedtls_mpi_free( &U );
    return ( ret );
}

static size_t
getMpiLen(const unsigned char* xVal,
          size_t xLen)
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
getEffectiveKeylength(unsigned int  type,
                      const void*   keyBytes)
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
        return getMpiLen(key->nBytes, key->nLen);
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
initImpl(SeosCrypto_MemIf*            memIf,
         SeosCryptoKey*               self)
{
    size_t keySize;

    switch (self->type)
    {
    case SeosCryptoKey_Type_AES:
        if (!((128 == self->bits) || (192 == self->bits) || (256 == self->bits)))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_AES);
        break;
    case SeosCryptoKey_Type_RSA_PRV:
        if (self->bits > (SeosCryptoKey_Size_RSA_PRV * 8) || self->bits < 128)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_RSAPrv);
        break;
    case SeosCryptoKey_Type_RSA_PUB:
        if (self->bits > (SeosCryptoKey_Size_RSA_PUB * 8) || self->bits < 128)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_RSAPub);
        break;
    case SeosCryptoKey_Type_DH_PRV:
        if (self->bits > (SeosCryptoKey_Size_DH_PRV * 8))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_DHPrv);
        break;
    case SeosCryptoKey_Type_DH_PUB:
        if (self->bits > (SeosCryptoKey_Size_DH_PUB * 8))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_DHPub);
        break;
    case SeosCryptoKey_Type_SECP256R1_PRV:
        if (self->bits != (SeosCryptoKey_Size_SECP256R1_PRV * 8))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_SECP256r1Prv);
        break;
    case SeosCryptoKey_Type_SECP256R1_PUB:
        if (self->bits != (SeosCryptoKey_Size_SECP256R1_PUB * 8))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_SECP256r1Pub);
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    self->keySize = keySize;
    return (self->keyBytes = memIf->malloc(self->keySize)) != NULL ?
           SEOS_SUCCESS : SEOS_ERROR_INSUFFICIENT_SPACE;
}

static seos_err_t
deInitImpl(SeosCrypto_MemIf*            memIf,
           SeosCryptoKey*               self)
{
    // We may have stored sensitive key data here, better make sure to remove it.
    if (!self->empty)
    {
        zeroize(self->keyBytes, self->keySize);
    }
    memIf->free(self->keyBytes);

    return SEOS_SUCCESS;
}

static seos_err_t
genImpl(SeosCryptoKey*      self,
        SeosCryptoRng*      rng)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    void* ptr;

    ptr = self->keyBytes;
    self->keySize = self->bits >> 3;

    switch (self->type)
    {
    case SeosCryptoKey_Type_AES:
    {
        retval = SeosCryptoRng_getBytes(rng, &ptr, self->keySize);
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
        prvRsa->nLen = mbedtls_mpi_size(&rsa.N);
        prvRsa->qLen = mbedtls_mpi_size(&rsa.Q);
        prvRsa->pLen = mbedtls_mpi_size(&rsa.P);
        prvRsa->dLen = mbedtls_mpi_size(&rsa.D);
        retval = mbedtls_mpi_write_binary(&rsa.N, pubRsa->nBytes, pubRsa->nLen) ||
                 mbedtls_mpi_write_binary(&rsa.E, pubRsa->eBytes, pubRsa->eLen) ||
                 mbedtls_mpi_write_binary(&rsa.N, prvRsa->nBytes, prvRsa->nLen) ||
                 mbedtls_mpi_write_binary(&rsa.P, prvRsa->pBytes, prvRsa->pLen) ||
                 mbedtls_mpi_write_binary(&rsa.Q, prvRsa->qBytes, prvRsa->qLen) ||
                 mbedtls_mpi_write_binary(&rsa.D, prvRsa->dBytes, prvRsa->dLen) ?
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
    mbedtls_mpi Q, X, GX;
    void* rngFunc = SeosCryptoRng_getBytesMbedtls;
    size_t retries;

    mbedtls_dhm_init(&dh);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&GX);

    // Generate a "safe prime" P such that Q=(P-1)/2 is also prime
    retval = SEOS_ERROR_ABORTED;
    retries = 10;
    while (retries > 0)
    {
        if (mbedtls_mpi_gen_prime(&dh.P, prvKey->bits, 1, rngFunc, rng) != 0 ||
            mbedtls_mpi_sub_int(&Q, &dh.P, 1) != 0 ||
            mbedtls_mpi_div_int(&Q, NULL, &Q, 2) != 0)
        {
            break;
        }
        // The prime test is iterated; a general recommendation is to set the amount
        // of iterations to half of the security parameter, e.g., the numbe of
        // bits of prime.
        else if (mbedtls_mpi_is_prime_ext(&Q, prvKey->bits / 2, rngFunc, rng) == 0)
        {
            retval = SEOS_SUCCESS;
            break;
        }
        retries--;
        Debug_LOG_WARNING("Could not generate prime P for DH, retrying..");
    }

    if (SEOS_SUCCESS == retval)
    {
        // Generate an X as large as possible
        retval = SEOS_ERROR_ABORTED;
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

            if (dhm_check_range(&X, &dh.P) == 0)
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
            && dhm_check_range(&GX, &dh.P) == 0)
        {
            prvDh->pLen = mbedtls_mpi_size(&dh.P);
            prvDh->gLen = mbedtls_mpi_size(&dh.G);
            prvDh->xLen = mbedtls_mpi_size(&X);
            pubDh->pLen = mbedtls_mpi_size(&dh.P);
            pubDh->gLen = mbedtls_mpi_size(&dh.G);
            pubDh->yLen = mbedtls_mpi_size(&GX);
            retval = mbedtls_mpi_write_binary(&X,    prvDh->xBytes, prvDh->xLen) != 0 ||
                     mbedtls_mpi_write_binary(&GX,   pubDh->yBytes, pubDh->yLen) != 0 ||
                     mbedtls_mpi_write_binary(&dh.P, prvDh->pBytes, prvDh->pLen) != 0 ||
                     mbedtls_mpi_write_binary(&dh.G, prvDh->gBytes, prvDh->gLen) != 0 ||
                     mbedtls_mpi_write_binary(&dh.G, pubDh->gBytes, pubDh->gLen) != 0 ||
                     mbedtls_mpi_write_binary(&dh.P, pubDh->pBytes, pubDh->pLen) != 0 ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
    }

    mbedtls_mpi_free(&GX);
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Q);
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

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);

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
importImpl(SeosCryptoKey*        self,
           SeosCryptoKey*        wrapKey,
           const void*           keyBytes,
           size_t                keySize)
{
    if (NULL != wrapKey)
    {
        // Todo: Implement key unwrapping algorithm
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    memcpy(self->keyBytes, keyBytes, keySize);
    self->empty = false;

    return SEOS_SUCCESS;
}

static seos_err_t
exportImpl(SeosCryptoKey*        self,
           SeosCryptoKey*        wrapKey,
           void**                buf,
           size_t*               bufSize)
{
    if (NULL != wrapKey)
    {
        // Todo: Implement key wrapping algorithm
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    if (NULL == *buf)
    {
        *buf = self->keyBytes;
    }
    else
    {
        if (*bufSize < self->keySize)
        {
            return SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(*buf, self->keyBytes, self->keySize);
    }

    *bufSize = self->keySize;

    return SEOS_SUCCESS;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoKey_init(SeosCrypto_MemIf*            memIf,
                   SeosCryptoKey*               self,
                   unsigned int                 type,
                   SeosCryptoKey_Flag           flags,
                   size_t                       bits)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->type    = type;
    self->bits    = bits;
    self->flags   = flags;
    self->empty   = true;

    return initImpl(memIf, self);
}

seos_err_t
SeosCryptoKey_generate(SeosCryptoKey*      self,
                       SeosCryptoRng*      rng)
{
    if (NULL == self || NULL == rng)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!self->empty)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return genImpl(self, rng);
}

seos_err_t
SeosCryptoKey_generatePair(SeosCryptoKey*  prvKey,
                           SeosCryptoKey*  pubKey,
                           SeosCryptoRng*  rng)
{
    if (NULL == prvKey || NULL == pubKey || NULL == rng
        || prvKey->bits != pubKey->bits)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!prvKey->empty || !pubKey->empty)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return genPairImpl(prvKey, pubKey, rng);
}

seos_err_t
SeosCryptoKey_import(SeosCryptoKey*        self,
                     SeosCryptoKey*        wrapKey,
                     const void*           keyBytes,
                     size_t                keySize)
{
    if (NULL == self || NULL == self->keyBytes || 0 == self->keySize
        || NULL == keyBytes || 0 == keySize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    // Can we store the key (e.g. have we allocated the correct amount of bytes
    // and do we not already hold a key?)
    if (keySize != self->keySize || !self->empty)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    // Make sure the imported key has the key length the user set when he
    // instantiated the key in the first place..
    if (getEffectiveKeylength(self->type, keyBytes) != self->bits)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return importImpl(self, wrapKey, keyBytes, keySize);
}

seos_err_t
SeosCryptoKey_export(SeosCryptoKey*        self,
                     SeosCryptoKey*        wrapKey,
                     void**                buf,
                     size_t*               bufSize)
{
    if (NULL == self || NULL == self->keyBytes || 0 == self->keySize || NULL == buf
        || NULL == bufSize || 0 == bufSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    // Is there any actual key material?
    if (self->empty)
    {
        return SEOS_ERROR_NOT_FOUND;
    }
    // Can we export the key without wrapping?
    if (NULL == wrapKey && !(self->flags & SeosCryptoKey_Flags_EXPORTABLE_RAW))
    {
        return SEOS_ERROR_ACCESS_DENIED;
    }

    return exportImpl(self, wrapKey, buf, bufSize);
}

seos_err_t
SeosCryptoKey_deInit(SeosCrypto_MemIf*          memIf,
                     SeosCryptoKey*             self)
{
    if (NULL == memIf || NULL == self || NULL == self->keyBytes)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return deInitImpl(memIf, self);
}