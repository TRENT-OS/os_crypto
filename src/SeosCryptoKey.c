/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoKey.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private static functions ----------------------------------------------------

// /*
//  * Verify sanity of parameter with regards to P
//  *
//  * Parameter should be: 2 <= public_param <= P - 2
//  *
//  * This means that we need to return an error if
//  *              public_param < 2 or public_param > P-2
//  *
//  * For more information on the attack, see:
//  *  http://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf
//  *  http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-2643
//  */
// static int dhm_check_range( const mbedtls_mpi* param, const mbedtls_mpi* P )
// {
//     mbedtls_mpi L, U;
//     int ret = 0;

//     mbedtls_mpi_init( &L );
//     mbedtls_mpi_init( &U );

//     MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &L, 2 ) );
//     MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &U, P, 2 ) );

//     if ( mbedtls_mpi_cmp_mpi( param, &L ) < 0 ||
//          mbedtls_mpi_cmp_mpi( param, &U ) > 0 )
//     {
//         ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
//     }

// cleanup:
//     mbedtls_mpi_free( &L );
//     mbedtls_mpi_free( &U );
//     return ( ret );
// }

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

static void zeroize( void* buf, size_t len )
{
    if ( len > 0 )
    {
        memset_func( buf, 0, len );
    }
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoKey_init(SeosCrypto_MemIf*            memIf,
                   SeosCryptoKey*               self,
                   unsigned int                 type,
                   SeosCryptoKey_Flag           flags,
                   size_t                       bits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    size_t keySize;

    Debug_ASSERT_SELF(self);
    Debug_PRINTF("\n%s\n", __func__);

    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (type)
    {
    case SeosCryptoKey_Type_AES:
        if (!(128 == bits || 192 == bits || 256 == bits))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_AES);
        break;
    case SeosCryptoKey_Type_RSA_PRIVATE:
        if (!(1024 == bits || 2048 == bits || 4096 == bits))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_RSA_PRIVATE);
        break;
    case SeosCryptoKey_Type_RSA_PUBLIC:
        if (!(1024 == bits || 2048 == bits || 4096 == bits))
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        keySize = sizeof(SeosCryptoKey_RSA_PUBLIC);
        break;
    case SeosCryptoKey_Type_DH_PRIVATE:
    case SeosCryptoKey_Type_DH_PUBLIC:
    case SeosCryptoKey_Type_EC_SECP256R1_PRIVATE:
    case SeosCryptoKey_Type_EC_SECP256R1_PUBLIC:
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    if ((self->raw = memIf->malloc(keySize)) != NULL)
    {
        retval = SEOS_SUCCESS;
        zeroize(self->raw, self->rawSize);
        self->rawSize = keySize;
        self->type = type;
        self->bits = bits;
        self->flags = flags;
    }
    else
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return retval;
}

seos_err_t
SeosCryptoKey_generate(SeosCryptoKey*      self)
{
    Debug_ASSERT_SELF(self);
    Debug_PRINTF("\n%s\n", __func__);
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_generatePair(SeosCryptoKey*  prvKey,
                           SeosCryptoKey*  pubKey)
{
    Debug_ASSERT_SELF(prvKey);
    Debug_ASSERT_SELF(pubKey);
    Debug_PRINTF("\n%s\n", __func__);
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_import(SeosCryptoKey*        self,
                     const void*           key,
                     size_t                keySize)
{
    Debug_ASSERT_SELF(self);
    Debug_PRINTF("\n%s\n", __func__);

    if (NULL == self || NULL == self->raw || 0 == self->rawSize || NULL == key
        || 0 == keySize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if (keySize > self->rawSize)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->raw, key, keySize);

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoKey_export(SeosCryptoKey*        self,
                     void**                key,
                     size_t*               keySize)
{
    Debug_ASSERT_SELF(self);
    Debug_PRINTF("\n%s\n", __func__);

    if (NULL == self || NULL == self->raw || 0 == self->rawSize || NULL == key
        || NULL == keySize || 0 == keySize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL == *key)
    {
        *key = self->raw;
    }
    else
    {
        if (*keySize < self->rawSize)
        {
            return SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(*key, self->raw, self->rawSize);
    }

    *keySize = self->rawSize;

    return SEOS_SUCCESS;
}

void
SeosCryptoKey_deInit(SeosCrypto_MemIf*          memIf,
                     SeosCryptoKey*             self)
{
    Debug_ASSERT_SELF(self);
    Debug_PRINTF("\n%s\n", __func__);

    if (NULL != self->raw)
    {
        // We may have stored sensitive key data here, better make sure
        // to remove it.
        zeroize(self->raw, self->rawSize);
        if (NULL != memIf)
        {
            memIf->free(self->raw);
        }
    }
}

SeosCryptoKey_RSA_PUBLIC*
SeosCryptoKey_getRsaPublic(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_RSA_PUBLIC*) key->raw;
}

SeosCryptoKey_RSA_PRIVATE*
SeosCryptoKey_getRsaPrivate(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_RSA_PRIVATE*) key->raw;
}

SeosCryptoKey_AES*
SeosCryptoKey_getAES(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_AES*) key->raw;
}

// seos_err_t
// SeosCryptoKey_init(SeosCryptoKey*   self,
//                    void*            algKeyCtx,
//                    unsigned         algorithm,
//                    BitMap32         flags,
//                    void*            bytes,
//                    size_t           lenBits)
// {
//     Debug_ASSERT_SELF(self);

//     Debug_LOG_TRACE("%s: algorithm -> %d, flags -> %x, lenBits -> %zu",
//                     __func__, algorithm, flags, lenBits);

//     seos_err_t retval = SEOS_ERROR_GENERIC;

//     if (NULL == bytes || 0 == lenBits)
//     {
//         retval = SEOS_ERROR_INVALID_PARAMETER;
//     }
//     else
//     {
//         memset(self, 0, sizeof(*self));

//         switch (algorithm)
//         {
//         default:
//             self->algoKeyCtx    = algKeyCtx;
//             self->flags         = flags;
//             self->algorithm     = algorithm;
//             self->bytes         = bytes;
//             self->lenBits       = lenBits;

//             retval = SEOS_SUCCESS;

//             break;
//         }
//     }
//     return retval;
// }

// seos_err_t
// SeosCryptoKey_initDhPublic(SeosCryptoKey*   self,
//                            void*            algoKeyCtx,
//                            const void*      p,
//                            size_t           lenP,
//                            const void*      g,
//                            size_t           lenG,
//                            const void*      gy,
//                            size_t           lenGY)
// {
//     mbedtls_dhm_context* dh = (mbedtls_dhm_context*) algoKeyCtx;

//     if (NULL == self || NULL == dh || NULL == p || NULL == g || NULL == gy)
//     {
//         return SEOS_ERROR_INVALID_PARAMETER;
//     }

//     // Set DH group params and public part of the key; make sure the key is
//     // in range 2 < GY < P-2
//     if (   mbedtls_mpi_read_binary(&dh->P,  p,  lenP)  != 0
//            || mbedtls_mpi_read_binary(&dh->G,  g,  lenG)  != 0
//            || mbedtls_mpi_read_binary(&dh->GY, gy, lenGY) != 0
//            || dhm_check_range(&dh->GY, &dh->P) != 0)
//     {
//         return SEOS_ERROR_ABORTED;
//     }

//     memset(self, 0, sizeof(*self));
//     self->lenBits    = mbedtls_mpi_size(&dh->P) * CHAR_BIT;
//     self->algoKeyCtx = algoKeyCtx;
//     self->algorithm  = SeosCryptoAgreement_Algorithm_DH;

//     return SEOS_SUCCESS;
// }

// seos_err_t
// SeosCryptoKey_initDhPrivate(SeosCryptoKey*    self,
//                             void*             algoKeyCtx,
//                             const void*       p,
//                             size_t            lenP,
//                             const void*       g,
//                             size_t            lenG,
//                             const void*       x,
//                             size_t            lenX)
// {
//     mbedtls_dhm_context* dh    = (mbedtls_dhm_context*) algoKeyCtx;

//     if (NULL ==  self || NULL == dh || NULL == p || NULL == g || NULL == x)
//     {
//         return SEOS_ERROR_INVALID_PARAMETER;
//     }

//     // Set DH group params and private part of the key; make sure the key is
//     // in range 2 < X < P-2
//     if (mbedtls_mpi_read_binary(&dh->P, p, lenP) != 0
//         || mbedtls_mpi_read_binary(&dh->G, g, lenG) != 0
//         || mbedtls_mpi_read_binary(&dh->X, x, lenX) != 0
//         || dhm_check_range(&dh->X, &dh->P) != 0)
//     {
//         return SEOS_ERROR_ABORTED;
//     }

//     memset(self, 0, sizeof(*self));
//     self->lenBits    = mbedtls_mpi_size(&dh->P) * CHAR_BIT;
//     self->algoKeyCtx = algoKeyCtx;
//     self->algorithm  = SeosCryptoAgreement_Algorithm_DH;

//     return SEOS_SUCCESS;
// }

// seos_err_t
// SeosCryptoKey_initEcdhPrivate(SeosCryptoKey*     self,
//                               void*              algoKeyCtx,
//                               unsigned int       curveId,
//                               const void*        d,
//                               size_t             lenD)
// {
//     mbedtls_ecp_keypair* ecp = (mbedtls_ecp_keypair*) algoKeyCtx;

//     if (NULL == self || NULL == ecp || NULL == d)
//     {
//         return SEOS_ERROR_INVALID_PARAMETER;
//     }

//     // Set the group (based on internal mbedTLS curve id) and the scalar
//     // we use as secret key.
//     if (mbedtls_ecp_group_load(&ecp->grp, curveId) != 0
//         || mbedtls_mpi_read_binary(&ecp->d, d, lenD) != 0)
//     {
//         return SEOS_ERROR_ABORTED;
//     }

//     memset(self, 0, sizeof(*self));
//     self->lenBits    = mbedtls_mpi_size(&ecp->grp.P) * CHAR_BIT;
//     self->algoKeyCtx = algoKeyCtx;
//     self->algorithm  = SeosCryptoAgreement_Algorithm_ECDH;

//     return SEOS_SUCCESS;
// }

// seos_err_t
// SeosCryptoKey_initEcdhPublic(SeosCryptoKey*    self,
//                              void*             algoKeyCtx,
//                              unsigned int      curveId,
//                              const void*       qX,
//                              size_t            lenQX,
//                              const void*       qY,
//                              size_t            lenQY)
// {
//     mbedtls_ecp_keypair* ecp = (mbedtls_ecp_keypair*) algoKeyCtx;

//     if (NULL == self || NULL == ecp || NULL == qX || NULL == qY)
//     {
//         return SEOS_ERROR_INVALID_PARAMETER;
//     }

//     // Set the group (based on internal mbedTLS curve id) and the X, Y and Z
//     // coordinates of the point Q, which represents the public key. Finally,
//     // also make sure that the point is ACTUALLY on the curve..
//     if (mbedtls_ecp_group_load(&ecp->grp, curveId) != 0
//         || mbedtls_mpi_read_binary(&ecp->Q.X, qX, lenQX) != 0
//         || mbedtls_mpi_read_binary(&ecp->Q.Y, qY, lenQY) != 0
//         || mbedtls_mpi_lset(&ecp->Q.Z, 1) != 0
//         || mbedtls_ecp_check_pubkey(&ecp->grp, &ecp->Q) != 0)
//     {
//         return SEOS_ERROR_ABORTED;
//     }

//     memset(self, 0, sizeof(*self));
//     self->lenBits    = mbedtls_mpi_size(&ecp->grp.P) * CHAR_BIT;
//     self->algoKeyCtx = algoKeyCtx;
//     self->algorithm  = SeosCryptoAgreement_Algorithm_ECDH;

//     return SEOS_SUCCESS;
// }

// seos_err_t
// SeosCryptoKey_initRsaPublic(SeosCryptoKey*  self,
//                             void*           algoKeyCtx,
//                             const void*     n,
//                             size_t          lenN,
//                             const void*     e,
//                             size_t          lenE)
// {
//     Debug_ASSERT_SELF(self);

//     seos_err_t retval           = SEOS_ERROR_GENERIC;
//     mbedtls_rsa_context* rsa    = (mbedtls_rsa_context*) algoKeyCtx;

//     if (NULL == rsa || NULL == n || NULL == e)
//     {
//         retval = SEOS_ERROR_INVALID_PARAMETER;
//     }
//     else
//     {
//         memset(self, 0, sizeof(*self));

//         if (mbedtls_rsa_import_raw(rsa,
//                                    n, lenN,
//                                    NULL, 0,
//                                    NULL, 0,
//                                    NULL, 0,
//                                    NULL, 0) != 0
//             || mbedtls_rsa_import_raw(rsa,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       e, lenE) != 0
//             || mbedtls_rsa_complete(rsa) != 0
//             || mbedtls_rsa_check_pubkey(rsa) != 0)
//         {
//             Debug_LOG_ERROR("%s: failed creating public RSA key", __func__);
//             retval = SEOS_ERROR_ABORTED;
//         }
//         else
//         {
//             self->algoKeyCtx = algoKeyCtx;
//             self->algorithm  = SeosCryptoSignature_Algorithm_RSA_PKCS1;
//             self->lenBits   = rsa->len * CHAR_BIT;

//             retval = SEOS_SUCCESS;
//         }
//     }
//     return retval;
// }

// seos_err_t
// SeosCryptoKey_initRsaPrivate(SeosCryptoKey* self,
//                              void*          algoKeyCtx,
//                              const void*    n,
//                              size_t         lenN,
//                              const void*    e,
//                              size_t         lenE,
//                              const void*    d,
//                              size_t         lenD,
//                              const void*    p,
//                              size_t         lenP,
//                              const void*    q,
//                              size_t         lenQ)
// {
//     Debug_ASSERT_SELF(self);

//     seos_err_t retval           = SEOS_ERROR_GENERIC;
//     mbedtls_rsa_context* rsa    = (mbedtls_rsa_context*) algoKeyCtx;

//     if (NULL == rsa || NULL == n || NULL == e)
//     {
//         retval = SEOS_ERROR_INVALID_PARAMETER;
//     }
//     else
//     {
//         memset(self, 0, sizeof(*self));

//         if (mbedtls_rsa_import_raw(rsa,
//                                    n, lenN,
//                                    NULL, 0,
//                                    NULL, 0,
//                                    NULL, 0,
//                                    NULL, 0) != 0
//             || mbedtls_rsa_import_raw(rsa,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       e, lenE) != 0
//             || mbedtls_rsa_import_raw(rsa,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       d, lenD,
//                                       NULL, 0)
//             || mbedtls_rsa_import_raw(rsa,
//                                       NULL, 0,
//                                       p, lenP,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       NULL, 0)
//             || mbedtls_rsa_import_raw(rsa,
//                                       NULL, 0,
//                                       NULL, 0,
//                                       q, lenQ,
//                                       NULL, 0,
//                                       NULL, 0 )
//             || mbedtls_rsa_complete(rsa) != 0
//             || mbedtls_rsa_check_privkey(rsa) != 0)
//         {
//             retval = SEOS_ERROR_ABORTED;
//         }
//         else
//         {
//             self->algoKeyCtx = algoKeyCtx;
//             self->algorithm  = SeosCryptoSignature_Algorithm_RSA_PKCS1;
//             self->lenBits   = rsa->len * CHAR_BIT;

//             retval = SEOS_SUCCESS;
//         }
//     }
//     return retval;
// }

// void
// SeosCryptoKey_deInit(SeosCryptoKey* self)
// {
//     Debug_ASSERT_SELF(self);

//     if (BitMap_GET_BIT(self->flags, SeosCryptoKey_Flags_IS_ALGO_CIPHER))
//     {
//         memset(self, 0, sizeof(SeosCryptoKey));
//     }
//     else
//     {
//         switch (self->algorithm)
//         {
//         case SeosCryptoSignature_Algorithm_RSA_PKCS1:
//             mbedtls_rsa_free((mbedtls_rsa_context*) self->algoKeyCtx);
//             break;

//         default:
//             Debug_ASSERT(false);
//             break;
//         }
//     }
// }