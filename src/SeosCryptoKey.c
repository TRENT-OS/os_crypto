/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoKey.h"

#include "LibDebug/Debug.h"

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
genImpl(SeosCryptoKey*      self)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

static seos_err_t
genPairImpl(SeosCryptoKey*  prvKey,
            SeosCryptoKey*  pubKey)
{
    return SEOS_ERROR_NOT_SUPPORTED;
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
SeosCryptoKey_generate(SeosCryptoKey*      self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return genImpl(self);
}

seos_err_t
SeosCryptoKey_generatePair(SeosCryptoKey*  prvKey,
                           SeosCryptoKey*  pubKey)
{
    if (NULL == prvKey || NULL == pubKey)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return genPairImpl(prvKey, pubKey);
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