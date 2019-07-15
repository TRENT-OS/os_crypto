/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStore.h"

/* Defines -------------------------------------------------------------------*/

/* Private functions prototypes ----------------------------------------------*/

/* Private variables ---------------------------------------------------------*/

/* Public functions ----------------------------------------------------------*/
bool KeyStore_ctor(SeosKeyStore* self, FileStreamFactory* fileStreamFactory,
                   size_t numOfFiles)
{
    self->fsFactory = fileStreamFactory;
    self->numOfFiles = numOfFiles;

    return SEOS_SUCCESS;
}

void KeyStore_dtor(SeosKeyStore* self)
{
    Debug_ASSERT_SELF(self);
}

seos_err_t KeyStore_createKey(SeosKeyStore* self, SeosCryptoKey* key,
                              const char* name)
{
    return SEOS_SUCCESS;
}

seos_err_t KeyStore_importKey(SeosKeyStore* self, SeosCryptoKey key)
{
    return SEOS_SUCCESS;
}

seos_err_t KeyStore_getKey(SeosKeyStore* self, SeosCryptoKey* key,
                           const char* name)
{
    return SEOS_SUCCESS;
}

seos_err_t KeyStore_updateKey(SeosKeyStore* self, SeosCryptoKey* key)
{
    return SEOS_SUCCESS;
}

seos_err_t KeyStore_deleteKey(SeosKeyStore* self, const char* name)
{
    return SEOS_SUCCESS;
}

/* Private functions ---------------------------------------------------------*/
