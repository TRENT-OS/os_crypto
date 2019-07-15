/**
 * @addtogroup SEOS
 * @{
 *
 * @file SeosKeyStore.h
 *
 * @brief a class that implements key storage functions for SEOS.
 *
 * @author Leonard Blazevic
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#if !defined(SEOS_KEY_STORE_H)
#define SEOS_KEY_STORE_H

/* Includes ------------------------------------------------------------------*/
#include "seos_err.h"
#include "SeosCryptoKey.h"
#include "LibIO/FileStream.h"
#include "LibIO/FileStreamFactory.h"

/* Exported macro ------------------------------------------------------------*/

/* Exported types ------------------------------------------------------------*/
typedef struct SeosKeyStore SeosKeyStore;

struct SeosKeyStore
{
    FileStreamFactory* fsFactory;
    size_t numOfFiles;
};

/* Exported constants --------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
/**
 * @brief Constructor
 *
 * @return true if success
 *
 */
bool KeyStore_ctor(SeosKeyStore* self, FileStreamFactory* fileStreamFactory,
                   size_t numOfFiles);
void KeyStore_dtor(SeosKeyStore* self);
seos_err_t KeyStore_createKey(SeosKeyStore* self, SeosCryptoKey* key,
                              const char* name);
seos_err_t KeyStore_importKey(SeosKeyStore* self, SeosCryptoKey key);
seos_err_t KeyStore_getKey(SeosKeyStore* self, SeosCryptoKey* key,
                           const char* name);
seos_err_t KeyStore_updateKey(SeosKeyStore* self, SeosCryptoKey* key);
seos_err_t KeyStore_deleteKey(SeosKeyStore* self, const char* name);

#endif
///@}