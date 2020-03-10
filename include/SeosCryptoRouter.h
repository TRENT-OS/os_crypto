/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file SeosCryptoRouter.h
 *
 * @brief The router instantiates the API as library AND RPC client and switches
 * between these contexts based on attributes of they key. This way, critical
 * operations will transparently be executed in an isolated component (e.g., the
 * CryptoServer) and uncritical operations will be performed locally and thus
 * faster.
 */

#pragma once

#include "SeosCryptoApi.h"

#include "SeosCryptoRpc_Client.h"
#include "SeosCryptoLib.h"

#include "util/PtrVector.h"

// Internal types/defines/enums ------------------------------------------------

typedef struct
{
    SeosCryptoApi_Impl lib;
    SeosCryptoApi_Impl client;
    SeosCryptoApi_MemIf memIf;
}
SeosCryptoRouter;

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoRouter_init(
    SeosCryptoRouter*                  self,
    const SeosCryptoVtable**           vtable,
    const SeosCryptoApi_MemIf*         memIf,
    const SeosCryptoApi_Router_Config* cfg);

seos_err_t
SeosCryptoRouter_free(
    SeosCryptoRouter* self);

/** @} */