/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoRpc_Impl.h
 *
 * @brief RPC server data structures and constants
 *
 */

#pragma once

#include "SeosCryptoCtx.h"
#include "compiler.h"

#include <sys/user.h>

// Data is returned via the dataport buffer of the RPC server. For now, we
// only return one array (at most), so the size of the returned array is written
// to the dataport buffer, followed by the actual data.
#define DATAPORT_BUFFER_SIZE  (PAGE_SIZE - sizeof(size_t))

typedef struct
{
    /**
     * crypto context to be used by the RPC object
     */
    SeosCryptoCtx*  seosCryptoApi;
    /**
     * the server's address of the dataport shared with the client
     */
    void*           serverDataport;
}
SeosCryptoRpc;

typedef SeosCryptoRpc* SeosCryptoRpc_Handle;

INLINE void*
get_dataport_buf_ptr(SeosCryptoRpc* self)
{
    return self->serverDataport + sizeof(size_t);
}

INLINE void*
get_dataport_len_ptr(SeosCryptoRpc* self)
{
    return self->serverDataport;
}

/** @} */