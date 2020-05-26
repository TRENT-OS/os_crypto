/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "util/PtrVector.h"

// -1 = not found
size_t
PtrVector_find(
    PtrVector*  v,
    const void* obj)
{
    size_t vectorSize = PointerVector_getSize(v);

    for (size_t i = 0; i < vectorSize; i++)
    {
        if (obj == PointerVector_getElementAt(v, i))
        {
            return i;
        }
    }
    return -1;
}

bool
PtrVector_hasPtr(
    PtrVector*  v,
    const void* obj)
{
    return (obj == NULL) ? false : PtrVector_find(v, obj) != -1;
}

OS_Error_t
PtrVector_remove(
    PtrVector*  v,
    const void* obj)
{
    size_t pos;

    if ((pos = PtrVector_find(v, obj)) == -1)
    {
        return SEOS_ERROR_NOT_FOUND;
    }

    PointerVector_replaceElementAt(v, pos, PointerVector_getBack(v));
    PointerVector_popBack(v);

    return SEOS_SUCCESS;
}

OS_Error_t
PtrVector_add(
    PtrVector* v,
    void*      obj)
{
    return !PointerVector_pushBack(v, obj) ?
           SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_SUCCESS;
}

void
PtrVector_free(
    PtrVector* v)
{
    PointerVector_dtor(v);
}

OS_Error_t
PtrVector_init(
    PtrVector* v)
{
    return !PointerVector_ctor(v, 1) ? SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_SUCCESS;
}