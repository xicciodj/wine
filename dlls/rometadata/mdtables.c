/*
 * IMetaDataTables implementation
 *
 * Copyright 2025 Vibhav Pant
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define COBJMACROS
#include "objbase.h"
#include "cor.h"
#include "rometadataapi.h"
#include "wine/debug.h"

#include "rometadatapriv.h"

WINE_DEFAULT_DEBUG_CHANNEL(rometadata);

struct metadata_tables
{
    IMetaDataTables IMetaDataTables_iface;
    LONG ref;
};

static inline struct metadata_tables *impl_from_IMetaDataTables(IMetaDataTables *iface)
{
    return CONTAINING_RECORD(iface, struct metadata_tables, IMetaDataTables_iface);
}

static HRESULT WINAPI tables_QueryInterface(IMetaDataTables *iface, REFIID iid, void **out)
{
    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(&IID_IUnknown, iid) || IsEqualGUID(&IID_IMetaDataTables, iid))
    {
        IMetaDataTables_AddRef((*out = iface));
        return S_OK;
    }

    FIXME("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    return E_NOINTERFACE;
}

static ULONG WINAPI tables_AddRef(IMetaDataTables *iface)
{
    struct metadata_tables *impl = impl_from_IMetaDataTables(iface);
    ULONG ref = InterlockedIncrement(&impl->ref);

    TRACE("(%p)\n", impl);

    return ref;
}

static ULONG WINAPI tables_Release(IMetaDataTables *iface)
{
    struct metadata_tables *impl = impl_from_IMetaDataTables(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    TRACE("(%p)\n", iface);

    if (!ref) free(impl);
    return ref;
}

static HRESULT WINAPI tables_GetStringHeapSize(IMetaDataTables *iface, ULONG *size)
{
    FIXME("(%p, %p): stub!\n", iface, size);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetBlobHeapSize(IMetaDataTables *iface, ULONG *size)
{
    FIXME("(%p, %p): stub!\n", iface, size);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetGuidHeapSize(IMetaDataTables *iface, ULONG *size)
{
    FIXME("(%p, %p): stub!\n", iface, size);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetUserStringHeapSize(IMetaDataTables *iface, ULONG *size)
{
    FIXME("(%p, %p): stub!\n", iface, size);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetNumTables(IMetaDataTables *iface, ULONG *size)
{
    FIXME("(%p, %p): stub!\n", iface, size);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetTableIndex(IMetaDataTables *iface, ULONG token, ULONG *idx)
{
    FIXME("(%p %lu %p): stub!\n", iface, token, idx);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetTableInfo(IMetaDataTables *iface, ULONG idx_tbl, ULONG *row_size, ULONG *num_rows,
                                          ULONG *num_cols, ULONG *idx_key, const char **name)
{
    FIXME("(%p, %lu, %p, %p, %p, %p, %p): stub!\n", iface, idx_tbl, row_size, num_rows, num_cols, idx_key, name);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetColumnInfo(IMetaDataTables *iface, ULONG idx_tbl, ULONG idx_col, ULONG *offset,
                                           ULONG *col_size, ULONG *type, const char **name)
{
    FIXME("(%p, %lu, %lu, %p, %p, %p, %p) stub!\n", iface, idx_tbl, idx_col, offset, col_size, type, name);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetCodedTokenInfo(IMetaDataTables *iface, ULONG type, ULONG *tokens_len,
                                               const ULONG **tokens, const char **name)
{
    FIXME("(%p, %lu, %p, %p, %p) stub!\n", iface, type, tokens_len, tokens, name);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetRow(IMetaDataTables *iface, ULONG idx_tbl, ULONG idx_row, const BYTE *row)
{
    FIXME("(%p, %lu, %lu, %p): stub!\n", iface, idx_tbl, idx_row, row);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetColumn(IMetaDataTables *iface, ULONG idx_tbl, ULONG idx_col, ULONG idx_row, ULONG *val)
{
    FIXME("(%p, %lu, %lu, %lu, %p): stub!\n", iface, idx_tbl, idx_col, idx_row, val);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetString(IMetaDataTables *iface, ULONG idx, const char **str)
{
    FIXME("(%p, %lu, %p): stub!\n", iface, idx, str);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetBlob(IMetaDataTables *iface, ULONG idx, ULONG *size, const BYTE **blob)
{
    FIXME("(%p, %lu, %p, %p): stub!\n", iface, idx, size, blob);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetGuid(IMetaDataTables *iface, ULONG idx, const GUID **guid)
{
    FIXME("(%p, %lu, %p): stub!\n", iface, idx, guid);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetUserString(IMetaDataTables *iface, ULONG idx, ULONG *size, const BYTE **string)
{
    FIXME("%p %lu %p %p stub!\n", iface, idx, size, string);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetNextString(IMetaDataTables *iface, ULONG idx, ULONG *next)
{
    FIXME("(%p, %lu, %p): stub!\n", iface, idx, next);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetNextBlob(IMetaDataTables *iface, ULONG idx, ULONG *next)
{
    FIXME("(%p, %lu, %p): stub!\n", iface, idx, next);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetNextGuid(IMetaDataTables *iface, ULONG idx, ULONG *next)
{
    FIXME("(%p, %lu, %p): stub!\n", iface, idx, next);
    return E_NOTIMPL;
}

static HRESULT WINAPI tables_GetNextUserString(IMetaDataTables *iface, ULONG idx, ULONG *next)
{
    FIXME("(%p, %lu, %p): stub!\n", iface, idx, next);
    return E_NOTIMPL;
}

static const struct IMetaDataTablesVtbl tables_vtbl =
{
    tables_QueryInterface,
    tables_AddRef,
    tables_Release,
    tables_GetStringHeapSize,
    tables_GetBlobHeapSize,
    tables_GetGuidHeapSize,
    tables_GetUserStringHeapSize,
    tables_GetNumTables,
    tables_GetTableIndex,
    tables_GetTableInfo,
    tables_GetColumnInfo,
    tables_GetCodedTokenInfo,
    tables_GetRow,
    tables_GetColumn,
    tables_GetString,
    tables_GetBlob,
    tables_GetGuid,
    tables_GetUserString,
    tables_GetNextString,
    tables_GetNextBlob,
    tables_GetNextGuid,
    tables_GetNextUserString,
};

HRESULT IMetaDataTables_create(IMetaDataTables **iface)
{
    struct metadata_tables *impl;

    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;
    impl->IMetaDataTables_iface.lpVtbl = &tables_vtbl;
    impl->ref = 1;
    *iface = &impl->IMetaDataTables_iface;
    return S_OK;
}
