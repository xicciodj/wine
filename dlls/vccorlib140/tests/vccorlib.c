/*
 * Unit tests for miscellaneous vccorlib functions
 *
 * Copyright 2025 Piotr Caban
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

#include <stdbool.h>

#include "initguid.h"
#include "activation.h"
#include "objbase.h"
#include "weakreference.h"
#include "wine/test.h"

#define DEFINE_EXPECT(func) \
    static BOOL expect_ ## func = FALSE; static unsigned int called_ ## func = 0

#define SET_EXPECT(func) \
    expect_ ## func = TRUE

#define CHECK_EXPECT2(func) \
    do { \
        ok(expect_ ##func, "unexpected call " #func "\n"); \
        called_ ## func++; \
    }while(0)

#define CHECK_EXPECT(func) \
    do { \
        CHECK_EXPECT2(func); \
        expect_ ## func = FALSE; \
    }while(0)

#define CHECK_CALLED(func, n) \
    do { \
        ok(called_ ## func == n, "expected " #func " called %u times, got %u\n", n, called_ ## func); \
        expect_ ## func = FALSE; \
        called_ ## func = 0; \
    }while(0)

#undef __thiscall
#ifdef __i386__

#pragma pack(push,1)
struct thiscall_thunk
{
    BYTE pop_eax;    /* popl  %eax (ret addr) */
    BYTE pop_edx;    /* popl  %edx (func) */
    BYTE pop_ecx;    /* popl  %ecx (this) */
    BYTE push_eax;   /* pushl %eax */
    WORD jmp_edx;    /* jmp  *%edx */
};
#pragma pack( pop )

static ULONG_PTR (WINAPI *call_thiscall_func1)(void *func, void *this);

static void init_thiscall_thunk(void)
{
    struct thiscall_thunk *thunk = VirtualAlloc(NULL, sizeof(*thunk), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    thunk->pop_eax  = 0x58;   /* popl  %eax */
    thunk->pop_edx  = 0x5a;   /* popl  %edx */
    thunk->pop_ecx  = 0x59;   /* popl  %ecx */
    thunk->push_eax = 0x50;   /* pushl %eax */
    thunk->jmp_edx  = 0xe2ff; /* jmp  *%edx */
    call_thiscall_func1 = (void *)thunk;
}

#define __thiscall __stdcall
#define call_func1(func,_this) call_thiscall_func1(func,_this)

#else

#define init_thiscall_thunk()
#define __thiscall __cdecl
#define call_func1(func,_this) func(_this)

#endif /* __i386__ */

#ifdef __i386__
#define __thiscall __stdcall
#else
#define __thiscall __cdecl
#endif

DEFINE_EXPECT(PreInitialize);
DEFINE_EXPECT(PostInitialize);
DEFINE_EXPECT(PreUninitialize);
DEFINE_EXPECT(PostUninitialize);

static HRESULT (__cdecl *pInitializeData)(int);
static void (__cdecl *pUninitializeData)(int);
static HRESULT (WINAPI *pGetActivationFactoryByPCWSTR)(const WCHAR *, const GUID *, void **);
static HRESULT (WINAPI *pGetIidsFn)(UINT32, UINT32 *, const GUID *, GUID **);
static void *(__cdecl *pAllocate)(size_t);
static void (__cdecl *pFree)(void *);
static void *(__cdecl *pAllocateWithWeakRef)(ptrdiff_t, size_t);
static void (__thiscall *pReleaseTarget)(void *);

static BOOL init(void)
{
    HMODULE hmod = LoadLibraryA("vccorlib140.dll");

    if (!hmod)
    {
        win_skip("vccorlib140.dll not available\n");
        return FALSE;
    }

    pInitializeData = (void *)GetProcAddress(hmod,
            "?InitializeData@Details@Platform@@YAJH@Z");
    ok(pInitializeData != NULL, "InitializeData not available\n");
    pUninitializeData = (void *)GetProcAddress(hmod,
            "?UninitializeData@Details@Platform@@YAXH@Z");
    ok(pUninitializeData != NULL, "UninitializeData not available\n");

#ifdef __arm__
    pGetActivationFactoryByPCWSTR = (void *)GetProcAddress(hmod,
            "?GetActivationFactoryByPCWSTR@@YAJPAXAAVGuid@Platform@@PAPAX@Z");
    pGetIidsFn = (void *)GetProcAddress(hmod, "?GetIidsFn@@YAJHPAKPBU__s_GUID@@PAPAVGuid@Platform@@@Z");
    pAllocate = (void *)GetProcAddress(hmod, "?Allocate@Heap@Details@Platform@@SAPAXI@Z");
    pFree = (void *)GetProcAddress(hmod, "?Free@Heap@Details@Platform@@SAXPAX@Z");
    pAllocateWithWeakRef = (void *)GetProcAddress(hmod, "?Allocate@Heap@Details@Platform@@SAPAXII@Z");
    pReleaseTarget = (void *)GetProcAddress(hmod, "?ReleaseTarget@ControlBlock@Details@Platform@@AAAXXZ");
#else
    if (sizeof(void *) == 8)
    {
        pGetActivationFactoryByPCWSTR = (void *)GetProcAddress(hmod,
                "?GetActivationFactoryByPCWSTR@@YAJPEAXAEAVGuid@Platform@@PEAPEAX@Z");
        pGetIidsFn = (void *)GetProcAddress(hmod, "?GetIidsFn@@YAJHPEAKPEBU__s_GUID@@PEAPEAVGuid@Platform@@@Z");
        pAllocate = (void *)GetProcAddress(hmod, "?Allocate@Heap@Details@Platform@@SAPEAX_K@Z");
        pFree = (void *)GetProcAddress(hmod, "?Free@Heap@Details@Platform@@SAXPEAX@Z");
        pAllocateWithWeakRef = (void *)GetProcAddress(hmod, "?Allocate@Heap@Details@Platform@@SAPEAX_K0@Z");
        pReleaseTarget = (void *)GetProcAddress(hmod, "?ReleaseTarget@ControlBlock@Details@Platform@@AEAAXXZ");
    }
    else
    {
        pGetActivationFactoryByPCWSTR = (void *)GetProcAddress(hmod,
                "?GetActivationFactoryByPCWSTR@@YGJPAXAAVGuid@Platform@@PAPAX@Z");
        pGetIidsFn = (void *)GetProcAddress(hmod, "?GetIidsFn@@YGJHPAKPBU__s_GUID@@PAPAVGuid@Platform@@@Z");
        pAllocate = (void *)GetProcAddress(hmod, "?Allocate@Heap@Details@Platform@@SAPAXI@Z");
        pFree = (void *)GetProcAddress(hmod, "?Free@Heap@Details@Platform@@SAXPAX@Z");
        pAllocateWithWeakRef = (void *)GetProcAddress(hmod, "?Allocate@Heap@Details@Platform@@SAPAXII@Z");
        pReleaseTarget = (void *)GetProcAddress(hmod, "?ReleaseTarget@ControlBlock@Details@Platform@@AAEXXZ");
    }
#endif
    ok(pGetActivationFactoryByPCWSTR != NULL, "GetActivationFactoryByPCWSTR not available\n");
    ok(pGetIidsFn != NULL, "GetIidsFn not available\n");
    ok(pAllocate != NULL, "Allocate not available\n");
    ok(pFree != NULL, "Free not available\n");
    ok(pAllocateWithWeakRef != NULL, "AllocateWithWeakRef not available\n");
    ok(pReleaseTarget != NULL, "ReleaseTarget not available\n");

    init_thiscall_thunk();

    return TRUE;
}

static HRESULT WINAPI InitializeSpy_QI(IInitializeSpy *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IInitializeSpy) || IsEqualIID(riid, &IID_IUnknown))
    {
        *obj = iface;
        IInitializeSpy_AddRef(iface);
        return S_OK;
    }

    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI InitializeSpy_AddRef(IInitializeSpy *iface)
{
    return 2;
}

static ULONG WINAPI InitializeSpy_Release(IInitializeSpy *iface)
{
    return 1;
}

static DWORD exp_coinit;
static HRESULT WINAPI InitializeSpy_PreInitialize(IInitializeSpy *iface, DWORD coinit, DWORD aptrefs)
{
    CHECK_EXPECT(PreInitialize);
    ok(coinit == exp_coinit, "coinit = %lx\n", coinit);
    return S_OK;
}

static HRESULT WINAPI InitializeSpy_PostInitialize(IInitializeSpy *iface, HRESULT hr, DWORD coinit, DWORD aptrefs)
{
    CHECK_EXPECT(PostInitialize);
    return hr;
}

static HRESULT WINAPI InitializeSpy_PreUninitialize(IInitializeSpy *iface, DWORD aptrefs)
{
    CHECK_EXPECT(PreUninitialize);
    return S_OK;
}

static HRESULT WINAPI InitializeSpy_PostUninitialize(IInitializeSpy *iface, DWORD aptrefs)
{
    CHECK_EXPECT(PostUninitialize);
    return S_OK;
}

static const IInitializeSpyVtbl InitializeSpyVtbl =
{
    InitializeSpy_QI,
    InitializeSpy_AddRef,
    InitializeSpy_Release,
    InitializeSpy_PreInitialize,
    InitializeSpy_PostInitialize,
    InitializeSpy_PreUninitialize,
    InitializeSpy_PostUninitialize
};

static IInitializeSpy InitializeSpy = { &InitializeSpyVtbl };

static void test_InitializeData(void)
{
    ULARGE_INTEGER cookie;
    HRESULT hr;

    hr = CoRegisterInitializeSpy(&InitializeSpy, &cookie);
    ok(hr == S_OK, "CoRegisterInitializeSpy returned %lx\n", hr);

    hr = pInitializeData(0);
    ok(hr == S_OK, "InitializeData returned %lx\n", hr);

    exp_coinit = COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE;
    SET_EXPECT(PreInitialize);
    SET_EXPECT(PostInitialize);
    hr = pInitializeData(1);
    ok(hr == S_OK, "InitializeData returned %lx\n", hr);
    CHECK_CALLED(PreInitialize, 1);
    CHECK_CALLED(PostInitialize, 1);

    SET_EXPECT(PreInitialize);
    SET_EXPECT(PostInitialize);
    hr = pInitializeData(1);
    ok(hr == S_OK, "InitializeData returned %lx\n", hr);
    CHECK_CALLED(PreInitialize, 1);
    CHECK_CALLED(PostInitialize, 1);

    exp_coinit = COINIT_MULTITHREADED;
    SET_EXPECT(PreInitialize);
    SET_EXPECT(PostInitialize);
    hr = pInitializeData(2);
    ok(hr == RPC_E_CHANGED_MODE, "InitializeData returned %lx\n", hr);
    CHECK_CALLED(PreInitialize, 1);
    CHECK_CALLED(PostInitialize, 1);

    pUninitializeData(0);
    SET_EXPECT(PreUninitialize);
    SET_EXPECT(PostUninitialize);
    pUninitializeData(1);
    CHECK_CALLED(PreUninitialize, 1);
    CHECK_CALLED(PostUninitialize, 1);
    SET_EXPECT(PreUninitialize);
    SET_EXPECT(PostUninitialize);
    pUninitializeData(2);
    CHECK_CALLED(PreUninitialize, 1);
    CHECK_CALLED(PostUninitialize, 1);

    SET_EXPECT(PreInitialize);
    SET_EXPECT(PostInitialize);
    hr = pInitializeData(2);
    ok(hr == S_OK, "InitializeData returned %lx\n", hr);
    CHECK_CALLED(PreInitialize, 1);
    CHECK_CALLED(PostInitialize, 1);
    SET_EXPECT(PreUninitialize);
    SET_EXPECT(PostUninitialize);
    pUninitializeData(2);
    CHECK_CALLED(PreUninitialize, 1);
    CHECK_CALLED(PostUninitialize, 1);

    SET_EXPECT(PreInitialize);
    SET_EXPECT(PostInitialize);
    hr = pInitializeData(3);
    ok(hr == S_OK, "InitializeData returned %lx\n", hr);
    CHECK_CALLED(PreInitialize, 1);
    CHECK_CALLED(PostInitialize, 1);
    SET_EXPECT(PreUninitialize);
    SET_EXPECT(PostUninitialize);
    pUninitializeData(3);
    CHECK_CALLED(PreUninitialize, 1);
    CHECK_CALLED(PostUninitialize, 1);

    hr = CoRevokeInitializeSpy(cookie);
    ok(hr == S_OK, "CoRevokeInitializeSpy returned %lx\n", hr);
}

static const GUID guid_null = {0};

static void test_GetActivationFactoryByPCWSTR(void)
{
    HRESULT hr;
    void *out;

    hr = pGetActivationFactoryByPCWSTR(L"Wine.Nonexistent.RuntimeClass", &IID_IActivationFactory, &out);
    ok(hr == CO_E_NOTINITIALIZED, "got hr %#lx\n", hr);

    hr = pInitializeData(1);
    ok(hr == S_OK, "got hr %#lx\n", hr);

    hr = pGetActivationFactoryByPCWSTR(L"Wine.Nonexistent.RuntimeClass", &IID_IActivationFactory, &out);
    ok(hr == REGDB_E_CLASSNOTREG, "got hr %#lx\n", hr);

    hr = pGetActivationFactoryByPCWSTR(L"Windows.Foundation.Metadata.ApiInformation", &IID_IActivationFactory, &out);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    IActivationFactory_Release(out);

    hr = pGetActivationFactoryByPCWSTR(L"Windows.Foundation.Metadata.ApiInformation", &IID_IInspectable, &out);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    IActivationFactory_Release(out);

    hr = pGetActivationFactoryByPCWSTR(L"Windows.Foundation.Metadata.ApiInformation", &guid_null, &out);
    ok(hr == E_NOINTERFACE, "got hr %#lx\n", hr);

    pUninitializeData(1);
}

static void test_GetIidsFn(void)
{
    static const GUID guids_src[] = {IID_IUnknown, IID_IInspectable, IID_IAgileObject, IID_IMarshal, guid_null};
    GUID *guids_dest;
    UINT32 copied;
    HRESULT hr;

    guids_dest = NULL;
    copied = 0xdeadbeef;
    hr = pGetIidsFn(0, &copied, NULL, &guids_dest);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    ok(copied == 0, "got copied %I32u\n", copied);
    ok(guids_dest != NULL, "got guids_dest %p\n", guids_dest);
    CoTaskMemFree(guids_dest);

    guids_dest = NULL;
    copied = 0;
    hr = pGetIidsFn(ARRAY_SIZE(guids_src), &copied, guids_src, &guids_dest);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    ok(copied == ARRAY_SIZE(guids_src), "got copied %I32u\n", copied);
    ok(guids_dest != NULL, "got guids_dest %p\n", guids_dest);
    ok(!memcmp(guids_src, guids_dest, sizeof(*guids_dest) * copied), "unexpected guids_dest value.\n");
    CoTaskMemFree(guids_dest);
}

static void test_Allocate(void)
{
    void *addr;

    addr = pAllocate(0);
    ok(!!addr, "got addr %p\n", addr);
    pFree(addr);

    addr = pAllocate(sizeof(void *));
    ok(!!addr, "got addr %p\n", addr);
    pFree(addr);
    pFree(NULL);
}

#define test_refcount(a, b) test_refcount_(__LINE__, (a), (b))
static void test_refcount_(int line, void *obj, LONG val)
{
    LONG count;

    IUnknown_AddRef((IUnknown *)obj);
    count = IUnknown_Release((IUnknown *)obj);
    ok_(__FILE__, line)(count == val, "got refcount %lu != %lu\n", count, val);
}

struct control_block
{
    IWeakReference IWeakReference_iface;
    LONG ref_weak;
    LONG ref_strong;
    IUnknown *object;
    bool is_inline;
    UINT16 unknown;
#ifdef _WIN32
    char _padding[4];
#endif
};

struct unknown_impl
{
    IUnknown IUnknown_iface;
    ULONG strong_ref_free_val; /* Should be a negative value  */
    struct control_block *weakref;
};

static struct unknown_impl *impl_from_IUnknown(IUnknown *iface)
{
    return CONTAINING_RECORD(iface, struct unknown_impl, IUnknown_iface);
}

static HRESULT WINAPI unknown_QueryInterface(IUnknown *iface, const GUID *iid, void **out)
{
    struct unknown_impl *impl = impl_from_IUnknown(iface);

    if (winetest_debug > 1)
        trace("(%p, %s, %p)\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IAgileObject))
    {
        *out = &impl->IUnknown_iface;
        IUnknown_AddRef(&impl->IUnknown_iface);
        return S_OK;
    }

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI unknown_AddRef(IUnknown *iface)
{
    struct unknown_impl *impl = impl_from_IUnknown(iface);

    return InterlockedIncrement(&impl->weakref->ref_strong);
}

static ULONG WINAPI unknown_Release(IUnknown *iface)
{
    struct unknown_impl *impl = impl_from_IUnknown(iface);
    LONG ref = InterlockedDecrement(&impl->weakref->ref_strong);

    if (!ref)
    {
        struct control_block *weak = impl->weakref;
        BOOL is_inline = weak->is_inline;
        IUnknown *out = NULL;
        LONG count;
        HRESULT hr;

        /* The object will only be freed when the strong refcount is < 0. */
        call_func1(pReleaseTarget, weak);
        hr = IWeakReference_QueryInterface(&weak->IWeakReference_iface, &IID_IWeakReference, (void **)&out);
        ok(hr == S_OK, "got hr %#lx\n", hr);
        test_refcount(out, 3);
        IUnknown_Release(out);

        /* Resolve on native seems to *not* set out to NULL if the weak reference is no longer there. */
        out = (IUnknown *)0xdeadbeef;
        hr = IWeakReference_Resolve(&weak->IWeakReference_iface, &IID_IAgileObject, (IInspectable **)&out);
        ok(hr == S_OK, "got hr %#lx\n", hr);
        ok(out == (IUnknown *)0xdeadbeef, "got out %p\n", out);

        impl->weakref->ref_strong = impl->strong_ref_free_val;
        /* Frees this object. */
        call_func1(pReleaseTarget, weak);
        if (is_inline)
        {
            /* For inline allocations, ReleaseTarget should do nothing.  */
            out = NULL;
            hr = IWeakReference_QueryInterface(&weak->IWeakReference_iface, &IID_IWeakReference, (void **)&out);
            ok(hr == S_OK, "got hr %#lx\n", hr);
            test_refcount(out, 3);
            IUnknown_Release(out);
        }

        /* ReleaseTarget can still be called after the object has been freed. */
        call_func1(pReleaseTarget, weak);
        count = IWeakReference_Release(&weak->IWeakReference_iface);
        ok(count == 1, "got count %lu\n", count);
    }
    return ref;
}


static const IUnknownVtbl unknown_impl_vtbl =
{
    unknown_QueryInterface,
    unknown_AddRef,
    unknown_Release,
};

/* The maximum size for inline allocations. */
#ifdef _WIN64
#define INLINE_MAX 128
#else
#define INLINE_MAX 64
#endif
/* Make sure that unknown_impl can be allocated inline. */
C_ASSERT(sizeof(struct unknown_impl) <= INLINE_MAX);

static void test_AllocateWithWeakRef_inline(void)
{
    struct unknown_impl *object;
    IWeakReference *weakref;
    IUnknown *out;
    ULONG count;
    HRESULT hr;

    /* Test inline allocation. */
    object = pAllocateWithWeakRef(offsetof(struct unknown_impl, weakref), sizeof(struct unknown_impl));
    ok(object != NULL, "got object %p\n", object);
    if (!object)
    {
        skip("AllocateWithWeakRef returned NULL\n");
        return;
    }

    object->strong_ref_free_val = -1;
    ok(object->weakref != NULL, "got weakref %p\n", object->weakref);
    object->IUnknown_iface.lpVtbl = &unknown_impl_vtbl;
    weakref = &object->weakref->IWeakReference_iface;
    test_refcount(weakref, 1);
    ok(object->weakref->is_inline, "got is_inline %d\n", object->weakref->is_inline);
    ok(object->weakref->ref_strong == 1, "got ref_strong %lu\n", object->weakref->ref_strong);
    ok(object->weakref->object == &object->IUnknown_iface, "got object %p != %p\n", object->weakref->object,
       &object->IUnknown_iface);
    ok(object->weakref->unknown == 0, "got unknown %d\n", object->weakref->unknown);
    /* The object is allocate within the weakref. */
    ok((char *)object->weakref == ((char *)object - sizeof(struct control_block)), "got %p != %p\n", object->weakref,
       (char *)object - sizeof(struct control_block));

    hr = IWeakReference_Resolve(weakref, &IID_IAgileObject, (IInspectable **)&out);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    test_refcount(&object->IUnknown_iface, 2);
    IUnknown_Release(out);

    /* Doesn't do anything if the object is still available. */
    call_func1(pReleaseTarget, object->weakref);
    hr = IWeakReference_Resolve(weakref, &IID_IAgileObject, (IInspectable **)&out);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    test_refcount(&object->IUnknown_iface, 2);
    IUnknown_Release(out);

    count = IWeakReference_AddRef(weakref);
    ok(count == 2, "got count %lu\n", count);

    count = IUnknown_Release(&object->IUnknown_iface);
    ok(count == 0, "got count %lu\n", count);
    test_refcount(weakref, 1);
    out = (IUnknown *)0xdeadbeef;
    hr = IWeakReference_Resolve(weakref, &IID_IAgileObject, (IInspectable **)&out);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    ok(out == (IUnknown *)0xdeadbeef, "got out %p\n", out);
    count = IWeakReference_Release(weakref);
    ok(count == 0, "got count %lu\n", count);
}

static void test_AllocateWithWeakRef(void)
{
    struct unknown_impl *object;
    IWeakReference *weakref;
    IUnknown *out;
    ULONG count;
    HRESULT hr;

    /* Test non-inline allocation. */
    object = pAllocateWithWeakRef(offsetof(struct unknown_impl, weakref), INLINE_MAX + 1);
    ok(object != NULL, "got object %p\n", object);
    if (!object)
    {
        skip("AllocateWithWeakRef returned NULL\n");
        return;
    }

    object->strong_ref_free_val = -100;
    ok(object->weakref != NULL, "got weakref %p\n", object->weakref);
    object->IUnknown_iface.lpVtbl = &unknown_impl_vtbl;
    weakref = &object->weakref->IWeakReference_iface;
    test_refcount(weakref, 1);
    ok(!object->weakref->is_inline, "got is_inline %d\n", object->weakref->is_inline);
    ok(object->weakref->ref_strong == 1, "got ref_strong %lu\n", object->weakref->ref_strong);
    ok(object->weakref->object == &object->IUnknown_iface, "got object %p != %p\n", object->weakref->object,
       &object->IUnknown_iface);
    ok(object->weakref->unknown == 0, "got unknown %d\n", object->weakref->unknown);

    hr = IWeakReference_Resolve(weakref, &IID_IAgileObject, (IInspectable **)&out);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    test_refcount(&object->IUnknown_iface, 2);
    IUnknown_Release(out);

    call_func1(pReleaseTarget, object->weakref);
    hr = IWeakReference_Resolve(weakref, &IID_IAgileObject, (IInspectable **)&out);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    test_refcount(&object->IUnknown_iface, 2);
    IUnknown_Release(out);

    count = IWeakReference_AddRef(weakref);
    ok(count == 2, "got count %lu\n", count);

    count = IUnknown_Release(&object->IUnknown_iface);
    ok(count == 0, "got count %lu\n", count);
    test_refcount(weakref, 1);
    out = (IUnknown *)0xdeadbeef;
    hr = IWeakReference_Resolve(weakref, &IID_IAgileObject, (IInspectable **)&out);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    ok(out == (IUnknown *)0xdeadbeef, "got out %p\n", out);
    count = IWeakReference_Release(weakref);
    ok(count == 0, "got count %lu\n", count);
}

START_TEST(vccorlib)
{
    if(!init())
        return;

    test_InitializeData();
    test_GetActivationFactoryByPCWSTR();
    test_GetIidsFn();
    test_Allocate();
    test_AllocateWithWeakRef_inline();
    test_AllocateWithWeakRef();
}
