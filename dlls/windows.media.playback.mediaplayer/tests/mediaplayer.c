/*
 * Copyright (C) 2025 Mohamad Al-Jaf
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
#include "initguid.h"
#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winstring.h"

#include "roapi.h"

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include "windows.foundation.h"
#define WIDL_using_Windows_Media_Playback
#include "windows.media.playback.h"

#include "wine/test.h"

#define check_interface( obj, iid, supported ) check_interface_( __LINE__, obj, iid, supported )
static void check_interface_( unsigned int line, void *obj, const IID *iid, BOOL supported )
{
    IUnknown *iface = obj;
    IUnknown *unk;
    HRESULT hr;

    hr = IUnknown_QueryInterface( iface, iid, (void **)&unk );
    ok_(__FILE__, line)( hr == S_OK || (!supported && hr == E_NOINTERFACE), "got hr %#lx.\n", hr );
    if (SUCCEEDED(hr)) IUnknown_Release( unk );
}

static void test_MediaPlayer_Statics(void)
{
    static const WCHAR *media_player_name = L"Windows.Media.Playback.MediaPlayer";
    IActivationFactory *factory = (void *)0xdeadbeef;
    IMediaPlayer *media_player = (void *)0xdeadbeef;
    IInspectable *inspectable = (void *)0xdeadbeef;
    HSTRING str;
    HRESULT hr;
    LONG ref;

    hr = WindowsCreateString( media_player_name, wcslen( media_player_name ), &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = RoGetActivationFactory( str, &IID_IActivationFactory, (void **)&factory );
    ok( hr == S_OK || broken( hr == REGDB_E_CLASSNOTREG ), "got hr %#lx.\n", hr );
    if (hr == REGDB_E_CLASSNOTREG)
    {
        WindowsDeleteString( str );
        win_skip( "%s runtimeclass not registered, skipping tests.\n", wine_dbgstr_w( media_player_name ) );
        return;
    }

    check_interface( factory, &IID_IUnknown, TRUE );
    check_interface( factory, &IID_IInspectable, TRUE );
    check_interface( factory, &IID_IAgileObject, FALSE );
    check_interface( factory, &IID_IMediaPlayer, FALSE );

    hr = RoActivateInstance( str, &inspectable );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    WindowsDeleteString( str );

    hr = IInspectable_QueryInterface( inspectable, &IID_IMediaPlayer, (void **)&media_player );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    check_interface( media_player, &IID_IAgileObject, TRUE );

    ref = IMediaPlayer_Release( media_player );
    ok( ref == 1, "got ref %ld.\n", ref );
    ref = IInspectable_Release( inspectable );
    ok( ref == 0, "got ref %ld.\n", ref );
    ref = IActivationFactory_Release( factory );
    ok( ref == 1, "got ref %ld.\n", ref );
}

START_TEST(mediaplayer)
{
    HRESULT hr;

    hr = RoInitialize( RO_INIT_MULTITHREADED );
    ok( hr == S_OK, "RoInitialize failed, hr %#lx\n", hr );

    test_MediaPlayer_Statics();

    RoUninitialize();
}
