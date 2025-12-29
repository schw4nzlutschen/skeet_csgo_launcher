#include "pch.h"
#include "sdk/sdk.h"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

using namespace SkeetSDK;

struct RegKey
{
    HKEY h{ nullptr };

    RegKey( ) = default;
    explicit RegKey( HKEY key ) noexcept : h( key ) {}

    RegKey( const RegKey& ) = delete;
    RegKey& operator=( const RegKey& ) = delete;

    RegKey( RegKey&& o ) noexcept : h( std::exchange( o.h, nullptr ) ) {}
    RegKey& operator=( RegKey&& o ) noexcept
    {
        if ( this != &o )
        {
            if ( h ) RegCloseKey( h );
            h = std::exchange( o.h, nullptr );
        }
        return *this;
    }

    ~RegKey( ) { if ( h ) RegCloseKey( h ); }
};

template <class T>
static bool read_unit_value( const ConfigDataUnit& u, T& out ) noexcept
{
    if ( u.data_size != sizeof( T ) ) // [file:2]
        return false;
    std::memcpy( &out, &u.data, sizeof( T ) );
    return true;
}

static bool g_need_layout_fix = false;
static bool g_menu_event_added = false;

static void __cdecl on_menu( )
{
    if ( !g_need_layout_fix )
        return;

    g_need_layout_fix = false;

    UI::ResetLayout( );
    UI::SetTab( UI::GetActiveTab( ) );
}

static void ensure_menu_event( )
{
    if ( g_menu_event_added ) return;
    g_menu_event_added = true;

    Renderer::Init( );
    Renderer::AddEvent( REVENT_MENU, &on_menu );
}


static void load_settings( )
{
    InitAndWaitForSkeet( ); // [file:1][file:2]
    ensure_menu_event( );

    HKEY raw{};
    if ( RegOpenKeyW( HKEY_CURRENT_USER, L"SOFTWARE", &raw ) != ERROR_SUCCESS ) // [file:1]
        return;

    RegKey regkey{ raw };

    static auto setpossize = reinterpret_cast<void( __thiscall* )( CMenu*, std::uint32_t& )>(
        Memory::CheatChunk.find( "56 57 8B 7C 24 ?? 8B F1 ?? ?? ?? 0F 85" ) ); // [file:1][file:2]

    static auto apply_dpi = reinterpret_cast<void( __thiscall* )( bool )>(
        Memory::CheatChunk.find( "55 8B EC 83 E4 ?? A1 ?? ?? ?? ?? 53" ) ); // [file:1][file:2]

    DWORD size = 0x400; // [file:1]
    std::vector<std::byte> buf( size );

    DWORD keytype{};
    const auto st = RegQueryValueExW(
        regkey.h,
        Menu->RegValueName, // [file:1][file:2]
        nullptr,
        &keytype,
        reinterpret_cast<BYTE*>( buf.data( ) ),
        &size );

    if ( st != ERROR_SUCCESS )
        return;

    if ( keytype != REG_BINARY ) // [file:1]
    {
        RegDeleteValueW( HKEY_CURRENT_USER, Menu->RegValueName ); // [file:1][file:2]
        return;
    }

    if ( size < sizeof( ConfigHead ) )
        return;

    buf.resize( size );
    auto bytes = std::span<std::byte>( buf.data( ), buf.size( ) );

    auto* head = reinterpret_cast<ConfigHead*>( bytes.data( ) ); // [file:2]
    if ( head->sig != SKEET_HEAD_SIGNATURE )                    // [file:2]
        return;

    std::size_t offset = sizeof( ConfigHead );
    while ( offset + sizeof( ConfigDataUnit ) <= bytes.size( ) )
    {
        auto* unit = reinterpret_cast<ConfigDataUnit*>( bytes.data( ) + offset ); // [file:2]

        const std::size_t total = sizeof( ConfigDataUnit ) + unit->data_size; // [file:2]
        if ( offset + total > bytes.size( ) )
            break;

        switch ( unit->data_type ) // [file:2]
        {
        case LCOLOR:
        {
            std::uint32_t v{};
            if ( read_unit_value( *unit, v ) )
            {
                *reinterpret_cast<std::uint32_t*>( 0x43468FB0 ) = v; // [file:1]
                Menu->Tabs[ MISC ]->Childs[ 2 ]->Elements[ 3 ]->GetAs<IElement>( )->OnConfigLoad( ); // [file:1][file:2]
            }
            break;
        }

        case LPOSSIZE:
        {
            std::uint32_t v{};
            if ( read_unit_value( *unit, v ) && setpossize )
                setpossize( Menu, v ); // [file:1]
            break;
        }

        case LBOOL:
        {
            bool v{};
            if ( read_unit_value( *unit, v ) )
                *reinterpret_cast<bool*>( 0x43475798 ) = v; // [file:1]
            break;
        }

        case LHOTKEY:
        {
            std::uint32_t v{};
            if ( read_unit_value( *unit, v ) )
                *reinterpret_cast<std::uint32_t*>( 0x43478DC8 ) = v; // [file:1]
            break;
        }

        case LARRAY:
        {
            constexpr std::size_t kHashBytes = sizeof( Menu->OnStartupHash );
            if ( unit->data_size == kHashBytes )
                std::memcpy( Menu->OnStartupHash, &unit->data, unit->data_size );
            break;
        }

        case LINTEGER:
            switch ( unit->hash ) // [file:1][file:2]
            {
            case 0x1F495BA0:
            {
                int v{};
                if ( read_unit_value( *unit, v ) ) Menu->Size.x = v; // [file:1][file:2]
                break;
            }
            case 0xEAA92CD1:
            {
                int v{};
                if ( read_unit_value( *unit, v ) ) Menu->Size.y = v; // [file:1][file:2]
                break;
            }
            case 0x27BA18FA:
            {
                std::uint32_t v{};
                if ( read_unit_value( *unit, v ) )
                {
                    *reinterpret_cast<std::uint32_t*>( 0x43475A94 ) = v; // [file:1]
                    if ( apply_dpi ) apply_dpi( true ); // [file:1]
                }
                break;
            }
            case 0xD3F1456E:
            {
                bool v{};
                if ( read_unit_value( *unit, v ) )
                    *reinterpret_cast<bool*>( 0x43467E4B ) = v; // [file:1]
                break;
            }
            default:
                break;
            }
            break;

        default:
            break;
        }

        offset += total;
    }

    g_need_layout_fix = true;
}

static decltype( load_settings )* fn = &load_settings; // [file:1]

__declspec( naked ) __declspec( noreturn ) void LoadStub( ) // [file:1]
{
    __asm
    {
        mov eax, fn
        call eax
        mov eax, 0x434938FF
        jmp eax
    }
}