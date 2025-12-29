#include "pch.h"
#include "skCrypter.h"

static void thread(HMODULE base) {
#ifdef DLOG
    system("cls");
#endif
    skeet_t* skeet = skeet_t::getInstance(base);
    if (!skeet->map())
        std::cout << skCrypt("[INFO] failed to allocate memory, reboot PC\n");
    while (GetModuleHandleA("serverbrowser.dll") == 0);
    skeet->fix_imports();
    std::cout << skCrypt("[INFO] fixed!\n");
    skeet->extra();
    skeet->entry();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if ( ul_reason_for_call == DLL_PROCESS_ATTACH ) {
#ifdef DLOG
        AllocConsole( );
        SetConsoleTitleA( "c0desense" );
        freopen( "CONOUT$", "w", stdout );
#endif
        DisableThreadLibraryCalls( hModule );
        CloseHandle( CreateThread( nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>( thread ), hModule, 0, nullptr ) );
    }

    return TRUE;
}