#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <iostream>
#include <thread>
#include <chrono>
#include <expected>
#include <string_view>
#include "skCrypter.h"

using namespace std::chrono_literals;

class unique_handle {
public:
    unique_handle() = default;
    explicit unique_handle(const HANDLE h) : h_(h) {}
    unique_handle(const unique_handle&) = delete;
    unique_handle& operator=(const unique_handle&) = delete;

    unique_handle(unique_handle&& other) noexcept : h_(std::exchange(other.h_, nullptr)) {}
    unique_handle& operator=(unique_handle&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = std::exchange(other.h_, nullptr);
        }
        return *this;
    }

    ~unique_handle() { reset(); }

    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ && h_ != INVALID_HANDLE_VALUE; }

    void reset(const HANDLE nh = nullptr) noexcept {
        if (h_ && h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
        }
        h_ = nh;
    }

private:
    HANDLE h_{nullptr};
};

static std::expected<DWORD, DWORD> find_process_id(std::wstring_view exe_name) {
    const unique_handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (!snapshot) {
        return std::unexpected(GetLastError());
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot.get(), &pe)) {
        return std::unexpected(GetLastError());
    }

    do {
        if (_wcsicmp(pe.szExeFile, exe_name.data()) == 0) {
            return pe.th32ProcessID;
        }
    } while (Process32NextW(snapshot.get(), &pe));

    return std::unexpected(ERROR_NOT_FOUND);
}

static std::expected<unique_handle, DWORD> open_process(const DWORD pid) {
    if (const HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); h) {
        return unique_handle{h};
    }
    return std::unexpected(GetLastError());
}

int main() {
    auto consoleTitle = skCrypt("c0desense");
    SetConsoleTitleA(consoleTitle);

    std::cout << skCrypt("DONT RENAME neverlose.dll!\nEnter -insecure in csgo params\n");

    const auto dll_path = std::filesystem::current_path() / L"neverlose.dll";

    if (!std::filesystem::exists(dll_path)) {
        std::cout << skCrypt("ERROR: neverlose.dll not found in current directory!\n");
        std::cout << skCrypt("Press Enter to exit...\n");
        std::cin.get();
        return 1;
    }

    const auto path_str = dll_path.wstring();
    const auto path_size_bytes = (path_str.length() + 1) * sizeof(wchar_t);

    std::cout << skCrypt("Waiting for csgo.exe...\n");

    bool injection_successful = false;

    auto proc = INVALID_HANDLE_VALUE;

    while (proc == INVALID_HANDLE_VALUE) {

        if (auto pid_result = find_process_id(L"csgo.exe"); pid_result) {
            const auto pid = *pid_result;
            std::cout << skCrypt("Found csgo.exe with PID: ") << pid << "\n";

            if (const auto proc_result = open_process(pid); proc_result) {
                proc = proc_result->get();

                const auto cheat_address = reinterpret_cast<void*>(0x43310000);
                constexpr size_t cheat_size = 0x2fc000;

                const LPVOID cheat_memory = VirtualAllocEx(
                    proc,
                    cheat_address,
                    cheat_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                );

                if (!cheat_memory) {
                    const DWORD err = GetLastError();
                    std::cout << skCrypt("Warning: Failed to allocate cheat memory at 0x43310000! Error: ") << err << "\n";
                    std::cout << skCrypt("The cheat might not work properly, but continuing...\n");
                } else {
                    std::cout << skCrypt("Cheat memory allocated at 0x43310000\n");
                }

                const LPVOID arg_memory = VirtualAllocEx(
                    proc,
                    nullptr,
                    path_size_bytes + 100,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );

                if (!arg_memory) {
                    std::cout << skCrypt("Failed to allocate memory for DLL path! Error: ") << GetLastError() << "\n";
                    std::this_thread::sleep_for(500ms);
                    continue;
                }

                std::cout << skCrypt("Memory for DLL path allocated at: 0x") << std::hex << arg_memory << std::dec << "\n";

                SIZE_T bytes_written = 0;
                if (!WriteProcessMemory(
                    proc,
                    arg_memory,
                    path_str.c_str(),
                    path_size_bytes,
                    &bytes_written
                )) {
                    std::cout << skCrypt("Failed to write DLL path to memory! Error: ") << GetLastError() << "\n";
                    VirtualFreeEx(proc, arg_memory, 0, MEM_RELEASE);
                    std::this_thread::sleep_for(500ms);
                    continue;
                }

                std::cout << skCrypt("DLL path written (") << bytes_written << skCrypt(" bytes)\n");

                const HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
                const FARPROC load_library_addr = GetProcAddress(kernel32, "LoadLibraryW");

                if (!load_library_addr) {
                    std::cout << skCrypt("Failed to get LoadLibraryW address!\n");
                    VirtualFreeEx(proc, arg_memory, 0, MEM_RELEASE);
                    std::this_thread::sleep_for(500ms);
                    continue;
                }

                const HANDLE hThread = CreateRemoteThread(
                    proc,
                    nullptr,
                    0,
                    reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library_addr),
                    arg_memory,
                    0,
                    nullptr
                );

                if (!hThread) {
                    std::cout << skCrypt("Failed to create remote thread!");
                    VirtualFreeEx(proc, arg_memory, 0, MEM_RELEASE);
                    std::this_thread::sleep_for(500ms);
                    continue;
                }

                std::cout << skCrypt("Remote thread created, waiting for DLL load...\n");

                WaitForSingleObject(hThread, INFINITE);

                DWORD exit_code = 0;
                if (GetExitCodeThread(hThread, &exit_code) && exit_code != 0) {
                    std::cout << skCrypt("SUCCESS! DLL loaded at 0x") << std::hex << exit_code << std::dec << "\n";

                    std::cout << skCrypt("Waiting for initialization...\n");
                    std::this_thread::sleep_for(3000ms);

                    DWORD process_exit_code = 0;
                    if (GetExitCodeProcess(proc, &process_exit_code) && process_exit_code == STILL_ACTIVE) {
                        std::cout << skCrypt("\n=== INJECTION COMPLETE ===\n");
                        std::cout << skCrypt("Game is running!\n");
                        std::cout << skCrypt("You can minimize this console.\n");
                        injection_successful = true;
                    } else {
                        std::cout << skCrypt("\n=== WARNING ===\n");
                        std::cout << skCrypt("Game may have crashed after injection!\n");
                    }
                } else {
                    std::cout << skCrypt("FAILED! LoadLibrary returned NULL\n");
                    VirtualFreeEx(proc, arg_memory, 0, MEM_RELEASE);
                }

                CloseHandle(hThread);

                if (injection_successful) {
                    std::cout << skCrypt("\nPress Enter to exit injector...\n");
                    std::cin.get();
                    break;
                }
            } else {
                std::cout << skCrypt("Failed to open process. Are you running as administrator?\n");
            }
        }

        std::this_thread::sleep_for(1000ms);
    }

    return 0;
}