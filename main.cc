#pragma comment(linker, "/export:ClearReportsBetween_ExportThunk=chrome_elf_orig.ClearReportsBetween_ExportThunk,@1")
#pragma comment(linker, "/export:CrashForException_ExportThunk=chrome_elf_orig.CrashForException_ExportThunk,@2")
#pragma comment(linker, "/export:DisableHook=chrome_elf_orig.DisableHook,@3")
#pragma comment(linker, "/export:DrainLog=chrome_elf_orig.DrainLog,@4")
#pragma comment(linker, "/export:DumpHungProcessWithPtype_ExportThunk=chrome_elf_orig.DumpHungProcessWithPtype_ExportThunk,@5")
#pragma comment(linker, "/export:DumpProcessWithoutCrash=chrome_elf_orig.DumpProcessWithoutCrash,@6")
#pragma comment(linker, "/export:GetApplyHookResult=chrome_elf_orig.GetApplyHookResult,@7")
#pragma comment(linker, "/export:GetBlockedModulesCount=chrome_elf_orig.GetBlockedModulesCount,@8")
#pragma comment(linker, "/export:GetCrashpadDatabasePath_ExportThunk=chrome_elf_orig.GetCrashpadDatabasePath_ExportThunk,@10")
#pragma comment(linker, "/export:GetCrashReports_ExportThunk=chrome_elf_orig.GetCrashReports_ExportThunk,@9")
#pragma comment(linker, "/export:GetHandleVerifier=chrome_elf_orig.GetHandleVerifier,@11")
#pragma comment(linker, "/export:GetInstallDetailsPayload=chrome_elf_orig.GetInstallDetailsPayload,@12")
#pragma comment(linker, "/export:GetUniqueBlockedModulesCount=chrome_elf_orig.GetUniqueBlockedModulesCount,@13")
#pragma comment(linker, "/export:GetUserDataDirectoryThunk=chrome_elf_orig.GetUserDataDirectoryThunk,@14")
#pragma comment(linker, "/export:InjectDumpForHungInput_ExportThunk=chrome_elf_orig.InjectDumpForHungInput_ExportThunk,@15")
#pragma comment(linker, "/export:IsBrowserProcess=chrome_elf_orig.IsBrowserProcess,@16")
#pragma comment(linker, "/export:IsCrashReportingEnabledImpl=chrome_elf_orig.IsCrashReportingEnabledImpl,@17")
#pragma comment(linker, "/export:IsThirdPartyInitialized=chrome_elf_orig.IsThirdPartyInitialized,@18")
#pragma comment(linker, "/export:RegisterLogNotification=chrome_elf_orig.RegisterLogNotification,@19")
#pragma comment(linker, "/export:RequestSingleCrashUpload_ExportThunk=chrome_elf_orig.RequestSingleCrashUpload_ExportThunk,@20")
#pragma comment(linker, "/export:SetCrashKeyValueImpl=chrome_elf_orig.SetCrashKeyValueImpl,@21")
#pragma comment(linker, "/export:SetMetricsClientId=chrome_elf_orig.SetMetricsClientId,@22")
#pragma comment(linker, "/export:SetUploadConsent_ExportThunk=chrome_elf_orig.SetUploadConsent_ExportThunk,@23")
#pragma comment(linker, "/export:SignalChromeElf=chrome_elf_orig.SignalChromeElf,@24")
#pragma comment(linker, "/export:SignalInitializeCrashReporting=chrome_elf_orig.SignalInitializeCrashReporting,@25")

#include <polyhook2/PE/IatHook.hpp>
#include <Windows.h>

#define CUSTOM_LAUNCHER_COMMAND (L"<INSERT_COMMAND_HERE>")

namespace {
    std::unique_ptr<PLH::IatHook> create_process_hook;
    std::uint64_t create_process_original;
    WNDPROC wndproc_original{nullptr};
    bool override = true;
    HMENU override_menu{nullptr};

    BOOL
    WINAPI
    CreateProcessHook(
            _In_opt_ LPCWSTR lpApplicationName,
            _Inout_opt_ LPWSTR lpCommandLine,
            _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
            _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
            _In_ BOOL bInheritHandles,
            _In_ DWORD dwCreationFlags,
            _In_opt_ LPVOID lpEnvironment,
            _In_opt_ LPCWSTR lpCurrentDirectory,
            _In_ LPSTARTUPINFOW lpStartupInfo,
            _Out_ LPPROCESS_INFORMATION lpProcessInformation
    ) {
        // Call original if we don't override
        if (!override) {
            return PLH::FnCast(create_process_original, CreateProcessHook)(
                    lpApplicationName,
                    lpCommandLine,
                    lpProcessAttributes,
                    lpThreadAttributes,
                    bInheritHandles,
                    dwCreationFlags,
                    lpEnvironment,
                    lpCurrentDirectory,
                    lpStartupInfo,
                    lpProcessInformation
            );
        }

        // Use our custom launcher command
        std::wstring command = std::wstring(CUSTOM_LAUNCHER_COMMAND);
        return PLH::FnCast(create_process_original, CreateProcessHook)(
                nullptr,
                _wcsdup(command.c_str()),
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation
        );
    }

    struct handle_data {
        DWORD process_id;
        std::vector<HWND> window_handles;
    };

    BOOL CALLBACK EnumWindowsCallback(HWND handle, LPARAM lParam) {
        auto *data = (handle_data *) lParam;
        DWORD process_id = 0;
        GetWindowThreadProcessId(handle, &process_id);
        if (data->process_id == process_id) {
            data->window_handles.push_back(handle);
        }
        return TRUE;
    }

    std::vector<HWND> FindCurrentProcessWindows() {
        handle_data data{GetCurrentProcessId(), std::vector<HWND>()};
        EnumWindows(EnumWindowsCallback, (LPARAM) &data);
        return data.window_handles;
    }

    constexpr auto OVERRIDE_MENU_ITEM_ID = 0x42;

    void UpdateOverrideCheckbox() {
        CheckMenuItem(override_menu, OVERRIDE_MENU_ITEM_ID, override ? MF_CHECKED : MF_UNCHECKED);
    }

    LRESULT CALLBACK LauncherWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        // Check if override is pressed
        if (uMsg == WM_COMMAND && LOWORD(wParam) == OVERRIDE_MENU_ITEM_ID) {
            override = !override;
            UpdateOverrideCheckbox();
        }
        return CallWindowProc(wndproc_original, hWnd, uMsg, wParam, lParam);
    }

    DWORD WINAPI MainThread(LPVOID lpParam) {
        // Hook CreateProcessW
        create_process_hook = std::make_unique<PLH::IatHook>(
                "kernel32.dll", "CreateProcessW", (std::uintptr_t) CreateProcessHook, &create_process_original, L"");
        create_process_hook->hook();

        // Wait for Jagex Launcher window
        HWND main_window;
        while (true) {
            auto windows = FindCurrentProcessWindows();
            for (auto window: windows) {
                TCHAR window_text[MAX_PATH];
                GetWindowTextA(window, window_text, _countof(window_text));
                OutputDebugStringA(window_text);
                if (strcmp(window_text, "Jagex Launcher") == 0) {
                    main_window = window;
                    goto found;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        found:

        // HookWndProc
        wndproc_original = (WNDPROC) SetWindowLongPtr(main_window, GWLP_WNDPROC, (LONG_PTR) LauncherWndProc);

        // Create a new menu and Settings item
        override_menu = CreateMenu();
        HMENU menu = CreateMenu();
        AppendMenuA(menu, MF_POPUP, (UINT_PTR) override_menu, "Settings");
        AppendMenuA(override_menu, MF_STRING, OVERRIDE_MENU_ITEM_ID, "Override client");
        SetMenu(main_window, menu);
        UpdateOverrideCheckbox();
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return true;
}
