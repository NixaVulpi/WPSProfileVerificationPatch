#include <Windows.h>
#include <memory>
#include <array>
#include <sstream>
#include <stdexcept>
#include "CreateFileHook.h"
#include "ModuleUtil.h"
#include "FileUtil.h"

namespace WPSProfileVerificationPatch {
    static const std::array<std::pair<std::wstring, std::wstring>, 4> _rules = {
        std::make_pair(L"\\CONTROL\\product.dat", L"product.dat"),
        std::make_pair(L"\\CONTROL\\product_new.dat", L"product_new.dat"),
        std::make_pair(L"\\CONTROL\\wpsplus\\product.dat", L"wpsplus_product.dat"),
        std::make_pair(L"\\CONTROL\\wpsplus\\product_new.dat", L"wpsplus_product_new.dat")
    };

    static HANDLE(WINAPI* _createFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;

    static HANDLE WINAPI CreateFileW(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    ) {
        if (lpFileName && dwDesiredAccess & GENERIC_WRITE) {
            HMODULE module = ModuleUtil::GetSelfHandle();
            std::wstring basePath = ModuleUtil::GetBasePathW(module);

            for (const auto& rule : _rules) {
                if (FileUtil::EndsWithW(lpFileName, rule.first)) {
                    std::wstring sourcePath = basePath + rule.second;

#if defined WP_DEBUG
                    std::wstringstream ss;
                    ss << L"Intercepted write to:\r\n";
                    ss << L"Target: " << std::wstring(lpFileName) << L"\r\n";
                    ss << L"Source: " << sourcePath << L"\r\n";
                    ss << L"Rule: " << rule.first;

                    MessageBoxW(nullptr, ss.str().data(), L"CreateFile Debug Information", MB_ICONINFORMATION);
#endif

                    if (FileUtil::IsFileExistsW(sourcePath)) {
                        if (CopyFileW(sourcePath.data(), lpFileName, FALSE)) {
#if defined(WP_DEBUG)
                            MessageBoxW(nullptr, L"File copied successfully.", L"CreateFile Debug Information", MB_ICONASTERISK);
#endif
                            return INVALID_HANDLE_VALUE;
                        } else {
#if defined(WP_DEBUG)
                            std::wstringstream ss;
                            ss << L"Failed to copy file. Error code: " << GetLastError();
                            MessageBoxW(nullptr, ss.str().data(), L"CreateFile Debug Information", MB_ICONWARNING);
#endif
                        }
                    } else {
#if defined(WP_DEBUG)
                        std::wstringstream ss;
                        ss << L"Source file not found: " << sourcePath;
                        MessageBoxW(nullptr, ss.str().data(), L"CreateFile Debug Information", MB_ICONWARNING);
#endif
                    }
                }
            }
        }

        return _createFileW(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile
        );
    }

    IFunctionHook::HookTarget CreateFileHook::LocateTarget() const {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!kernel32) {
            throw std::runtime_error("Failed to get kernel32.dll handle");
        }

        FARPROC addressW = GetProcAddress(kernel32, "CreateFileW");
        if (!addressW) {
            throw std::runtime_error("Failed to find CreateFileW");
        }

        _createFileW = reinterpret_cast<decltype(_createFileW)>(addressW);

        return {
            reinterpret_cast<PVOID*>(&_createFileW),
            reinterpret_cast<PVOID>(CreateFileW)
        };
    }

    const char* CreateFileHook::GetName() const {
        return "CreateFileHook";
    }
}
