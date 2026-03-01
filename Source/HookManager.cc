#include <Windows.h>
#include <detours.h>
#include <stdexcept>
#include <sstream>
#include "HookManager.h"

namespace WPSProfileVerificationPatch {
    size_t HookManager::InstallHooks(const std::vector<std::unique_ptr<IFunctionHook>>& hooks) {
        if (hooks.size() == 0) {
            return 0;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        size_t count = 0;

        for (auto& hook : hooks) {
            try {
                hook->LocateTarget();
            } catch (const std::exception& e) {
#if defined WP_DEBUG
                MessageBoxA(nullptr, e.what(), (std::string("Hook Locate Failed: ") + hook->GetName()).c_str(), MB_ICONSTOP);
#endif
                continue;
            }

            PVOID* originalPointer = hook->GetOriginalPointer();

            if (*originalPointer == nullptr) {
                continue;
            }

            DetourAttach(originalPointer, hook->GetDetourFunction());

            ++count;
        }

        LONG result = DetourTransactionCommit();

        if (result != NO_ERROR) {
            count = 0;
#if defined WP_DEBUG
            std::stringstream ss;
            ss << "Failed to install hooks, error: " << result;
            MessageBoxA(nullptr, ss.str().c_str(), "Hook Install Failed", MB_ICONSTOP);
#endif
        }

        return count;
    }

    size_t HookManager::UninstallHooks(const std::vector<std::unique_ptr<IFunctionHook>>& hooks) {
        if (hooks.size() == 0) {
            return 0;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        size_t count = 0;

        for (auto& hook : hooks) {
            PVOID* originalPointer = hook->GetOriginalPointer();

            if (*originalPointer == nullptr) {
                continue;
            }

            DetourDetach(originalPointer, hook->GetDetourFunction());

            ++count;
        }

        LONG result = DetourTransactionCommit();

        if (result != NO_ERROR) {
            count = 0;
#if defined WP_DEBUG
            std::stringstream ss;
            ss << "Failed to uninstall hooks, error: " << result;
            MessageBoxA(nullptr, ss.str().c_str(), "Hook Uninstall Failed", MB_ICONSTOP);
#endif
        }

        return count;
    }
}
