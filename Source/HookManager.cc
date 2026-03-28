#include <Windows.h>
#include <detours.h>
#include <stdexcept>
#include <sstream>
#include "HookManager.h"

namespace WPSProfileVerificationPatch {
    HookManager& HookManager::GetInstance() {
        static HookManager instance;
        return instance;
    }

    void HookManager::AddHook(std::unique_ptr<IFunctionHook> hook) {
        if (hook) {
            _hooks.push_back(std::move(hook));
        }
    }

    void HookManager::ClearHooks() {
        _hooks.clear();
        _targets.clear();
    }

    size_t HookManager::InstallHooks() {
        if (_hooks.empty()) {
            return 0;
        }

        _targets.clear();
        _targets.reserve(_hooks.size());

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        size_t count = 0;

        for (const auto& hook : _hooks) {
            IFunctionHook::HookTarget target = { nullptr, nullptr };

            try {
                target = hook->LocateTarget();
            } catch (const std::exception& e) {
#if defined WP_DEBUG
                MessageBoxA(nullptr, e.what(), (std::string("Hook Locate Failed: ") + hook->GetName()).c_str(), MB_ICONSTOP);
#endif
                continue;
            }

            if (target.original == nullptr || *target.original == nullptr || target.detour == nullptr) {
                continue;
            }

            DetourAttach(target.original, target.detour);

            _targets.push_back(target);

            ++count;
        }

        LONG result = DetourTransactionCommit();

        if (result != NO_ERROR) {
            _targets.clear();
            count = 0;
#if defined WP_DEBUG
            std::stringstream ss;
            ss << "Failed to install hooks, error: " << result;
            MessageBoxA(nullptr, ss.str().c_str(), "Hook Install Failed", MB_ICONSTOP);
#endif
        }

        return count;
    }

    size_t HookManager::UninstallHooks() {
        if (_targets.empty()) {
            return 0;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        size_t count = 0;

        for (const auto& target : _targets) {
            if (target.original && *target.original && target.detour) {
                DetourDetach(target.original, target.detour);
                ++count;
            }
        }

        LONG result = DetourTransactionCommit();

        if (result != NO_ERROR) {
            count = 0;
#if defined WP_DEBUG
            std::stringstream ss;
            ss << "Failed to uninstall hooks, error: " << result;
            MessageBoxA(nullptr, ss.str().c_str(), "Hook Uninstall Failed", MB_ICONSTOP);
#endif
        } else {
            _targets.clear();
        }

        return count;
    }
}
