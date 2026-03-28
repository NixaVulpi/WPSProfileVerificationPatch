#pragma once
#include <vector>
#include <memory>
#include <cstdint>
#include "IFunctionHook.h"

namespace WPSProfileVerificationPatch {
    class HookManager {
    public:
        HookManager(const HookManager&) = delete;
        HookManager& operator=(const HookManager&) = delete;

        static HookManager& GetInstance();

        void AddHook(std::unique_ptr<IFunctionHook> hook);
        void ClearHooks();
        size_t InstallHooks();
        size_t UninstallHooks();

    private:
        HookManager() = default;
        std::vector<std::unique_ptr<IFunctionHook>> _hooks;
        std::vector<IFunctionHook::HookTarget> _targets;
    };
}
