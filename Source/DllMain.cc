#include <Windows.h>
#include <stdexcept>
#include <format>
#include <vector>
#include <memory>
#include "ProxyLibrary.h"
#include "HookManager.h"
#include "KRSAVerifyFileHook.h"
#include "CreateFileHook.h"

using namespace WPSProfileVerificationPatch;

static std::vector<std::unique_ptr<IFunctionHook>> _hooks;

BOOL APIENTRY DllMain(HMODULE module, DWORD reasonForCall, LPVOID reserved) {
    switch (reasonForCall) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(module);
            ProxyLibrary_Load();
            _hooks.push_back(std::make_unique<KRSAVerifyFileHook>());
#if defined WP_PACKET
            _hooks.push_back(std::make_unique<CreateFileHook>());
#endif
            if (HookManager::InstallHooks(_hooks) != _hooks.size()) {
                HookManager::UninstallHooks(_hooks);
            }
            break;
        case DLL_PROCESS_DETACH:
            HookManager::UninstallHooks(_hooks);
            _hooks.clear();
            ProxyLibrary_Unload();
            break;
    }
    return TRUE;
}
