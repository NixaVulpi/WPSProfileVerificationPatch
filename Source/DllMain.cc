#include <Windows.h>
#include <stdexcept>
#include <format>
#include <vector>
#include <memory>
#include "ProxyLibrary.h"
#include "HookManager.h"
#include "KRSAVerifyFileHook.h"
#include "CreateFileHook.h"
#include "WPSProductUtil.h"

using namespace WPSProfileVerificationPatch;

static std::vector<std::unique_ptr<IFunctionHook>> _hooks;

BOOL APIENTRY DllMain(HMODULE module, DWORD reasonForCall, LPVOID reserved) {
    switch (reasonForCall) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(module);
            ProxyLibrary_Load();
            if (!WPSProductUtil::IsWPSOfficeProcess()) {
                break;
            }
#if defined WP_PACKET
            _hooks.push_back(std::make_unique<KRSAVerifyFileHookPacket>());
            _hooks.push_back(std::make_unique<CreateFileHook>());
#elif defined WP_MAIN
            _hooks.push_back(std::make_unique<KRSAVerifyFileHookConfigCenter>());
            _hooks.push_back(std::make_unique<KRSAVerifyFileHookKrt>());
#endif
            if (HookManager::InstallHooks(_hooks) != _hooks.size()) {
                HookManager::UninstallHooks(_hooks);
                _hooks.clear();
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
