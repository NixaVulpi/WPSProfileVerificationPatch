#include <Windows.h>
#include <stdexcept>
#include <format>
#include <vector>
#include <memory>
#include "ProxyLibrary.h"
#include "KRSAVerifyFileHook.h"
#include "CreateFileHook.h"
#include "WPSProductUtil.h"

using namespace WPSProfileVerificationPatch;

BOOL APIENTRY DllMain(HMODULE module, DWORD reasonForCall, LPVOID reserved) {
    switch (reasonForCall) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(module);
            ProxyLibrary_Load();
            if (!WPSProductUtil::IsWPSOfficeProcess()) {
                break;
            }
#if defined WP_PACKET
            KRSAVerifyFileHookPacket::Register();
            CreateFileHook::Register();
#elif defined WP_MAIN
            KRSAVerifyFileHookConfigCenter::Register();
            KRSAVerifyFileHookKrt::Register();
#endif
            HookManager::GetInstance().InstallHooks();
            break;
        case DLL_PROCESS_DETACH:
            HookManager::GetInstance().UninstallHooks();
            ProxyLibrary_Unload();
            break;
    }
    return TRUE;
}
