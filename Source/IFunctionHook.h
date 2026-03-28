#pragma once
#include <Windows.h>
#include <string>

namespace WPSProfileVerificationPatch {
    struct IFunctionHook {
        struct HookTarget {
            PVOID* original;
            PVOID detour;
        };

        virtual ~IFunctionHook() = default;

        virtual HookTarget LocateTarget() const = 0;
        virtual const char* GetName() const = 0;
    };
}
