#pragma once
#include <memory>
#include "IFunctionHook.h"
#include "HookManager.h"

namespace WPSProfileVerificationPatch {
    template <typename T>
    class SingletonHook : public virtual IFunctionHook {
    protected:
        SingletonHook() = default;

    public:
        static void Register() {
            static bool registered = false;
            if (!registered) {
                registered = true;
                HookManager::GetInstance().AddHook(std::unique_ptr<IFunctionHook>(new T()));
            }
        }
    };
}
