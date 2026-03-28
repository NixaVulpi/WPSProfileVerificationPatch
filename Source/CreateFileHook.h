#pragma once
#include <string>
#include "SingletonHook.h"

namespace WPSProfileVerificationPatch {
    class CreateFileHook : public SingletonHook<CreateFileHook> {
    public:
        friend class SingletonHook<CreateFileHook>;

        HookTarget LocateTarget() const override;
        const char* GetName() const override;

    private:
        CreateFileHook() = default;
    };
}
