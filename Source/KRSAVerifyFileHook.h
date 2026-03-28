#pragma once
#include <Windows.h>
#include <string>
#include <span>
#include "IFunctionHook.h"
#include "SingletonHook.h"

namespace WPSProfileVerificationPatch {
    class KRSAVerifyFileHook : public virtual IFunctionHook {
    public:
        HookTarget LocateTarget() const override;
        const char* GetName() const override = 0;

    protected:
        KRSAVerifyFileHook() = default;
        virtual std::span<const uint8_t> GetSearchRegion() const = 0;
    };

    class KRSAVerifyFileHookPacket : public KRSAVerifyFileHook, public SingletonHook<KRSAVerifyFileHookPacket> {
    public:
        friend class SingletonHook<KRSAVerifyFileHookPacket>;

        HookTarget LocateTarget() const override;
        const char* GetName() const override;

    protected:
        std::span<const uint8_t> GetSearchRegion() const override;

    private:
        KRSAVerifyFileHookPacket() = default;
    };

    class KRSAVerifyFileHookKrt : public KRSAVerifyFileHook, public SingletonHook<KRSAVerifyFileHookKrt> {
    public:
        friend class SingletonHook<KRSAVerifyFileHookKrt>;

        HookTarget LocateTarget() const override;
        const char* GetName() const override;

    protected:
        std::span<const uint8_t> GetSearchRegion() const override;

    private:
        KRSAVerifyFileHookKrt() = default;
    };

    class KRSAVerifyFileHookConfigCenter : public KRSAVerifyFileHook, public SingletonHook<KRSAVerifyFileHookConfigCenter> {
    public:
        friend class SingletonHook<KRSAVerifyFileHookConfigCenter>;

        HookTarget LocateTarget() const override;
        const char* GetName() const override;

    protected:
        std::span<const uint8_t> GetSearchRegion() const override;

    private:
        KRSAVerifyFileHookConfigCenter() = default;
    };
}
