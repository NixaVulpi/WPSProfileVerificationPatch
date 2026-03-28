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

    class KRSAVerifyFilePacketHook : public KRSAVerifyFileHook, public SingletonHook<KRSAVerifyFilePacketHook> {
    public:
        friend class SingletonHook<KRSAVerifyFilePacketHook>;

        HookTarget LocateTarget() const override;
        const char* GetName() const override;

    protected:
        std::span<const uint8_t> GetSearchRegion() const override;

    private:
        KRSAVerifyFilePacketHook() = default;
    };

    class KRSAVerifyFileKrtHook : public KRSAVerifyFileHook, public SingletonHook<KRSAVerifyFileKrtHook> {
    public:
        friend class SingletonHook<KRSAVerifyFileKrtHook>;

        HookTarget LocateTarget() const override;
        const char* GetName() const override;

    protected:
        std::span<const uint8_t> GetSearchRegion() const override;

    private:
        KRSAVerifyFileKrtHook() = default;
    };

    class KRSAVerifyFileConfigCenterHook : public KRSAVerifyFileHook, public SingletonHook<KRSAVerifyFileConfigCenterHook> {
    public:
        friend class SingletonHook<KRSAVerifyFileConfigCenterHook>;

        HookTarget LocateTarget() const override;
        const char* GetName() const override;

    protected:
        std::span<const uint8_t> GetSearchRegion() const override;

    private:
        KRSAVerifyFileConfigCenterHook() = default;
    };
}
