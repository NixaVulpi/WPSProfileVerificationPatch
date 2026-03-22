#pragma once
#include <Windows.h>
#include <string>
#include <span>
#include "IFunctionHook.h"

namespace WPSProfileVerificationPatch {
    class KRSAVerifyFileHook : public IFunctionHook {
    public:
        static bool (*kRSAVerifyFile)(const std::string&, const std::string&, const std::string&);

        static bool KRSAVerifyFile(const std::string& publicKey, const std::string& fileHash, const std::string& fileSignature);

        void LocateTarget() const override;
        PVOID* GetOriginalPointer() const override;
        PVOID GetDetourFunction() const override;
        const char* GetName() const override;

        virtual std::span<const uint8_t> GetSearchRegion() const = 0;

    private:
        void LocateTargetInRegion(std::span<const uint8_t> region) const;
    };

    class KRSAVerifyFileHookPacket : public KRSAVerifyFileHook {
    public:
        std::span<const uint8_t> GetSearchRegion() const override;
    };

    class KRSAVerifyFileHookKrt : public KRSAVerifyFileHook {
    public:
        std::span<const uint8_t> GetSearchRegion() const override;
    };

    class KRSAVerifyFileHookConfigCenter : public KRSAVerifyFileHook {
    public:
        std::span<const uint8_t> GetSearchRegion() const override;
    };
}
