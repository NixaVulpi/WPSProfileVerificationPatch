#include <Windows.h>
#include <stdexcept>
#include <sstream>
#include <memory>
#include <array>
#include "Detours.h"
#include "KRSAVerifyFileHook.h"
#include "FileUtil.h"
#include "ModuleUtil.h"
#include "PatternUtil.h"

namespace WPSProfileVerificationPatch {
    static bool (*_kRSAVerifyFile)(const std::string& publicKey, const std::string& fileHash, const std::string& fileSignature) = nullptr;

    static bool KRSAVerifyFile(const std::string& publicKey, const std::string& fileHash, const std::string& fileSignature) {
#if defined WP_DEBUG
        std::stringstream ss;
        ss << "KRSAVerifyFile called with parameters:\r\n";
        ss << "Public Key: " << publicKey << "\r\n";
        ss << "File Hash: " << fileHash << "\r\n";
        ss << "File Signature: " << fileSignature << "\r\n";
        ss << "Verification Result: ";
#endif
        // 如果数字签名全部为 0 则通过校验，否则调用原始校验函数
        for (char c : fileSignature) {
            if (c != '0') {
                bool result = _kRSAVerifyFile(publicKey, fileHash, fileSignature);
#if defined WP_DEBUG
                ss << (result ? "Passed" : "Failed");
                MessageBoxA(nullptr, ss.str().data(), "KRSAVerifyFile Debug Information", MB_ICONINFORMATION);
#endif
                return result;
            }
        }
#if defined WP_DEBUG
        ss << "Passed (all-zero signature)";
        MessageBoxA(nullptr, ss.str().data(), "KRSAVerifyFile Debug Information", MB_ICONINFORMATION);
#endif
        return true;
    }

    static void LocateTargetInRegion(std::span<const uint8_t> region) {
#if defined DETOURS_ARM64
        const std::array<uint16_t, 18> anchor = { 0x00, 0xD0, 0xFFFF, 0xFFFF, 0xFFFF, 0x91, 0xFFFF, 0xFFFF, 0x00, 0xD0, 0xFFFF, 0xFFFF, 0xFFFF, 0x91, 0xFFFF, 0x5A, 0x00, 0xA9 };
        const std::array<uint16_t, 4> prologue = { 0xFD, 0xFFFF, 0xFFFF, 0xA9 };
#elif defined DETOURS_X64
        const std::array<uint16_t, 21> anchor = { 0x4C, 0x8D, 0x3D, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x4C, 0x89, 0x3F, 0x4C, 0x8D, 0x25, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x4C, 0x89, 0x67, 0x08 };
        const std::array<uint16_t, 3> prologue = { 0x40, 0x53, 0x56 };
#elif defined DETOURS_X86
        const std::array<uint16_t, 25> anchor = { 0xC7, 0x06, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xC7, 0x46, 0x04, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xEB, 0x02, 0x33, 0xF6, 0x83, 0x7F, 0x14, 0x10, 0xC6, 0x45, 0xFC, 0x00 };
        const std::array<uint16_t, 3> prologue = { 0x55, 0x8B, 0xEC };
#else
#error "Unsupported architecture"
#endif

#if defined WP_DEBUG
        constexpr size_t maxMatches = 2;
#else
        constexpr size_t maxMatches = 1;
#endif

        std::vector<const uint8_t*> anchors = PatternUtil::FindPattern(region, anchor, 0, false, maxMatches);
        if (anchors.empty()) {
            throw std::runtime_error("Failed to find KRSAVerifyFile anchor");
        }
#if defined WP_DEBUG
        if (anchors.size() > 1) {
            throw std::runtime_error("Multiple KRSAVerifyFile anchors found");
        }
#endif
        std::vector<const uint8_t*> prologues = PatternUtil::FindPattern(region, prologue, anchors[0] - region.data(), true, 1);
        if (prologues.empty()) {
            throw std::runtime_error("Failed to find KRSAVerifyFile prologue");
        }

        _kRSAVerifyFile = reinterpret_cast<decltype(_kRSAVerifyFile)>(prologues[0]);
    }

    IFunctionHook::HookTarget KRSAVerifyFileHook::LocateTarget() const {
        std::span<const uint8_t> region = GetSearchRegion();
        if (region.empty()) {
            throw std::runtime_error("Failed to get memory region for search");
        }
        LocateTargetInRegion(region);
        return {
            reinterpret_cast<PVOID*>(&_kRSAVerifyFile),
            reinterpret_cast<PVOID>(KRSAVerifyFile)
        };
    }

    std::span<const uint8_t> KRSAVerifyFilePacketHook::GetSearchRegion() const {
        HMODULE module = ModuleUtil::GetHandleW(std::nullopt);
        return ModuleUtil::GetMemoryRegion(module);
    }

    IFunctionHook::HookTarget KRSAVerifyFilePacketHook::LocateTarget() const {
        return KRSAVerifyFileHook::LocateTarget();
    }

    const char* KRSAVerifyFilePacketHook::GetName() const {
        return "KRSAVerifyFilePacketHook";
    }

    std::span<const uint8_t> KRSAVerifyFileKrtHook::GetSearchRegion() const {
        HMODULE module = ModuleUtil::GetSelfHandle();
        std::wstring basePath = ModuleUtil::GetBasePathW(module);
        std::wstring krtPath = basePath + L"krt.dll";

        if (FileUtil::IsFileExistsW(krtPath)) {
            HMODULE krtModule = LoadLibraryW(krtPath.data());
            if (!krtModule) {
                throw std::runtime_error("Failed to load krt.dll");
            }
            return ModuleUtil::GetMemoryRegion(krtModule);
        }
        throw std::runtime_error("krt.dll not found");
    }

    IFunctionHook::HookTarget KRSAVerifyFileKrtHook::LocateTarget() const {
        return KRSAVerifyFileHook::LocateTarget();
    }

    const char* KRSAVerifyFileKrtHook::GetName() const {
        return "KRSAVerifyFileKrtHook";
    }

    std::span<const uint8_t> KRSAVerifyFileConfigCenterHook::GetSearchRegion() const {
#if defined DETOURS_X86
#define KBASECONFIGCENTER_SUFFIX_W L""
#define KBASECONFIGCENTER_SUFFIX ""
#else
#define KBASECONFIGCENTER_SUFFIX_W L"64"
#define KBASECONFIGCENTER_SUFFIX "64"
#endif

        HMODULE module = ModuleUtil::GetSelfHandle();
        std::wstring basePath = ModuleUtil::GetBasePathW(module);

        std::wstring dllPath = basePath + L"kbaseconfigcenter" KBASECONFIGCENTER_SUFFIX_W L".dll";

        if (FileUtil::IsFileExistsW(dllPath)) {
            HMODULE targetModule = LoadLibraryW(dllPath.data());
            if (!targetModule) {
                throw std::runtime_error("Failed to load kbaseconfigcenter" KBASECONFIGCENTER_SUFFIX ".dll");
            }
            return ModuleUtil::GetMemoryRegion(targetModule);
        }
        throw std::runtime_error("kbaseconfigcenter" KBASECONFIGCENTER_SUFFIX ".dll not found");
    }

    IFunctionHook::HookTarget KRSAVerifyFileConfigCenterHook::LocateTarget() const {
        return KRSAVerifyFileHook::LocateTarget();
    }

    const char* KRSAVerifyFileConfigCenterHook::GetName() const {
        return "KRSAVerifyFileConfigCenterHook";
    }
}
