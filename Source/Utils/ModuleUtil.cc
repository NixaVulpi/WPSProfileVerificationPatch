#include <Windows.h>
#include <Psapi.h>
#include <stdexcept>
#include "ModuleUtil.h"

namespace WPSProfileVerificationPatch {
    HMODULE ModuleUtil::GetHandleA(const std::optional<const std::string>& moduleName) {
        HMODULE module = GetModuleHandleA(moduleName ? moduleName->data() : nullptr);
        if (module == nullptr) {
            throw std::runtime_error("Failed to get module handle");
        }
        return module;
    }

    HMODULE ModuleUtil::GetHandleW(const std::optional<const std::wstring>& moduleName) {
        HMODULE module = GetModuleHandleW(moduleName ? moduleName->data() : nullptr);
        if (module == nullptr) {
            throw std::runtime_error("Failed to get module handle");
        }
        return module;
    }

    HMODULE ModuleUtil::GetSelfHandle() {
        MEMORY_BASIC_INFORMATION memoryBasicInfo;
        if (!VirtualQuery(ModuleUtil::GetSelfHandle, &memoryBasicInfo, sizeof(memoryBasicInfo))) {
            throw std::runtime_error("Failed to get self module handle");
        }
        return reinterpret_cast<HMODULE>(memoryBasicInfo.AllocationBase);
    }

    std::string ModuleUtil::GetFileNameA(HMODULE module) {
        std::string buffer(MAX_PATH, 0);
        DWORD retSize = GetModuleFileNameA(module, buffer.data(), MAX_PATH);
        if (retSize == 0 || retSize >= MAX_PATH) {
            throw std::runtime_error("Failed to get program file name");
        }
        buffer.resize(retSize);
        return buffer;
    }

    std::wstring ModuleUtil::GetFileNameW(HMODULE module) {
        std::wstring buffer(MAX_PATH, 0);
        DWORD retSize = GetModuleFileNameW(module, buffer.data(), MAX_PATH);
        if (retSize == 0 || retSize >= MAX_PATH) {
            throw std::runtime_error("Failed to get program file name");
        }
        buffer.resize(retSize);
        return buffer;
    }

    std::string ModuleUtil::GetBasePathA(HMODULE module) {
        std::string fileName = GetFileNameA(module);
        size_t position = fileName.find_last_of("\\");
        if (position == std::string::npos) {
            throw std::runtime_error("Failed to get program base path");
        }
        fileName.resize(position + 1);
        return fileName;
    }

    std::wstring ModuleUtil::GetBasePathW(HMODULE module) {
        std::wstring fileName = GetFileNameW(module);
        size_t position = fileName.find_last_of(L"\\");
        if (position == std::wstring::npos) {
            throw std::runtime_error("Failed to get program base path");
        }
        fileName.resize(position + 1);
        return fileName;
    }

    size_t ModuleUtil::GetSize(HMODULE module) {
        if (!module) {
            module = GetHandleW(std::nullopt);
        }
        MODULEINFO mi;
        if (!GetModuleInformation(GetCurrentProcess(), module, &mi, sizeof(mi))) {
            throw std::runtime_error("Failed to get program module size");
        }
        return mi.SizeOfImage;
    }

    std::span<const uint8_t> ModuleUtil::GetMemoryRegion(HMODULE module) {
        if (!module) {
            module = GetHandleW(std::nullopt);
        }
        return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(module), GetSize(module));
    }
}
