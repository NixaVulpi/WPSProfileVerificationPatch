#include "WpsProductUtil.h"
#include "VersionUtil.h"
#include "ModuleUtil.h"
#include <format>

namespace WPSProfileVerificationPatch {
    bool WPSProductUtil::IsWPSOfficeProcess() {
        std::wstring fileName = ModuleUtil::GetFileNameW(nullptr);
        std::unique_ptr<const uint8_t[]> versionInfoData = VersionUtil::GetVersionInfoDataW(fileName);
        std::optional<std::span<const uint8_t>> translation = VersionUtil::QueryVersionInfoValueW(versionInfoData, L"\\VarFileInfo\\Translation");
        if (!translation.has_value()) {
            return false;
        }
        uint16_t langId = *reinterpret_cast<const uint16_t*>(translation->data());
        uint16_t codePage = *reinterpret_cast<const uint16_t*>(translation->data() + 2);
        std::optional<std::span<const uint8_t>> productName = VersionUtil::QueryVersionInfoValueW(versionInfoData, std::format(L"\\StringFileInfo\\{:04x}{:04x}\\ProductName", langId, codePage));
        if (!productName.has_value() || productName->size() != 11 || std::memcmp(productName->data(), L"WPS Office", 22) != 0) {
            return false;
        }
        return true;
    }
}
