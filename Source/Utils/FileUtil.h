#pragma once
#include <string>

namespace WPSProfileVerificationPatch {
    class FileUtil {
    private:
        FileUtil() = delete;

    public:
        static bool IsFileExistsA(const std::string& filePath);
        static bool IsFileExistsW(const std::wstring& filePath);
        static bool EndsWithA(const std::string& filePath, const std::string& suffix);
        static bool EndsWithW(const std::wstring& filePath, const std::wstring& suffix);
    };
}
