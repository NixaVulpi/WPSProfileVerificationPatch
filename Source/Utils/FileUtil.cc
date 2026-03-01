#include <Windows.h>
#include "FileUtil.h"

namespace WPSProfileVerificationPatch {
    bool FileUtil::IsFileExistsA(const std::string& filePath) {
        DWORD attributes = GetFileAttributesA(filePath.data());
        return (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY));
    }

    bool FileUtil::IsFileExistsW(const std::wstring& filePath) {
        DWORD attributes = GetFileAttributesW(filePath.data());
        return (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY));
    }

    bool FileUtil::EndsWithA(const std::string& filePath, const std::string& suffix) {
        if (filePath.length() < suffix.length()) {
            return false;
        }

        LPCSTR tail = filePath.data() + (filePath.length() - suffix.length());
        int result = CompareStringA(LOCALE_INVARIANT, NORM_IGNORECASE, tail, static_cast<int>(suffix.size()), suffix.data(), static_cast<int>(suffix.size()));
        return result == CSTR_EQUAL;
    }

    bool FileUtil::EndsWithW(const std::wstring& filePath, const std::wstring& suffix) {
        if (filePath.size() < suffix.size()) {
            return false;
        }

        LPCWSTR tail = filePath.data() + (filePath.size() - suffix.size());
        int result = CompareStringOrdinal(tail, static_cast<int>(suffix.size()), suffix.data(), static_cast<int>(suffix.size()), TRUE);
        return result == CSTR_EQUAL;
    }
}
