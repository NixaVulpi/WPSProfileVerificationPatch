#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <memory>
#include <span>

namespace WPSProfileVerificationPatch {
    class WPSProductUtil {
    private:
        WPSProductUtil() = delete;

    public:
        static bool IsWPSOfficeProcess();
    };
}
