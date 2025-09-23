#pragma once

#include <windows.h>
#include <string>
#include <map>
#include <mutex>
#include <optional>
#include "MinHook.h"

namespace rgs::sdk::hooks {

    enum class HookState {
        Unknown,
        Created,
        Enabled,
        Disabled,
        Error
    };

    struct HookInfo {
        void* targetAddress = nullptr;
        void* detourFunction = nullptr;
        void* originalFunction = nullptr; // Trampoline
        HookState state = HookState::Unknown;
        MH_STATUS lastError = MH_OK;
    };

    class HookManager {
    public:
        static HookManager& getInstance();

        bool initialize();
        void shutdown();

        bool installHook(const std::string& id, void* targetAddress, void* detourFunction);
        bool removeHook(const std::string& id);
        bool enableHook(const std::string& id);
        bool disableHook(const std::string& id);

        std::optional<HookState> getHookState(const std::string& id);
        template<typename T>
        T getOriginal(const std::string& id);

    private:
        HookManager() = default;

        std::map<std::string, HookInfo> m_hooks;
        mutable std::mutex m_mutex;
        bool m_isInitialized = false;
    };

    template<typename T>
    T HookManager::getOriginal(const std::string& id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hooks.find(id);
        if (it != m_hooks.end() && it->second.originalFunction) {
            return static_cast<T>(it->second.originalFunction);
        }
        return nullptr;
    }

} // namespace rgs::sdk::hooks
