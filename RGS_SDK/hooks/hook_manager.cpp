#include "hook_manager.hpp"

namespace rgs::sdk::hooks {

    HookManager& HookManager::getInstance() {
        static HookManager instance;
        return instance;
    }

    bool HookManager::initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_isInitialized) return true;

        if (MH_Initialize() != MH_OK) {
            return false;
        }
        m_isInitialized = true;
        return true;
    }

    void HookManager::shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized) return;

        for (auto const& [id, info] : m_hooks) {
            if (info.state == HookState::Enabled) {
                MH_DisableHook(info.targetAddress);
            }
        }
        m_hooks.clear();

        MH_Uninitialize();
        m_isInitialized = false;
    }

    bool HookManager::installHook(const std::string& id, void* targetAddress, void* detourFunction) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isInitialized || m_hooks.count(id)) return false;

        HookInfo info;
        info.targetAddress = targetAddress;
        info.detourFunction = detourFunction;

        info.lastError = MH_CreateHook(targetAddress, detourFunction, &info.originalFunction);
        if (info.lastError != MH_OK) {
            info.state = HookState::Error;
            m_hooks[id] = info;
            return false;
        }
        info.state = HookState::Created;
        m_hooks[id] = info;

        return enableHook(id);
    }

    bool HookManager::removeHook(const std::string& id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hooks.find(id);
        if (it == m_hooks.end()) return false;

        disableHook(id);

        it->second.lastError = MH_RemoveHook(it->second.targetAddress);
        if (it->second.lastError != MH_OK) {
            it->second.state = HookState::Error;
            return false;
        }

        m_hooks.erase(it);
        return true;
    }

    bool HookManager::enableHook(const std::string& id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hooks.find(id);
        if (it == m_hooks.end() || it->second.state == HookState::Enabled) return false;

        it->second.lastError = MH_EnableHook(it->second.targetAddress);
        if (it->second.lastError != MH_OK) {
            it->second.state = HookState::Error;
            return false;
        }
        it->second.state = HookState::Enabled;
        return true;
    }

    bool HookManager::disableHook(const std::string& id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hooks.find(id);
        if (it == m_hooks.end() || it->second.state != HookState::Enabled) return false;

        it->second.lastError = MH_DisableHook(it->second.targetAddress);
        if (it->second.lastError != MH_OK) {
            it->second.state = HookState::Error;
            return false;
        }
        it->second.state = HookState::Disabled;
        return true;
    }

    std::optional<HookState> HookManager::getHookState(const std::string& id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hooks.find(id);
        if (it != m_hooks.end()) {
            return it->second.state;
        }
        return std::nullopt;
    }

} // namespace rgs::sdk::hooks
