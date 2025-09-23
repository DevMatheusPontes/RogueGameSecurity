#include "nonce.hpp"
#include "random.hpp"
#include "../utils/config.hpp"
#include <algorithm>

namespace rgs::sdk::security {

    NonceManager& NonceManager::getInstance() {
        static NonceManager instance;
        return instance;
    }

    uint64_t NonceManager::newNonce() {
        return generateNonce();
    }

    bool NonceManager::isReplay(uint64_t sessionId, uint64_t nonce) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto& buffer = m_sessionNonces[sessionId];
        if (buffer.capacity() == 0) {
            auto& config = utils::Config::getInstance();
            buffer.set_capacity(config.get<size_t>("security.replay_window_size").value_or(1024));
        }

        if (std::find(buffer.begin(), buffer.end(), nonce) != buffer.end()) {
            return true; // Replay detected
        }

        buffer.push_back(nonce);
        return false;
    }

    void NonceManager::cleanUp() {
        // The circular buffer handles cleanup automatically.
        // This function could be used for more complex cleanup logic in the future,
        // like removing old sessions.
    }

} // namespace rgs::sdk::security
