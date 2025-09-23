#pragma once

#include <cstdint>
#include <mutex>
#include <map>
#include <boost/circular_buffer.hpp>

namespace rgs::sdk::security {

    class NonceManager {
    public:
        static NonceManager& getInstance();

        uint64_t newNonce();
        bool isReplay(uint64_t sessionId, uint64_t nonce);
        void cleanUp(); // To be called periodically

    private:
        NonceManager() = default;

        // Map session ID to a circular buffer of recent nonces
        std::map<uint64_t, boost::circular_buffer<uint64_t>> m_sessionNonces;
        mutable std::mutex m_mutex;
    };

} // namespace rgs::sdk::security
