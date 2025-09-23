#include "hash.hpp"
#include <boost/crc.hpp>

namespace rgs::sdk::security {

    uint32_t computeCrc32(const std::vector<std::byte>& data) {
        boost::crc_32_type result;
        result.process_bytes(data.data(), data.size());
        return result.checksum();
    }

    bool verifyCrc32(const std::vector<std::byte>& data, uint32_t expectedCrc32) {
        return computeCrc32(data) == expectedCrc32;
    }

} // namespace rgs::sdk::security
