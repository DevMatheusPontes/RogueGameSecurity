#include "hash.hpp"
#include <boost/uuid/detail/sha1.hpp>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h> // via vcpkg: openssl

namespace rgs::sdk::security {

std::string Hash::sha1(const std::string& input) {
    boost::uuids::detail::sha1 sha1;
    sha1.process_bytes(input.data(), input.size());

    unsigned int digest[5];
    sha1.get_digest(digest);

    std::ostringstream oss;
    for (int i = 0; i < 5; ++i) {
        oss << std::hex << std::setw(8) << std::setfill('0') << digest[i];
    }
    return oss.str();
}

std::string Hash::sha256(const std::string& input) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash.data());
    return to_hex(hash);
}

std::string Hash::to_hex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (auto c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}

} // namespace rgs::sdk::security
