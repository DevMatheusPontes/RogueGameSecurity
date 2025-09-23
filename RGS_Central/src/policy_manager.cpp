#include "policy_manager.hpp"
#include <boost/property_tree/json_parser.hpp>

namespace rgs::central {

    bool PolicyManager::load(const std::string& filename) {
        try {
            boost::property_tree::read_json(filename, m_tree);
            return true;
        }
        catch (const std::exception&) {
            // In a real app, log this error.
            return false;
        }
    }

} // namespace rgs::central
