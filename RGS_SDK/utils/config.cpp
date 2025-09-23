#include "config.hpp"
#include <boost/property_tree/json_parser.hpp>

namespace rgs::sdk::utils {

    bool Config::load(const std::string& filename) {
        try {
            boost::property_tree::read_json(filename, m_tree);
            return true;
        }
        catch (const boost::property_tree::json_parser_error& e) {
            // Log the error in a real application
            return false;
        }
    }

} // namespace rgs::sdk::utils
