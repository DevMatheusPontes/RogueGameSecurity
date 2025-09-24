#include "config.hpp"
#include <boost/algorithm/string.hpp>

namespace rgs::sdk::utils {

    bool Config::load(const std::string& filepath) {
        try {
            boost::property_tree::read_json(filepath, tree_);
            return true;
        }
        catch (...) {
            return false;
        }
    }

    std::optional<std::string> Config::get_string(const std::string& key) const {
        try {
            return tree_.get<std::string>(key);
        }
        catch (...) {
            return std::nullopt;
        }
    }

    std::optional<int> Config::get_int(const std::string& key) const {
        try {
            return tree_.get<int>(key);
        }
        catch (...) {
            return std::nullopt;
        }
    }

    std::optional<bool> Config::get_bool(const std::string& key) const {
        try {
            auto val = tree_.get<std::string>(key);
            boost::algorithm::to_lower(val);
            return (val == "true" || val == "1");
        }
        catch (...) {
            return std::nullopt;
        }
    }

} // namespace rgs::sdk::utils
