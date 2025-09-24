#pragma once

#include <string>
#include <unordered_map>
#include <optional>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace rgs::sdk::utils {

    class Config {
    public:
        bool load(const std::string& filepath);

        std::optional<std::string> get_string(const std::string& key) const;
        std::optional<int> get_int(const std::string& key) const;
        std::optional<bool> get_bool(const std::string& key) const;

    private:
        boost::property_tree::ptree tree_;
    };

} // namespace rgs::sdk::utils
