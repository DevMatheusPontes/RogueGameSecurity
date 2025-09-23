#pragma once

#include <boost/property_tree/ptree.hpp>
#include <string>
#include <optional>

namespace rgs::sdk::utils {

    class Config {
    public:
        Config(const Config&) = delete;
        Config& operator=(const Config&) = delete;

        static Config& getInstance() {
            static Config instance;
            return instance;
        }

        bool load(const std::string& filename);

        template<typename T> 
        std::optional<T> get(const std::string& path) {
            return m_tree.get_optional<T>(path);
        }

    private:
        Config() = default;
        boost::property_tree::ptree m_tree;
    };

} // namespace rgs::sdk::utils
