#pragma once

#include <boost/property_tree/ptree.hpp>
#include <string>
#include <optional>

namespace rgs::central {

    class PolicyManager {
    public:
        PolicyManager(const PolicyManager&) = delete;
        PolicyManager& operator=(const PolicyManager&) = delete;

        static PolicyManager& getInstance() {
            static PolicyManager instance;
            return instance;
        }

        bool load(const std::string& filename);

        template<typename T>
        T get(const std::string& path, const T& defaultValue) {
            return m_tree.get<T>(path, defaultValue);
        }

    private:
        PolicyManager() = default;
        boost::property_tree::ptree m_tree;
    };

} // namespace rgs::central
