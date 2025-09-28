#pragma once

#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include "session.hpp"

namespace rgs::network {

class ConnectionManager {
public:
    void add(std::shared_ptr<Session> session);
    void remove(const std::string& id);
    std::shared_ptr<Session> get(const std::string& id);

    void broadcast(const std::vector<uint8_t>& data);
    std::size_t count() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_;
};

}