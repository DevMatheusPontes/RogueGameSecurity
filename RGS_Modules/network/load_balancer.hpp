#pragma once

#include <vector>
#include <string>
#include <atomic>
#include <mutex>

namespace rgs::network {

class LoadBalancer {
public:
    LoadBalancer();

    void addTarget(const std::string& host, uint16_t port);
    void clear();

    // Round-robin
    std::pair<std::string, uint16_t> next();

    // Retorna quantidade de alvos
    std::size_t size() const;

private:
    std::vector<std::pair<std::string, uint16_t>> targets_;
    mutable std::mutex mutex_;
    std::atomic<std::size_t> index_{0};
};

}