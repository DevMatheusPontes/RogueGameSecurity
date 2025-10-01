#pragma once

#include <unordered_map>
#include <functional>
#include <cstdint>
#include "message.hpp"
#include "handler.hpp"

namespace rgs::network {

// Dispatcher: registra handlers por service code e despacha mensagens.
class Dispatcher {
public:
    using HandlerFunc = std::function<void(const Message&)>;

    void register_handler(std::uint16_t service, HandlerFunc handler);

    void dispatch(const Message& msg) const;

private:
    std::unordered_map<std::uint16_t, HandlerFunc> handlers_;
};

} // namespace rgs::network