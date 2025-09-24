#pragma once

#include <unordered_map>
#include <functional>
#include "network/message.hpp"
#include "network/service.hpp"

namespace rgs::sdk::network {

class Session; // forward-declaration

using ServiceHandler = std::function<void(const Message&, Session&)>;
using ErrorHandler   = std::function<void(const Message&, Session&)>;

class Dispatcher {
public:
    void register_handler(ServiceCode svc, ServiceHandler handler);
    void register_error_handler(ErrorHandler handler);

    void dispatch(const Message& msg, Session& session);

private:
    std::unordered_map<ServiceCode, ServiceHandler> handlers_;
    ErrorHandler error_handler_;
};

} // namespace rgs::sdk::network
