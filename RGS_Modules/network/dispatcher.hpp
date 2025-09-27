#pragma once
#include <functional>
#include <unordered_map>
#include <memory>
#include "message.hpp"

namespace rgs::modules::network {

class Session; // forward

using Handler = std::function<void(std::shared_ptr<Session>, const Message&)>;

class Dispatcher {
public:
    void registerHandler(ServiceCode svc, Handler h);
    bool dispatch(std::shared_ptr<Session> session, const Message& msg);

private:
    std::unordered_map<uint8_t, Handler> handlers_;
};

} // namespace rgs::modules::network