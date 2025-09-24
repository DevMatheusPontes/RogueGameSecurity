#pragma once

#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <functional>

#include "network/session.hpp"
#include "network/message.hpp"

namespace rgs::sdk::network {

class SessionManager : public std::enable_shared_from_this<SessionManager> {
public:
    // Registra ou atualiza uma sessão autenticada (login -> session)
    void on_authenticated(const std::string& login, std::shared_ptr<Session> session);

    // Operações diretas
    void add_session(const std::string& login, std::shared_ptr<Session> session);
    void remove_session(const std::string& login);
    std::shared_ptr<Session> get_session(const std::string& login);

    // Envio de mensagens
    void send_to(const std::string& login, Message& msg);
    void send_to_many(const std::vector<std::string>& logins, Message& msg);
    void broadcast(Message& msg);

    // Iteração utilitária
    void for_each(const std::function<void(const std::string&, std::shared_ptr<Session>)>& fn);

private:
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_;
    std::mutex mutex_;
};

} // namespace rgs::sdk::network
