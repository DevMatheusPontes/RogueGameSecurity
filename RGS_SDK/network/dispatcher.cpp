#include "dispatcher.hpp"
#include "session.hpp"
#include <boost/asio/post.hpp>

namespace rgs::sdk::network {

    Dispatcher::Dispatcher(boost::asio::io_context& io_context)
        : m_strand(boost::asio::make_strand(io_context)) {}

    void Dispatcher::registerHandler(MessageType type, MessageHandler handler) {
        m_handlers[type] = handler;
    }

    void Dispatcher::dispatch(std::shared_ptr<Session> session, Message&& message) {
        auto it = m_handlers.find(message.getHeader().type);
        if (it != m_handlers.end()) {
            // Execute the handler within the strand to ensure serial execution per session if needed
            boost::asio::post(m_strand, [handler = it->second, session, message = std::move(message)]() mutable {
                handler(session, std::move(message));
            });
        } else {
            // Optional: Log or handle unregistered message types
        }
    }

} // namespace rgs::sdk::network
