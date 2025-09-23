#pragma once

#include "message.hpp"
#include <functional>
#include <map>
#include <memory>
#include <boost/asio/strand.hpp>
#include <boost/asio/io_context.hpp>

namespace rgs::sdk::network {

    class Dispatcher {
    public:
        using MessageHandler = std::function<void(std::shared_ptr<class Session>, Message&&)>;

        explicit Dispatcher(boost::asio::io_context& io_context);

        /**
         * @brief Registers a handler for a specific message type.
         * @param type The message type to handle.
         * @param handler The function to be called when a message of 'type' is received.
         */
        void registerHandler(MessageType type, MessageHandler handler);

        /**
         * @brief Dispatches a message to its registered handler.
         * @param session The session that received the message.
         * @param message The message to dispatch.
         */
        void dispatch(std::shared_ptr<class Session> session, Message&& message);

    private:
        // Use a strand to ensure handlers for a given session are executed serially.
        boost::asio::strand<boost::asio::io_context::executor_type> m_strand;
        std::map<MessageType, MessageHandler> m_handlers;
    };

} // namespace rgs::sdk::network
