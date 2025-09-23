#pragma once

#include "session.hpp"
#include "dispatcher.hpp"
#include <boost/asio.hpp>
#include <string>
#include <memory>

namespace rgs::sdk::network {

    using boost::asio::ip::tcp;

    // Forward declaration
    class Dispatcher;

    class Server {
    public:
        using SessionHandler = std::function<void(std::shared_ptr<Session>)>;

        Server(boost::asio::io_context& io_context, uint16_t port, Dispatcher& dispatcher);

        void start();
        void stop();

        void setSessionHandler(SessionHandler handler) { m_sessionHandler = handler; }

    private:
        void doAccept();

        boost::asio::io_context& m_io_context;
        tcp::acceptor m_acceptor;
        Dispatcher& m_dispatcher;
        SessionHandler m_sessionHandler;
    };

    class Client {
    public:
        Client(boost::asio::io_context& io_context, const std::string& host, uint16_t port, Dispatcher& dispatcher);

        void start();
        void stop();

        std::shared_ptr<Session> getSession() const { return m_session; }

    private:
        void doConnect();
        void handleConnect(const boost::system::error_code& ec);
        void scheduleReconnect();

        boost::asio::io_context& m_io_context;
        tcp::resolver m_resolver;
        tcp::endpoint m_endpoint;
        Dispatcher& m_dispatcher;
        std::shared_ptr<Session> m_session;
        
        boost::asio::steady_timer m_reconnectTimer;
        std::chrono::seconds m_reconnectInterval;
        const std::chrono::seconds m_maxReconnectInterval = std::chrono::seconds(60);

        std::atomic<bool> m_isStopped{false};
    };

} // namespace rgs::sdk::network
