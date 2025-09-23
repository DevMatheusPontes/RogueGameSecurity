#include "transport.hpp"
#include "dispatcher.hpp"
#include "../utils/config.hpp"

namespace rgs::sdk::network {

    // --- Server Implementation ---
    Server::Server(boost::asio::io_context& io_context, uint16_t port, Dispatcher& dispatcher)
        : m_io_context(io_context),
          m_acceptor(io_context, tcp::endpoint(tcp::v4(), port)),
          m_dispatcher(dispatcher) {}

    void Server::start() {
        doAccept();
    }

    void Server::stop() {
        m_acceptor.close();
    }

    void Server::doAccept() {
        m_acceptor.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
            if (!ec) {
                auto& config = utils::Config::getInstance();
                auto heartbeat_interval = std::chrono::seconds(config.get<long>("network.heartbeat_interval_seconds").value_or(15));
                auto inactivity_timeout = std::chrono::seconds(config.get<long>("network.inactivity_timeout_seconds").value_or(60));

                auto session = std::make_shared<Session>(std::move(socket), heartbeat_interval, inactivity_timeout);
                
                if (m_sessionHandler) {
                    m_sessionHandler(session);
                }

                session->start();
            }
            
            if (m_acceptor.is_open()) {
                doAccept();
            }
        });
    }

    // --- Client Implementation ---
    Client::Client(boost::asio::io_context& io_context, const std::string& host, uint16_t port, Dispatcher& dispatcher)
        : m_io_context(io_context),
          m_resolver(io_context),
          m_dispatcher(dispatcher),
          m_reconnectTimer(io_context),
          m_reconnectInterval(std::chrono::seconds(1)) {
        m_endpoint = *m_resolver.resolve(host, std::to_string(port)).begin();
    }

    void Client::start() {
        m_isStopped = false;
        doConnect();
    }

    void Client::stop() {
        m_isStopped = true;
        m_reconnectTimer.cancel();
        if (m_session && m_session->isConnected()) {
            m_session->stop();
        }
    }

    void Client::doConnect() {
        if (m_isStopped) return;

        auto socket = std::make_shared<tcp::socket>(m_io_context);
        socket->async_connect(m_endpoint, [this, socket](const boost::system::error_code& ec) {
            if (!ec) {
                auto& config = utils::Config::getInstance();
                auto heartbeat_interval = std::chrono::seconds(config.get<long>("network.heartbeat_interval_seconds").value_or(15));
                auto inactivity_timeout = std::chrono::seconds(config.get<long>("network.inactivity_timeout_seconds").value_or(60));

                m_session = std::make_shared<Session>(std::move(*socket), heartbeat_interval, inactivity_timeout);
                
                // Reset reconnect interval on successful connection
                m_reconnectInterval = std::chrono::seconds(config.get<long>("network.reconnect_initial_interval_ms").value_or(1000) / 1000);

                // Setup handlers
                m_session->setMessageHandler([this](Message&& msg) {
                    m_dispatcher.dispatch(m_session, std::move(msg));
                });
                m_session->setDisconnectHandler([this]() {
                    m_session.reset();
                    scheduleReconnect();
                });

                m_session->start();
            } else {
                scheduleReconnect();
            }
        });
    }

    void Client::scheduleReconnect() {
        if (m_isStopped) return;

        m_reconnectTimer.expires_after(m_reconnectInterval);
        m_reconnectTimer.async_wait([this](const boost::system::error_code& ec) {
            if (!ec) {
                doConnect();
            }
        });

        // Exponential backoff
        m_reconnectInterval = std::min(m_reconnectInterval * 2, m_maxReconnectInterval);
    }

} // namespace rgs::sdk::network
