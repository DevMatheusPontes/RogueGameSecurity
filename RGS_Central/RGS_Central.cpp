#include "network/io_context_pool.hpp"
#include "network/server_acceptor.hpp"
#include "network/protocol.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <locale>
#include <clocale>

using namespace rgs::modules::network;

int main() {
    try {
        // Força locale para UTF-8 (corrige acentuação no console)
        std::setlocale(LC_ALL, "pt_BR.UTF-8");

        IoContextPool pool(4);
        auto& io = pool.next();

        ServerAcceptor acceptor(io, 7777);

        acceptor.onClientConnected([](std::shared_ptr<Session> s) {
            std::cout << "[Central] Nova conexão recebida\n";

            // Envia mensagem de boas-vindas usando o protocolo
            ProtocolMessage msg = ProtocolMessage::fromString(
                MessageType::Hello,
                "Welcome to RGS_Central!"
            );
            s->send(msg);
        });

        acceptor.start();
        pool.run();

        // Mantém o Central ativo até o usuário encerrar manualmente
        std::cout << "[Central] Servidor em execução. Pressione ENTER para encerrar...\n";
        std::cin.get();

        // Encerramento limpo
        acceptor.stop();
        pool.stop();

    } catch (const std::exception& e) {
        // Em vez de encerrar, apenas loga o erro e continua
        std::cerr << "[Central] Erro capturado: " << e.what() << std::endl;
        std::cout << "[Central] Continuando em execução. Pressione ENTER para encerrar...\n";
        std::cin.get();
    } catch (...) {
        std::cerr << "[Central] Erro desconhecido capturado.\n";
        std::cout << "[Central] Continuando em execução. Pressione ENTER para encerrar...\n";
        std::cin.get();
    }

    return 0;
}