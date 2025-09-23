# 02_network.md - Módulo de Rede (RGS_SDK/network/)

O módulo `RGS_SDK/network/` fornece a infraestrutura para comunicação TCP assíncrona entre os componentes do sistema RogueGameSecurity. Ele é construído sobre `Boost.Asio` para garantir alta performance e não bloqueio.

## Protocolo Interno

Todas as mensagens trocadas seguem um protocolo de framing fixo, definido em `protocol.hpp`:

```cpp
#pragma pack(push, 1)
struct ProtocolHeader {
    uint32_t magic;       // Valor mágico para identificação do protocolo (0xRGSSEC)
    uint16_t version;     // Versão do protocolo (1)
    MessageType type;     // Tipo da mensagem (Handshake, Telemetry, Command, etc.)
    MessageFlags flags;   // Flags adicionais (Encrypted, Compressed, HighPriority, HasHmac)
    uint32_t length;      // Comprimento do payload da mensagem
    uint64_t nonce;       // Nonce para proteção anti-replay
    uint32_t crc32;       // CRC32 do payload para verificação de integridade
};
#pragma pack(pop)
```

*   **`magic`**: Um valor constante (`0xRGSSEC`) para identificar o início de uma mensagem válida do protocolo.
*   **`version`**: A versão atual do protocolo, permitindo compatibilidade futura.
*   **`type`**: Um `enum class MessageType` que categoriza a mensagem (controle, telemetria, comando, etc.).
*   **`flags`**: Um `enum class MessageFlags` para indicar características adicionais da mensagem, como criptografia, compressão, prioridade ou presença de HMAC.
*   **`length`**: O tamanho do payload da mensagem em bytes.
*   **`nonce`**: Um número único por mensagem, gerado pelo módulo de segurança, para prevenir ataques de replay.
*   **`crc32`**: Um checksum CRC32 do payload, usado para verificar a integridade dos dados recebidos.

## Sessões TCP (`Session`)

A classe `rgs::sdk::network::Session` representa uma conexão TCP assíncrona individual. Ela gerencia o ciclo de vida da conexão, incluindo leitura e escrita de dados, heartbeats e tratamento de desconexões.

*   **I/O Assíncrono:** Utiliza `boost::asio::async_read` e `boost::asio::async_write` para operações de rede não bloqueantes.
*   **Heartbeats:** Envia mensagens de heartbeat periodicamente e monitora a inatividade para detectar conexões mortas.
*   **Filas de Mensagens:** Possui filas internas (`boost::circular_buffer`) com diferentes prioridades (High, Medium, Low) para gerenciar o envio de mensagens, garantindo que mensagens críticas sejam processadas primeiro.
*   **Validação:** Realiza validação do cabeçalho do protocolo, verificação de nonce e CRC32 do payload em mensagens recebidas.

## Transporte (`Server` e `Client`)

O módulo de transporte fornece as classes `Server` e `Client` para estabelecer e gerenciar conexões TCP.

### `Server`

A classe `rgs::sdk::network::Server` aceita conexões de entrada de clientes.

*   **Aceitação Assíncrona:** Utiliza `boost::asio::async_accept` para aceitar novas conexões de forma não bloqueante.
*   **Gerenciamento de Sessões:** Para cada nova conexão, cria uma instância de `Session` e a integra com um `Dispatcher` para roteamento de mensagens.
*   **Callback de Nova Sessão:** Permite que o componente central (`RGS_Central`) seja notificado sobre novas sessões através de um `SessionHandler`.

### `Client`

A classe `rgs::sdk::network::Client` estabelece e mantém uma conexão com um servidor remoto (geralmente o `RGS_Central`).

*   **Conexão Assíncrona:** Utiliza `boost::asio::async_connect` para estabelecer a conexão.
*   **Reconexão com Backoff:** Em caso de desconexão, tenta reconectar automaticamente com um algoritmo de backoff exponencial configurável, evitando sobrecarga no servidor.
*   **Gerenciamento de Sessão:** Mantém uma instância de `Session` para a comunicação ativa.

## Roteamento de Mensagens (`Dispatcher`)

A classe `rgs::sdk::network::Dispatcher` é responsável por registrar e despachar handlers para diferentes tipos de mensagens.

*   **Registro de Handlers:** Permite associar funções de callback a `MessageType` específicos.
*   **Execução em Strands:** Garante que os handlers sejam executados de forma thread-safe, geralmente dentro de um `boost::asio::strand` para evitar condições de corrida ao acessar estados compartilhados.

## Configuração

O comportamento do módulo de rede é configurável via `config.json`:

```json
{
  "network": {
    "heartbeat_interval_seconds": 15,       // Intervalo entre heartbeats em segundos
    "inactivity_timeout_seconds": 60,       // Tempo limite de inatividade para desconexão em segundos
    "reconnect_initial_interval_ms": 1000,  // Intervalo inicial de reconexão em milissegundos
    "reconnect_max_interval_seconds": 60,   // Intervalo máximo de reconexão em segundos
    "hmac_enabled": false                   // Ativar/desativar HMAC (opcional, não implementado nesta fase)
  },
  "queues": {
    "high_priority_size": 128,              // Capacidade da fila de alta prioridade
    "medium_priority_size": 256,            // Capacidade da fila de média prioridade
    "low_priority_size": 512                // Capacidade da fila de baixa prioridade
  }
}
```
