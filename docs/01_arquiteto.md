# 01_arquiteto.md - Visão Geral da Arquitetura RogueGameSecurity

## Camadas do Sistema

O sistema RogueGameSecurity é composto por três projetos principais e um SDK compartilhado, organizados em camadas para modularidade e reutilização:

1.  **RGS_SDK (Software Development Kit):**
    *   **Propósito:** Fornecer um conjunto de utilitários e abstrações de baixo nível para funcionalidades comuns a todos os componentes do sistema.
    *   **Módulos:**
        *   `network/`: Comunicação TCP assíncrona, protocolo de mensagens, sessões, transporte.
        *   `memory/`: Acesso seguro à memória, resolução de ponteiros, scan de padrões, registro de offsets.
        *   `hooks/`: Gerenciamento de hooks (MinHook), proteção contra reentrada.
        *   `security/`: Hashing, geração de nonces, proteção anti-replay, geração de números aleatórios.
        *   `utils/`: Utilitários gerais, como carregamento de configurações (`config.json`).
    *   **Características:** Independente de plataforma (exceto Win32 APIs específicas), reutilizável, focado em segurança e desempenho.

2.  **RGS_Central:**
    *   **Propósito:** Orquestrar a comunicação e o estado de todos os clientes e servidores conectados. Atua como o ponto central de coleta de telemetria, distribuição de comandos e aplicação de políticas.
    *   **Componentes:**
        *   `SessionManager`: Gerencia sessões ativas, registra conexões, associa IDs e tipos.
        *   `Router`: Roteia mensagens recebidas para os destinos corretos com base em tipo e prioridade.
        *   `HealthMonitor`: Monitora a saúde das sessões (heartbeats, timeouts).
        *   `PolicyManager`: Carrega e gerencia políticas de configuração.
        *   `ShutdownController`: Orquestra o desligamento gracioso do sistema.
    *   **Características:** Aplicação console, persistente, escalável, utiliza `Boost.Asio` para concorrência.

3.  **RGS_Server:**
    *   **Propósito:** Componente injetado em processos de servidor de jogo. Coleta informações específicas do servidor e as reporta ao `RGS_Central`. Pode receber comandos do central.
    *   **Componentes:**
        *   `ServerCore`: Gerencia a conexão TCP assíncrona com o `RGS_Central`, timers, thread pool e filas internas de mensageria.
    *   **Características:** DLL injetável, leve, não bloqueante para o processo hospedeiro.

4.  **RGS_Client:**
    *   **Propósito:** Componente injetado em processos de cliente de jogo. Monitora o ambiente do cliente, intercepta eventos, aplica detecções e reporta ao `RGS_Central`.
    *   **Componentes:**
        *   `ClientCore`: Gerencia a conexão TCP assíncrona com o `RGS_Central`, timers, thread pool e filas internas de mensageria.
        *   `ProtectionPipeline`: Orquestra o fluxo de detecção, desde a interceptação até o reporte.
        *   `EventInterceptor`: Intercepta eventos relevantes no processo do cliente.
        *   `Reporter`: Agrupa, limita e envia eventos detectados ao `RGS_Central`.
    *   **Características:** DLL injetável, leve, não bloqueante, focado em proteção e detecção.

## Fluxo de Dados e Comunicação

A comunicação é baseada em TCP assíncrono, utilizando o módulo `network` do `RGS_SDK`.

*   **Conexão:** `RGS_Server` e `RGS_Client` iniciam conexões com o `RGS_Central`. O `RGS_Central` atua como um servidor TCP, aceitando múltiplas conexões.
*   **Protocolo:** Todas as mensagens seguem um protocolo interno definido em `RGS_SDK/network/protocol.hpp`, incluindo cabeçalho com `magic`, `version`, `type`, `flags`, `length`, `nonce` e `crc32`.
*   **Segurança:** Nonces são usados para proteção anti-replay e CRC32 para verificação de integridade do payload.
*   **Roteamento:** O `RGS_Central` utiliza um `Dispatcher` e um `Router` para processar mensagens recebidas e encaminhá-las para a lógica apropriada ou para outras sessões.
*   **Heartbeats:** Mensagens de heartbeat são trocadas periodicamente para monitorar a saúde das sessões.
*   **Reconexão:** Clientes e servidores implementam lógica de reconexão com backoff exponencial em caso de desconexão.

## Concorrência e Desempenho

*   **Boost.Asio:** Utilizado extensivamente para operações de I/O assíncronas, garantindo que as operações de rede não bloqueiem o thread principal.
*   **io_context:** Cada componente principal (`RGS_Central`, `ServerCore`, `ClientCore`) possui seu próprio `io_context` e `thread_pool` dedicados para processamento de eventos.
*   **Strands:** Usados para garantir a execução serial de handlers para estados compartilhados, evitando condições de corrida sem a necessidade de locks grosseiros.
*   **Filas Bounded:** Implementadas para gerenciar o fluxo de mensagens, aplicando políticas de backpressure e coalescimento.
