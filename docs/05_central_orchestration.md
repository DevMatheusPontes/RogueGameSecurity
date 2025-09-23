# 05_central_orchestration.md - Orquestração Central (RGS_Central)

O projeto `RGS_Central` é o coração do sistema RogueGameSecurity, responsável por gerenciar todas as conexões, rotear mensagens, monitorar a saúde dos componentes conectados e orquestrar o desligamento do sistema.

## Componentes Principais

### `PolicyManager`

Um singleton que carrega e fornece acesso às políticas de configuração do sistema, lidas do `config.json`.

*   **Carregamento:** Responsável por carregar o arquivo `config.json` na inicialização.
*   **Acesso a Políticas:** Permite que outros componentes acessem valores de configuração de forma centralizada e segura.

### `SessionManager`

Gerencia todas as sessões TCP ativas (`rgs::sdk::network::Session`) com os clientes e servidores.

*   **Registro:** Adiciona novas sessões quando uma conexão é estabelecida.
*   **Remoção:** Remove sessões quando a conexão é encerrada ou falha.
*   **Lookup:** Permite buscar sessões por ID único.
*   **Thread-Safe:** Todas as operações são protegidas por mutex para garantir segurança em ambientes concorrentes.

### `Router`

Responsável por direcionar as mensagens recebidas para os handlers apropriados.

*   **Integração com `Dispatcher`:** Registra handlers para diferentes tipos de mensagens (`MessageType`) no `rgs::sdk::network::Dispatcher`.
*   **Roteamento:** Quando uma mensagem é recebida, o `Dispatcher` a encaminha para o handler registrado no `Router`.
*   **Lógica de Negócio:** Os handlers do `Router` contêm a lógica para processar mensagens específicas (ex: heartbeats, telemetria, comandos).

### `HealthMonitor`

Monitora a saúde e o status das sessões conectadas.

*   **Verificações Periódicas:** Utiliza um `boost::asio::steady_timer` para realizar verificações regulares.
*   **Monitoramento de Heartbeats:** (Funcionalidade futura) Pode verificar o último tempo de heartbeat recebido de cada sessão para identificar inatividade.
*   **Integração com `SessionManager`:** Acessa as sessões gerenciadas pelo `SessionManager` para realizar as verificações.

### `ShutdownController`

Orquestra o processo de desligamento gracioso do `RGS_Central` e, futuramente, dos componentes conectados.

*   **Sinalização:** Responde a sinais do sistema operacional (SIGINT, SIGTERM) para iniciar o processo de desligamento.
*   **Parada do `io_context`:** Interrompe o `boost::asio::io_context`, que por sua vez cancela todas as operações assíncronas pendentes.
*   **Desligamento Coordenado:** (Funcionalidade futura) Pode enviar mensagens de `GOODBYE` para as sessões conectadas, aguardar confirmações e garantir que os recursos sejam liberados de forma segura.

## Fluxo de Operação

1.  Na inicialização, o `main()` do `RGS_Central` carrega as configurações via `PolicyManager`.
2.  Um `boost::asio::io_context` é criado para gerenciar todas as operações assíncronas.
3.  Instâncias de `SessionManager`, `Dispatcher`, `Router`, `HealthMonitor` e `ShutdownController` são criadas.
4.  O `Router` registra seus handlers no `Dispatcher`.
5.  Um `rgs::sdk::network::Server` é iniciado para aceitar conexões de entrada.
6.  Quando uma nova conexão é estabelecida, o `Server` notifica o `SessionManager`, que adiciona a nova sessão.
7.  Mensagens recebidas são despachadas pelo `Dispatcher` para o `Router`, que as processa.
8.  O `HealthMonitor` periodicamente verifica a saúde das sessões.
9.  Ao receber um sinal de desligamento, o `ShutdownController` inicia o processo de encerramento.

## Configuração

O comportamento da orquestração central é configurável via `config.json`:

```json
{
  "central": {
    "port": 12345,                      // Porta TCP para o RGS_Central aceitar conexões
    "health_check_interval_seconds": 10 // Intervalo de verificação de saúde em segundos
  }
}
```
