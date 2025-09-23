# 04_client_protection.md - Proteções no Cliente (RGS_Client)

O projeto `RGS_Client` é responsável por monitorar e proteger o processo do cliente de jogo, interceptando eventos, aplicando regras de detecção e reportando atividades suspeitas ao `RGS_Central`.

## Arquitetura

A proteção no cliente é organizada em um pipeline, garantindo modularidade e extensibilidade:

1.  **`EventInterceptor`:** Componente responsável por capturar eventos brutos do processo do cliente (ex: chamadas de API, acessos à memória, modificações de arquivos). Nesta fase, a interceptação é simulada, focando na interface.
2.  **`ProtectionPipeline`:** O orquestrador central. Recebe eventos do `EventInterceptor`, aplica regras de detecção, normaliza os dados e os encaminha para o `Reporter`.
3.  **`Reporter`:** Agrupa, filtra e envia eventos processados para o `RGS_Central`, aplicando políticas de rate limit e coalescimento para otimizar o tráfego de rede.

## Componentes Principais

### `ClientCore`

O núcleo do `RGS_Client`, responsável pela inicialização e gerenciamento da conexão com o `RGS_Central`.

*   **Inicialização:** Iniciado via `DllMain` em `DLL_PROCESS_ATTACH`, garantindo uma inicialização leve e não bloqueante para o thread principal do processo injetado.
*   **Conexão TCP:** Utiliza `rgs::sdk::network::Client` para manter uma conexão assíncrona com o `RGS_Central`, com reconexão automática e heartbeats.
*   **Thread Pool:** Possui um `boost::asio::io_context` e um `boost::asio::thread_pool` dedicados para processar operações de rede e outras tarefas em segundo plano.
*   **Shutdown:** Em `DLL_PROCESS_DETACH`, realiza um desligamento limpo, cancelando timers, encerrando conexões e liberando recursos.

### `ProtectionPipeline`

O pipeline de detecção e processamento de eventos.

*   **Registro de Eventos:** Recebe eventos do `EventInterceptor` (ou de fontes simuladas).
*   **Aplicação de Regras:** Aplica um conjunto de regras configuráveis para identificar comportamentos suspeitos. As regras podem ser baseadas em padrões, frequência ou contexto.
*   **Normalização:** Transforma os eventos brutos em um formato padronizado para facilitar o processamento e o envio.
*   **Encaminhamento:** Envia os eventos processados para o `Reporter`.

### `EventInterceptor`

O ponto de entrada para a captura de eventos.

*   **Interface:** Define a interface para interceptar diferentes tipos de eventos (ex: `interceptAPICall`, `interceptMemoryAccess`).
*   **Simulação:** Nesta fase, a implementação real de interceptação de baixo nível (usando hooks ou outras técnicas) é um placeholder. O foco é na integração com o `ProtectionPipeline`.

### `Reporter`

Responsável pelo envio eficiente e seguro de eventos para o `RGS_Central`.

*   **Agrupamento/Coalescimento:** Agrupa eventos semelhantes ou repetidos para reduzir o volume de dados enviados.
*   **Rate Limit:** Controla a frequência de envio de eventos para evitar sobrecarga da rede e do `RGS_Central`.
*   **Envio Assíncrono:** Utiliza a `rgs::sdk::network::Session` para enviar mensagens de forma não bloqueante, com prioridade configurável (alta, média, baixa).
*   **Confirmação e Reenvio:** (Funcionalidade futura) Em caso de falha na entrega, pode implementar lógica de reenvio.

## Fluxo de Operação

1.  `DllMain` do `RGS_Client` inicia o `ClientCore`.
2.  `ClientCore` estabelece conexão com `RGS_Central` e inicia o `ProtectionPipeline`.
3.  `EventInterceptor` (simulado/real) captura eventos e os envia para o `ProtectionPipeline`.
4.  `ProtectionPipeline` processa os eventos, aplica regras e os encaminha para o `Reporter`.
5.  `Reporter` gerencia as filas de eventos, aplica rate limit e coalescimento, e envia os eventos para o `RGS_Central` via conexão TCP.
6.  `RGS_Central` recebe os eventos, os processa e toma as ações necessárias (log, alerta, comando de resposta).

## Configuração

O comportamento das proteções no cliente é configurável via `config.json`:

```json
{
  "protection": {
    "event_rate_limit_per_minute": 100, // Limite de eventos por minuto para reporte
    "coalesce_duplicates": true,        // Ativar/desativar coalescimento de eventos duplicados
    "report_priority": "medium"         // Prioridade padrão para o envio de eventos (low, medium, high)
  }
}
```
