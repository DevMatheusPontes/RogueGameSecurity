# 06_config_logs_metrics.md - Configuração, Logs e Métricas

Este documento detalha a estrutura do arquivo de configuração `config.json`, a abordagem para logs e a coleta de métricas no sistema RogueGameSecurity.

## Configuração (`config.json`)

O `config.json` é o arquivo central para parametrizar o comportamento de todos os módulos do sistema. Ele é lido e gerenciado pelo `rgs::sdk::utils::Config` (para o SDK) e `rgs::central::PolicyManager` (para o RGS_Central), utilizando a biblioteca `Boost.PropertyTree` para parsing JSON.

### Estrutura Geral

O arquivo é dividido em seções lógicas, cada uma correspondendo a um módulo ou funcionalidade específica. Abaixo está um exemplo consolidado da estrutura e dos campos mais relevantes:

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
    "low_priority_size": 512,                // Capacidade da fila de baixa prioridade
    "low_priority_policy": "coalesce"       // Política para fila de baixa prioridade (ex: "coalesce", "drop")
  },
  "memory": {
    "max_read_size": 4096,              // Tamanho máximo permitido para leitura de buffer
    "max_write_size": 4096,             // Tamanho máximo permitido para escrita de buffer
    "allow_protected_write": false,     // Permitir escrita em regiões de memória protegidas (ex: código)
    "max_scan_time_ms": 5000            // Tempo máximo em ms para operações de scan de padrão
  },
  "hooks": {
    "max_active_hooks": 128,            // Número máximo de hooks ativos permitidos
    "allow_protected_hooks": false,     // Permitir hooks em regiões de memória protegidas
    "verify_on_install": true,          // Verificar integridade do patch após instalação
    "rollback_on_failure": true         // Reverter hook em caso de falha na verificação
  },
  "security": {
    "nonce_window_size": 1024,          // Tamanho da janela de nonces para proteção anti-replay
    "hash_type": "crc32",               // Tipo de hash padrão (ex: "crc32", "sha256")
    "reject_replay": true               // Ativar/desativar rejeição de nonces repetidos
  },
  "protection": {
    "event_rate_limit_per_minute": 100, // Limite de eventos por minuto para reporte
    "coalesce_duplicates": true,        // Ativar/desativar coalescimento de eventos duplicados
    "report_priority": "medium"         // Prioridade padrão para o envio de eventos (low, medium, high)
  },
  "central": {
    "port": 12345,                      // Porta TCP para o RGS_Central aceitar conexões
    "health_check_interval_seconds": 10 // Intervalo de verificação de saúde em segundos
  }
}
```

### Acesso à Configuração

Os valores são acessados através de `PolicyManager::getInstance().get<Type>("path.to.value", defaultValue)` ou `Config::getInstance().get<Type>("path.to.value", defaultValue)`.

## Logs (Boost.Log)

Embora `spdlog` tenha sido removido em favor de uma abordagem mais Boost-centric, a implementação de logs robustos seria feita com `Boost.Log`. Esta biblioteca oferece:

*   **Níveis de Log:** `trace`, `debug`, `info`, `warning`, `error`, `fatal`.
*   **Rotação de Arquivos:** Gerenciamento automático de arquivos de log por tamanho ou tempo.
*   **Filtros:** Capacidade de filtrar mensagens de log com base em nível, módulo ou conteúdo.
*   **Formatadores:** Personalização do formato das mensagens de log.
*   **Saídas Múltiplas:** Envio de logs para console, arquivo, syslog, etc.

**Exemplo de Uso (Conceitual):**

```cpp
// Configuração inicial (uma vez na inicialização)
// boost::log::add_file_log("sample.log");
// boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);

// Uso em qualquer parte do código
// BOOST_LOG_TRIVIAL(info) << "Mensagem informativa";
// BOOST_LOG_TRIVIAL(error) << "Ocorreu um erro: " << errorCode;
```

## Métricas

A coleta de métricas é crucial para monitorar o desempenho e a saúde do sistema. Embora não haja um módulo de métricas dedicado nesta fase, os componentes foram projetados para permitir a fácil integração de um sistema de métricas.

*   **Contadores:** Número de mensagens enviadas/recebidas, hooks instalados, eventos detectados.
*   **Latência:** Tempo médio de processamento de mensagens, tempo de resposta da rede.
*   **Filas:** Tamanho atual das filas de mensagens, taxa de descarte/coalescimento.
*   **Saúde:** Número de sessões ativas, tempo de atividade, falhas de conexão.

Essas métricas seriam expostas através de uma interface simples ou coletadas por um sistema de monitoramento externo.
