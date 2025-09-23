# prompts.md - Prompts de Uso e Integração do RogueGameSecurity

Este documento consolida os prompts utilizados durante o desenvolvimento do projeto RogueGameSecurity, servindo como referência para futuras interações, automação e integração com outras ferramentas ou agentes.

## Prompts de Desenvolvimento (Etapas 1 a 10)

### Etapa 1: Configuração Inicial e Estrutura Básica

```markdown
Você é o agente responsável por configurar o ambiente de desenvolvimento inicial do projeto RogueGameSecurity. Sua tarefa é criar a estrutura de diretórios básica, o arquivo de solução do Visual Studio e os arquivos de projeto (.vcxproj) para RGS_Central, RGS_Server e RGS_Client, além de configurar o vcpkg.json.

📌 Diretrizes principais:
- Seguir estritamente o escopo e arquitetura definidos.
- Usar C++20 (MSVC, Win32/x86) e gerenciar dependências via vcpkg.
- Utilizar bibliotecas maduras para cada tarefa (Boost completo, spdlog, fmt, nlohmann-json, xxhash, OpenSSL opcional, MinHook, Catch2/GTest).
- Evitar código monolítico; sempre modular e reutilizável.
- Priorizar segurança, desempenho e clareza.
- Desenvolver por etapas curtas e verificáveis, mantendo contexto e consistência.
- Não criar módulos fora do escopo definido.
- Documentar cada etapa com comentários claros e atualizações nos docs.

🛠 Tarefas obrigatórias:

1.  **Estrutura de Diretórios:**
    - Criar a pasta raiz `RogueGameSecurity/`.
    - Dentro dela, criar as pastas:
        - `RGS_Central/`
        - `RGS_Server/`
        - `RGS_Client/`
        - `RGS_SDK/` (para o SDK compartilhado)

2.  **Arquivos de Projeto:**
    - Criar `RogueGameSecurity.sln` na raiz.
    - Criar `RGS_Central/RGS_Central.vcxproj` (aplicativo de console).
    - Criar `RGS_Server/RGS_Server.vcxproj` (DLL).
    - Criar `RGS_Client/RGS_Client.vcxproj` (DLL).

3.  **Configuração dos Projetos (.vcxproj):**
    - Para todos os projetos:
        - **PlatformToolset:** `v143`
        - **TargetPlatformVersion:** `10.0`
        - **ConfigurationType:** `Application` para `RGS_Central`, `DynamicLibrary` para `RGS_Server` e `RGS_Client`.
        - **CharacterSet:** `MultiByte`
        - **LanguageStandard:** `stdcpp20`
        - **WarningLevel:** `Level4`
        - **Optimization:** `MaxSpeed` para `Release`, `Disabled` para `Debug`.
        - **AdditionalIncludeDirectories:** Adicionar `$(SolutionDir)RGS_SDK` para que os projetos possam incluir headers do SDK.
        - **PreprocessorDefinitions:** `WIN32` para todos; `_DEBUG;_CONSOLE` para `RGS_Central` Debug; `NDEBUG;_CONSOLE` para `RGS_Central` Release; `_DEBUG;_WINDOWS;_USRDLL` para `RGS_Server`/`RGS_Client` Debug; `NDEBUG;_WINDOWS;_USRDLL` para `RGS_Server`/`RGS_Client` Release.

4.  **Arquivos de Código Iniciais:**
    - `RGS_Central/src/main.cpp` com um `main` vazio.
    - `RGS_Server/src/dllmain.cpp` com um `DllMain` vazio.
    - `RGS_Client/src/dllmain.cpp` com um `DllMain` vazio.

5.  **Configuração do Vcpkg:**
    - Criar `vcpkg.json` na raiz do projeto com as seguintes dependências:
        - `boost` (completo)
        - `spdlog`
        - `fmt`
        - `nlohmann-json`
        - `xxhash`
        - `openssl`
        - `minhook`
        - `catch2`

6.  **Compilação Inicial:**
    - Tentar compilar a solução para verificar se a configuração básica está correta.

🎯 Resultado esperado:
- Estrutura de diretórios criada.
- Arquivos de solução e projeto configurados.
- Arquivos de código iniciais criados.
- `vcpkg.json` configurado.
- Solução compilando sem erros.
```

### Etapa 2: Módulo de Rede (RGS_SDK/network/)

```markdown
Você é o agente responsável por executar a Etapa 2 do desenvolvimento do RogueGameSecurity, que consiste em:

1. Implementar o módulo de rede (`RGS_SDK/network/`) usando exclusivamente recursos do Boost já instalados via vcpkg.
2. Atualizar o arquivo `vcpkg.json` para remover pacotes redundantes que serão substituídos por funcionalidades do Boost.
3. Garantir que a solução compile limpa e que o módulo de rede esteja funcional para testes básicos de comunicação.

📌 Objetivo da Etapa:
- Criar o submódulo `RGS_SDK/network/` com todos os componentes necessários para comunicação TCP assíncrona robusta entre RGS_Central, RGS_Server e RGS_Client.
- Usar Boost.Asio para I/O assíncrono, Boost.Lockfree ou Boost.CircularBuffer para filas, Boost.Serialization para mensagens, Boost.CRC/Hash para integridade, Boost.MultiIndex para gestão de sessões.
- Remover do `vcpkg.json` bibliotecas que duplicam funcionalidades já presentes no Boost.

🛠 Tarefas obrigatórias:

1.  **Limpeza do vcpkg.json**
    - Abrir `vcpkg.json` na raiz da solução.
    - Remover as seguintes dependências redundantes:
      - `spdlog` → substituído por Boost.Log.
      - `fmt` → substituído por Boost.Format.
      - `nlohmann-json` → substituído por Boost.PropertyTree.
      - `xxhash` → substituído por Boost.CRC/Boost.Hash.
      - `catch2` → substituído por Boost.Test.
      - `openssl` (opcional) → manter apenas se necessário para criptografia forte; caso contrário, remover.
      - `minhook` → manter apenas se necessário para hooks; não é substituído pelo Boost.
    - Garantir que `boost` permaneça como dependência principal.
    - Salvar `vcpkg.json` atualizado.

2.  **Arquivos e classes do módulo de rede**
    - Criar:
      - `protocol.hpp/cpp`: definição do cabeçalho `{magic, version, type, flags, length, nonce}`, enums de tipos de mensagem, funções de validação.
      - `message.hpp/cpp`: estrutura de payload, builders/parsers, serialização com Boost.Serialization, validação de tamanho e integridade.
      - `session.hpp/cpp`: abstração de conexão TCP assíncrona, métodos `start()`, `stop()`, `asyncSend()`, `setHandler()`, `setHeartbeat()`.
      - `transport.hpp/cpp`: cliente/servidor TCP, reconexão com backoff exponencial, handshake, renegociação de versão.
      - `dispatcher.hpp/cpp`: registro e execução de handlers por tipo de mensagem, execução via strands, métricas por handler.

3.  **Funcionalidades obrigatórias**
    - Heartbeats periódicos e watchdog de inatividade.
    - Reconexão automática com backoff e cap configuráveis.
    - Filas bounded por prioridade (high/medium/low) usando Boost.Lockfree ou Boost.CircularBuffer.
    - Coalescimento de mensagens low-priority para reduzir overhead.
    - Métricas internas: contadores de mensagens enviadas/recebidas, latência média, tamanho médio de payload.

4.  **Segurança**
    - Integridade: Boost.CRC ou Boost.Hash para rotas padrão; HMAC opcional apenas se OpenSSL for mantido.
    - Anti-replay: janela de nonces; rejeição de duplicatas; limpeza periódica.
    - Validação de cabeçalho e payload antes de processar.

5.  **Configuração**
    - Parametrizar intervalos de heartbeat, timeouts, capacidades de fila e políticas de backpressure via Boost.PropertyTree lendo `config.json`.
    - Permitir habilitar/desabilitar HMAC via config.

📏 Regras específicas desta etapa:
- Não instalar bibliotecas que duplicam funcionalidades já presentes no Boost.
- Seguir convenções de nomes e namespaces do projeto.
- Usar RAII para recursos (sockets, timers, filas).
- Handlers devem ser curtos e não bloquear; trabalho pesado deve ir para thread pool (Boost.Asio::thread_pool).
- Documentar no log do agente cada ação executada.

🎯 Resultado esperado:
- `vcpkg.json` atualizado, contendo apenas dependências necessárias (Boost e outras não substituíveis).
- Módulo `RGS_SDK/network/` completo, compilando limpo.
- Teste básico de conexão TCP assíncrona com heartbeats e reconexão funcionando entre dois executáveis de teste.
```

### Etapa 3: Orquestração Central (RGS_Central)

```markdown
Você é o agente responsável por implementar a orquestração central do sistema RogueGameSecurity, dentro do projeto RGS_Central. Esta etapa conecta os módulos de rede do SDK com a lógica de controle, monitoramento e roteamento de mensagens entre RGS_Server e RGS_Client.

📌 Objetivo da Etapa:
- Criar os componentes centrais de controle no projeto RGS_Central.
- Integrar o módulo de rede do RGS_SDK para gerenciar sessões TCP assíncronas.
- Implementar roteamento de mensagens, monitoramento de saúde, políticas de fila e shutdown coordenado.

🛠 Tarefas obrigatórias:

1.  **Criar os seguintes componentes em RGS_Central/include e src:**
    - `SessionManager`: gerencia sessões ativas, registra conexões, associa IDs e tipos (server/client), fornece lookup e remoção.
    - `Router`: roteia mensagens recebidas para os destinos corretos com base em tipo e prioridade; aplica coalescimento e políticas de fila.
    - `HealthMonitor`: monitora heartbeats, latência, timeouts; atualiza estado de sessão (OK, DEGRADED, FAILED).
    - `PolicyManager`: carrega políticas de configuração (limites de fila, tamanho de mensagem, prioridades) via Boost.PropertyTree.
    - `ShutdownController`: executa desligamento coordenado, envia ordens de encerramento, aguarda confirmações e aplica rollback se necessário.

2.  **Integração com o SDK de rede**
    - Usar `rgs::sdk::network::Session` para criar e gerenciar conexões TCP.
    - Registrar handlers por tipo de mensagem usando `Dispatcher`.
    - Configurar heartbeats e reconexão com backoff.
    - Usar Boost.Asio::thread_pool para tarefas paralelas.

3.  **Funcionalidades obrigatórias**
    - Registro de sessão com ID único e tipo (server/client).
    - Roteamento por tipo de mensagem e prioridade.
    - Heartbeats periódicos e timeout configurável.
    - Métricas: contadores de mensagens, latência média, sessões ativas.
    - Shutdown limpo: envio de GOODBYE, flush de filas, cancelamento de timers.

4.  **Configuração**
    - Carregar `config.json` via Boost.PropertyTree.
    - Definir:
      - Intervalo de heartbeat.
      - Timeout de sessão.
      - Capacidade de fila por prioridade.
      - Política de backpressure (drop/refuse/coalesce).
      - Flags de segurança (ex: exigir nonce, habilitar HMAC).

📏 Regras específicas desta etapa:
- Não implementar lógica fora do projeto RGS_Central.
- Usar apenas recursos do Boost para timers, filas, parsing, logs e métricas.
- Seguir convenções de nomes e namespaces do projeto.
- Garantir que todos os componentes sejam modulares e testáveis.
- Documentar no log do agente cada ação executada.

🎯 Resultado esperado:
- Projeto RGS_Central com os componentes de orquestração implementados.
- Sessões TCP funcionando com heartbeats, reconexão e roteamento.
- Shutdown coordenado e monitoramento de saúde operacional.
- Código compilando limpo e pronto para testes com os módulos RGS_Server e RGS_Client.
```

### Etapa 4: Módulos Base das DLLs (RGS_Server e RGS_Client)

```markdown
Você é o agente responsável por implementar os módulos base das DLLs RGS_Server e RGS_Client do projeto RogueGameSecurity. Esta etapa estabelece a estrutura de inicialização, conexão TCP assíncrona com o núcleo central, timers e filas internas para mensageria.

📌 Objetivo da Etapa:
- Criar os componentes `ServerCore` e `ClientCore` dentro dos projetos RGS_Server e RGS_Client, respectivamente.
- Estabelecer conexão TCP assíncrona com o RGS_Central usando o SDK de rede.
- Implementar timers, thread pool e filas internas para envio/recebimento de mensagens.
- Garantir que a inicialização seja leve e segura, sem bloquear o thread principal do processo injetado.

🛠 Tarefas obrigatórias:

1.  **Criar os seguintes componentes:**
    - `ServerCore` (em RGS_Server/include e src)
    - `ClientCore` (em RGS_Client/include e src)

2.  **Inicialização**
    - Em `DllMain`, iniciar `ServerCore` ou `ClientCore` apenas em `DLL_PROCESS_ATTACH`.
    - Criar thread secundária dedicada para `io_context` e timers.
    - Evitar qualquer operação pesada ou bloqueante no thread principal.

3.  **Conexão TCP**
    - Usar `rgs::sdk::network::Session` para conectar ao RGS_Central.
    - Configurar reconexão com backoff, heartbeats e handlers por tipo de mensagem.
    - Registrar ID único e tipo (server/client) no handshake.

4.  **Mensageria**
    - Criar filas internas para envio e recebimento de mensagens.
    - Usar Boost.Lockfree ou Boost.CircularBuffer para filas bounded.
    - Implementar métodos:
      - `sendMessage(type, payload)`
      - `onMessageReceived(type, payload)`
      - `flushQueues()`

5.  **Timers e thread pool**
    - Usar Boost.Asio::steady_timer para heartbeats e tarefas periódicas.
    - Usar Boost.Asio::thread_pool (2–4 threads) para tarefas paralelas.
    - Garantir cancelamento seguro em `DLL_PROCESS_DETACH`.

6.  **Shutdown**
    - Em `DLL_PROCESS_DETACH`, cancelar timers, encerrar conexões, flush de filas e liberar recursos.
    - Enviar mensagem de `GOODBYE` ao central antes de encerrar.

📏 Regras específicas desta etapa:
- Não implementar lógica de memória, hooks ou proteção nesta etapa.
- Usar apenas recursos do Boost para rede, timers, filas e concorrência.
- Seguir convenções de nomes e namespaces do projeto.
- Documentar no log do agente cada ação executada.

🎯 Resultado esperado:
- Projetos RGS_Server e RGS_Client com `ServerCore` e `ClientCore` implementados.
- Conexão TCP assíncrona com o RGS_Central funcionando.
- Timers e thread pool operacionais.
- Inicialização leve e encerramento limpo via DllMain.
- Código compilando limpo e pronto para receber os módulos de memória, hooks e proteção nas próximas etapas.
```

### Etapa 5: Módulo de Memória (RGS_SDK/memory/)

```markdown
Você é o agente responsável por implementar o módulo de memória do SDK do projeto RogueGameSecurity. Esta etapa estabelece os componentes necessários para leitura/escrita segura de memória, resolução de ponteiros, scans por padrão e registro de offsets versionados.

📌 Objetivo da Etapa:
- Criar o submódulo `RGS_SDK/memory/` com utilitários reutilizáveis para acesso à memória, ponteiros, scans e offsets.
- Garantir que todas as operações sejam seguras, validadas e encapsuladas.
- Preparar o módulo para uso tanto pelo RGS_Server quanto pelo RGS_Client.

🛠 Tarefas obrigatórias:

1.  **Criar os seguintes arquivos e componentes:**
    - `memory_access.hpp/cpp`: funções genéricas para leitura e escrita de memória com validação.
    - `pointer_utils.hpp/cpp`: utilitários para resolver ponteiros com múltiplos offsets, validação de ponteiros e aritmética segura.
    - `offset_registry.hpp/cpp`: sistema de registro de offsets por nome/ID/versão, com verificação e rollback.
    - `scanner.hpp/cpp`: scanner de padrões de bytes com máscara, limites de tempo e escopo.

2.  **Funcionalidades obrigatórias**
    - `read<T>(uintptr_t address)` e `write<T>(uintptr_t address, T value)` com validação de página, permissões e tamanho.
    - `readBuffer(address, size)` e `writeBuffer(address, data)` com proteção temporária via `VirtualProtect`.
    - `resolvePointer(base, std::vector<uintptr_t> offsets)` com validação de cada salto.
    - `scanPattern(moduleBase, pattern, mask)` com resultado confiável e limite de tempo.
    - `registerOffset(name, id, version, address)` e `getOffset(id|name)` com auditoria e rollback.

3.  **Segurança**
    - Envolver todas as operações com SEH (`__try/__except`) para capturar exceções de acesso inválido.
    - Validar se o endereço está em uma página acessível (`IsBadReadPtr`, `VirtualQuery`).
    - Limitar tamanho máximo de leitura/escrita configurável via `config.json`.

4.  **Configuração**
    - Carregar limites e flags via Boost.PropertyTree (`config.json`):
      - Tamanho máximo de leitura/escrita.
      - Permitir ou não escrita em regiões protegidas.
      - Tempo máximo de scan.
      - Política de rollback de offsets.

📏 Regras específicas desta etapa:
- Não implementar lógica de hooks ou proteção nesta etapa.
- Usar apenas recursos do Boost e da API Win32.
- Garantir que todas as funções sejam modulares, reutilizáveis e seguras.
- Seguir convenções de nomes e namespaces do projeto.
- Documentar no log do agente cada ação executada.

🎯 Resultado esperado:
- Módulo `RGS_SDK/memory/` completo, compilando limpo.
- Funções de leitura/escrita, ponteiros, scans e offsets operacionais.
- Testes básicos de leitura/escrita e scan funcionando em ambiente controlado.
- Pronto para integração com os módulos RGS_Server e RGS_Client nas próximas etapas.
```

### Etapa 6: Módulo de Hooks (RGS_SDK/hooks/)

```markdown
Você é o agente responsável por implementar o módulo de hooks do SDK do projeto RogueGameSecurity. Esta etapa estabelece os componentes necessários para instalação, verificação e remoção segura de hooks, com proteção contra reentrada e auditoria de estado.

📌 Objetivo da Etapa:
- Criar o submódulo `RGS_SDK/hooks/` com utilitários reutilizáveis para gerenciamento de hooks.
- Usar a biblioteca MinHook (já instalada via vcpkg) para instalação de trampolines confiáveis.
- Implementar proteção contra reentrada e verificação de integridade dos patches aplicados.

🛠 Tarefas obrigatórias:

1.  **Criar os seguintes arquivos e componentes:**
    - `hook_manager.hpp/cpp`: gerenciador central de hooks, com registro por ID, instalação, verificação e remoção.
    - `trampoline.hpp/cpp`: abstração para criação de trampolines, preservação de prolog/epilog, cálculo de jump.
    - `patch_utils.hpp/cpp`: funções para aplicar/verificar patches, comparar bytes antes/depois, restaurar original.
    - `reentry_guard.hpp`: macros e helpers para proteção contra reentrada em funções hookadas.

2.  **Funcionalidades obrigatórias**
    - `installHook(id, targetAddress, detourFunction)` com validação e estado.
    - `verifyHook(id)` para checar se o patch está ativo e íntegro.
    - `removeHook(id)` com rollback seguro e confirmação.
    - `isHooked(id)` e `getHookState(id)` para consulta.
    - `HookStats`: estrutura com métricas (instalações, falhas, tempo médio, etc.).
    - `RGS_REENTRY_GUARD()` macro para evitar loops em funções hookadas.

3.  **Segurança**
    - Validar endereço alvo antes de aplicar patch.
    - Comparar bytes originais com esperados antes de instalar.
    - Usar `VirtualProtect` para alterar permissões temporariamente.
    - Restaurar bytes originais ao remover hook.
    - Proteger contra múltiplas instalações simultâneas.

4.  **Configuração**
    - Carregar limites e flags via Boost.PropertyTree (`config.json`):
      - Número máximo de hooks ativos.
      - Permitir ou não hooks em regiões protegidas.
      - Política de rollback em falha.
      - Ativar/desativar verificação periódica de integridade.

📏 Regras específicas desta etapa:
- Não implementar lógica de memória ou proteção nesta etapa.
- Usar MinHook para instalação de trampolines.
- Usar apenas recursos do Boost e da API Win32.
- Garantir que todas as funções sejam modulares, reutilizáveis e seguras.
- Seguir convenções de nomes e namespaces do projeto.
- Documentar no log do agente cada ação executada.

🎯 Resultado esperado:
- Módulo `RGS_SDK/hooks/` completo, compilando limpo.
- Hooks instaláveis, verificáveis e removíveis com segurança.
- Proteção contra reentrada funcional.
- Pronto para integração com os módulos RGS_Server e RGS_Client nas próximas etapas.
```

### Etapa 7: Módulo de Segurança (RGS_SDK/security/)

```markdown
Você é o agente responsável por implementar o módulo de segurança do SDK do projeto RogueGameSecurity. Esta etapa estabelece os componentes necessários para garantir integridade de mensagens, proteção contra replay e geração segura de nonces.

📌 Objetivo da Etapa:
- Criar o submódulo `RGS_SDK/security/` com utilitários reutilizáveis para hashing, verificação de integridade, gestão de nonces e geração segura de dados aleatórios.
- Garantir que todas as mensagens trocadas entre os módulos possam ser verificadas quanto à autenticidade e integridade.
- Preparar o módulo para uso em todas as camadas do sistema (central, servidor, cliente).

🛠 Tarefas obrigatórias:

1.  **Criar os seguintes arquivos e componentes:**
    - `hash.hpp/cpp`: funções para gerar hashes usando Boost.Hash ou Boost.CRC (ex: CRC32, SHA1).
    - `integrity.hpp/cpp`: verificação de integridade de payloads, suporte a HMAC opcional.
    - `nonce.hpp/cpp`: geração e gestão de nonces por sessão/mensagem, janela anti-replay.
    - `random.hpp/cpp`: PRNG seguro usando fontes do sistema (ex: `CryptGenRandom`, `std::random_device`).

2.  **Funcionalidades obrigatórias**
    - `computeHash(data)` → retorna hash do payload.
    - `verifyHash(data, expected)` → compara hash calculado com esperado.
    - `generateNonce()` → retorna nonce único e imprevisível.
    - `registerNonce(sessionId, nonce)` → armazena nonce usado.
    - `isReplay(sessionId, nonce)` → verifica se nonce já foi usado.
    - `cleanExpiredNonces()` → remove nonces antigos com base em tempo ou contagem.

3.  **Segurança**
    - Hashing leve e rápido para rotas padrão (Boost.CRC).
    - HMAC opcional para rotas sensíveis (se OpenSSL estiver mantido).
    - Nonces únicos por mensagem; rejeição de duplicatas.
    - Janela de replay configurável (ex: últimos 1000 nonces ou últimos 5 minutos).
    - Geração de dados aleatórios com entropia suficiente.

4.  **Configuração**
    - Carregar parâmetros via Boost.PropertyTree (`config.json`):
      - Tipo de hash (CRC32, SHA1, HMAC).
      - Tamanho da janela de replay.
      - Política de rejeição (silenciosa ou logada).
      - Ativar/desativar verificação de integridade por tipo de mensagem.

📏 Regras específicas desta etapa:
- Não implementar lógica de rede, memória ou hooks nesta etapa.
- Usar apenas recursos do Boost e da API Win32.
- Garantir que todas as funções sejam modulares, reutilizáveis e seguras.
- Seguir convenções de nomes e namespaces do projeto.
- Documentar no log do agente cada ação executada.

🎯 Resultado esperado:
- Módulo `RGS_SDK/security/` completo, compilando limpo.
- Hashing, verificação de integridade e proteção contra replay funcionando.
- Pronto para integração com o protocolo interno e os módulos de rede, servidor e cliente.
```

### Etapa 8: Proteções no Cliente (RGS_Client)

```markdown
Você é o agente responsável por executar duas tarefas sequenciais no projeto RogueGameSecurity:

1. Corrigir os pontos pendentes identificados na auditoria.
2. Implementar as rotinas de proteção no cliente (Etapa 8), dentro do projeto RGS_Client.

---

🛠 Parte 1 – Correções da Auditoria

1. Adicionar a flag `/permissive-` nos arquivos `.vcxproj` dos três projetos:
   - Abrir `RGS_Central.vcxproj`, `RGS_Server.vcxproj`, `RGS_Client.vcxproj`.
   - Em cada bloco `&lt;ClCompile&gt;` de Debug e Release, adicionar:
     ```xml
     &lt;AdditionalOptions&gt;/permissive- %(AdditionalOptions)&lt;/AdditionalOptions&gt;
     ```

2. Corrigir ambiente de compilação:
   - Verificar se o comando `msbuild` está disponível no terminal.
   - Se não estiver, instruir o usuário a abrir o **Developer Command Prompt for VS 2022**.
   - Compilar a solução com:
     ```
     msbuild RogueGameSecurity.sln /p:Configuration=Release /p:Platform=Win32
     ```

---

🛡 Parte 2 – Etapa 8: Proteções no Cliente (RGS_Client)

📌 Objetivo:
Implementar o módulo de proteção no cliente, responsável por interceptar eventos relevantes, aplicar regras de detecção e reportar ao núcleo central de forma eficiente e segura.

📦 Local de implementação:
- Projeto: `RGS_Client`
- Pastas: `include/` e `src/`

📁 Componentes a criar:
1. `ProtectionPipeline`: pipeline de detecção com encadeamento de regras, normalização de eventos e controle de envio.
2. `EventInterceptor`: interceptação de eventos no processo do cliente (ex: chamadas, acessos, modificações).
3. `Reporter`: agrupamento/coalescimento de eventos detectados e envio ao RGS_Central com prioridade e rate limit.

🔧 Funcionalidades obrigatórias:
- Registro de eventos interceptados com timestamp, tipo e contexto.
- Aplicação de regras configuráveis (ex: padrão de comportamento, frequência, origem).
- Normalização dos dados para envio.
- Rate limit por tipo de evento.
- Coalescimento de eventos repetidos.
- Envio assíncrono via `rgs::sdk::network::Session` com prioridade configurável.
- Confirmação de recebimento e reenvio em caso de falha.

⚙️ Configuração:
- Carregar regras e limites via `config.json` usando Boost.PropertyTree:
  - Tipos de eventos monitorados.
  - Limite de eventos por minuto.
  - Política de envio (imediato, batch, coalescido).
  - Prioridade por tipo de evento.

📏 Regras específicas:
- Não implementar lógica de memória ou hooks nesta etapa.
- Usar apenas recursos do Boost e do SDK.
- Garantir que todas as funções sejam modulares, reutilizáveis e seguras.
- Seguir convenções de nomes e namespaces do projeto.
- Documentar no log do agente cada ação executada.

🎯 Resultado esperado:
- Correções aplicadas nos `.vcxproj` e compilação validada.
- Projeto RGS_Client com `ProtectionPipeline`, `EventInterceptor` e `Reporter` implementados.
- Eventos interceptados, processados e enviados ao RGS_Central com controle de fluxo.
- Código compilando limpo e pronto para testes de proteção.
```

### Etapa 9: Testes e Validação & Atualização do vcpkg.json

```markdown
Você é o agente responsável por executar a Etapa 9 do projeto RogueGameSecurity, que consiste em:

1. Realizar testes e validações dos módulos já implementados.
2. Atualizar o arquivo `vcpkg.json` para conter apenas os pacotes realmente utilizados, removendo o Boost completo e mantendo apenas os submódulos necessários.

---

🧪 Parte 1 – Testes e Validação (Etapa 9)

📌 Objetivo:
Verificar o funcionamento dos principais componentes do sistema, incluindo rede, memória, hooks e proteção, garantindo estabilidade, segurança e desempenho.

📁 Componentes a testar:
- Rede (RGS_SDK/network/):
  - Teste de conexão TCP entre RGS_Central e RGS_Server/RGS_Client.
  - Heartbeats, reconexão e roteamento de mensagens.
  - Verificação de integridade e rejeição de mensagens inválidas.

- Memória (RGS_SDK/memory/):
  - Testes de leitura/escrita com endereços válidos e inválidos.
  - Teste de `resolvePointer` com múltiplos offsets.
  - Scan de padrões com máscara e tempo limite.

- Hooks (RGS_SDK/hooks/):
  - Instalação e remoção de hooks com MinHook.
  - Verificação de patch antes/depois.
  - Proteção contra reentrada funcional.

- Proteção (RGS_Client):
  - Interceptação de eventos simulados.
  - Aplicação de regras de detecção.
  - Rate limit e coalescimento.
  - Envio de eventos ao RGS_Central com confirmação.

📊 Métricas a coletar:
- Latência média de envio/recebimento.
- Taxa de sucesso/falha por módulo.
- Uso de CPU/memória durante testes.
- Logs de erro e eventos relevantes.

📏 Regras:
- Criar harnesses simples para cada módulo.
- Executar testes em ambiente controlado.
- Documentar resultados e falhas encontradas.
- Validar compilação completa via `msbuild`.

---

🔧 Parte 2 – Atualização do vcpkg.json

📌 Objetivo:
Limpar o arquivo `vcpkg.json`, removendo o pacote `boost` completo e mantendo apenas os submódulos realmente utilizados no projeto.

📦 Novo conteúdo recomendado para `vcpkg.json`:

```json
{
  "name": "roguegamesecurity",
  "version": "0.1.0",
  "dependencies": [
    "boost-asio",
    "boost-log",
    "boost-format",
    "boost-property-tree",
    "boost-crc",
    "boost-lockfree",
    "boost-circular-buffer",
    "boost-serialization",
    "boost-multi-index",
    "boost-filesystem",
    "boost-test",
    "minhook"
  ]
}
```
```

### Etapa 10: Documentação Final e Prompts de Uso

```markdown
Você é o agente responsável por executar a Etapa 10 do projeto RogueGameSecurity, que consiste em finalizar a documentação, exemplos de configuração e prompts de uso para desenvolvedores e operadores.

📌 Objetivo:
- Criar documentação clara, objetiva e modular para cada parte do sistema.
- Gerar exemplos práticos de configuração (`config.json`) e uso dos componentes.
- Consolidar os prompts utilizados para desenvolvimento e integração.
- Garantir que o projeto esteja pronto para entrega, manutenção e expansão futura.

---

📝 Parte 1 – Documentação por módulo

📁 Criar arquivos `.md` dentro de uma pasta `docs/` com os seguintes conteúdos:

1. `01_arquiteto.md` – visão geral da arquitetura, camadas, módulos e fluxo de dados.
2. `02_network.md` – protocolo interno, sessões TCP, heartbeats, reconexão, roteamento.
3. `03_memory_hooks.md` – leitura/escrita segura, ponteiros, scans, hooks com MinHook.
4. `04_client_protection.md` – interceptação de eventos, pipeline de detecção, reporte.
5. `05_central_orchestration.md` – SessionManager, Router, HealthMonitor, ShutdownController.
6. `06_config_logs_metrics.md` – estrutura de `config.json`, logs com Boost.Log, métricas.
7. `07_build_vcpkg.md` – instruções de build, uso do `vcpkg.json`, integração com VS2022.

📏 Regras:
- Usar linguagem técnica clara e objetiva.
- Incluir exemplos de código e estrutura de dados.
- Referenciar arquivos reais do projeto quando aplicável.

---

🧪 Parte 2 – Exemplo de configuração

📁 Criar `config.json` de exemplo na raiz do projeto com os seguintes campos:

```json
{
  "network": {
    "heartbeat_interval_ms": 5000,
    "session_timeout_ms": 15000,
    "max_payload_size": 4096,
    "enable_hmac": false
  },
  "queues": {
    "high_priority_capacity": 128,
    "medium_priority_capacity": 256,
    "low_priority_capacity": 512,
    "low_priority_policy": "coalesce"
  },
  "memory": {
    "max_read_size": 1024,
    "max_write_size": 1024,
    "allow_protected_write": false
  },
  "hooks": {
    "max_active_hooks": 64,
    "verify_on_install": true,
    "rollback_on_failure": true
  },
  "security": {
    "nonce_window_size": 1000,
    "hash_type": "crc32",
    "reject_replay": true
  },
  "protection": {
    "event_rate_limit_per_minute": 100,
    "coalesce_duplicates": true,
    "report_priority": "medium"
  }
}
```
📏 Regras:

Validar compatibilidade com Boost.PropertyTree.

Comentar cada campo no README ou doc correspondente.

💬 Parte 3 – Prompts de uso e integração

📁 Criar prompts.md com os seguintes conteúdos:

Prompts para cada etapa de desenvolvimento (Etapas 1 a 10).

Prompts para auditoria e validação.

Prompts para integração com agentes externos (ex: monitoramento, automação).

Instruções para adaptar prompts em ambientes CI/CD ou IDEs.

📏 Regras:

Organizar por categoria.

Incluir contexto e objetivo de cada prompt.

Garantir que sejam reutilizáveis e adaptáveis.

🎯 Resultado esperado:

Pasta docs/ com documentação completa e modular.

Arquivo config.json de exemplo funcional.

Arquivo prompts.md com todos os prompts utilizados.

Projeto pronto para entrega, manutenção e expansão.
```
