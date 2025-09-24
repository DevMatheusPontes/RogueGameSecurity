# 📖 Documentação — RogueGameSecurity (RGS)

## 🎯 Objetivo
Construir um sistema modular de segurança para jogos, composto por:

- **RGS_Central** (EXE): coordena sessões, políticas e monitoramento.  
- **RGS_Client** (DLL): injetado no cliente do jogo, aplica hooks e proteções locais.  
- **RGS_Server** (DLL): atua no servidor do jogo, valida integridade e protege memória.  
- **RGS_SDK**: biblioteca compartilhada com módulos reutilizáveis.

---

## 🧱 Estrutura do RGS_SDK

### 1. **utils/**
- `config` → Configuração em JSON (Boost.PropertyTree).  
- `threads/`  
  - `thread_pool` → pool de threads com fila de tarefas (Boost.Thread).  
  - `thread_guard` → garante join seguro.  
  - `task_group` → executa várias tarefas e aguarda.  
  - `thread_monitor` → executa tarefas periódicas (watchdog).  
  - `thread_utils` → utilitários (sleep, id da thread, joinable).  
- `logger` → Logger thread-safe com níveis (Debug, Info, Warn, Error, Critical).

---

### 2. **security/**
- `hash` → SHA1 e SHA256.  
- `random` → geração de bytes, inteiros, chaves AES, IVs.  
- `nonce` → gerador de IV único por sessão (anti-replay).  
- `hmac` → HMAC-SHA256.  
- `crypto` → AES-256-GCM (criptografia autenticada).  
- `jwt` → JWT HS256 (autenticação inicial).  
- `hkdf` → derivação de chaves de sessão (HKDF-SHA256).  
- `secure_clear` → limpeza segura de memória.

---

### 3. **network/**
- `protocol` → definição de header, tipos de mensagem, service codes.  
- `service` → enum de serviços (`SVC_HEARTBEAT`, `SVC_AUTH`, `SVC_BROADCAST`, etc.).  
- `message` → serialização, criptografia AES-GCM, validação de tag.  
- `dispatcher` → roteia mensagens para handlers, com error handler para pacotes inválidos/desconhecidos.  
- `session` →  
  - Handshake JWT HS256 (cliente envia JWT, servidor valida).  
  - Derivação de chaves de sessão com HKDF.  
  - Criptografia AES-256-GCM em todos os pacotes após handshake.  
  - Proteção anti-replay (IV monotônico).  
- `session_manager` →  
  - Mapeia login → sessão/socket.  
  - Permite unicast, multicast e broadcast.  
  - Integração automática: após handshake, a `Session` chama `on_authenticated` para registrar o login.  
- `server` → aceita conexões, cria sessões, integra com dispatcher e session_manager.  
- `client` → conecta ao servidor, realiza handshake e mantém sessão.

---

### 4. **memory/** (próximo)
- `memory_access` → leitura/escrita segura.  
- `pointer_utils` → resolução de ponteiros.  
- `scanner` → busca de padrões na memória.  
- `offset_registry` → registro central de offsets.

---

### 5. **protection/** (planejado)
- `anti_debug` → detecta/debuggers.  
- `injection_detector` → detecta injeções externas.  
- `event_interceptor` → intercepta eventos suspeitos.  
- `interface_protection` → protege APIs expostas.  
- `memory_protection` → protege regiões críticas.  
- `reporter` → envia relatórios para o servidor.  
- `protection_pipeline` → orquestra as proteções.

---

### 6. **hooks/** (planejado)
- `hook_manager` → gerencia hooks.  
- `reentry_guard` → evita reentrância em funções hookadas.

---

## 🔐 Segurança dos Packets
- **AES-256-GCM** → criptografia + integridade.  
- **HKDF-SHA256** → derivação de chaves de sessão.  
- **JWT HS256** → autenticação inicial (login).  
- **Anti-replay** → IV único por sessão (nonce monotônico).  
- **Dispatcher** → rejeita pacotes inválidos ou desconhecidos.  
- **SessionManager** → garante associação login ↔ socket.

---

## 📐 Ordem de Desenvolvimento
1. **utils** ✅  
2. **security** ✅  
3. **network** ✅ (finalizado)  
4. **memory** 🚧 (próximo)  
5. **protection**  
6. **hooks**

---

## 📦 Dependências vcpkg
Atualmente utilizadas:
```json
{
  "name": "roguegamesecurity",
  "version": "1.0",
  "supports": "windows & x86",
  "dependencies": [
    "boost-asio",
    "boost-circular-buffer",
    "boost-crc",
    "boost-filesystem",
    "boost-format",
    "boost-lockfree",
    "boost-log",
    "boost-multi-index",
    "boost-property-tree",
    "boost-serialization",
    "boost-test",
    "minhook",
    "openssl"
  ]
}
```

---

## ✅ Status Atual
- **utils** completo.  
- **security** completo.  
- **network** completo (com handshake, criptografia, anti-replay, dispatcher, session_manager, server e client).  
- Próximo passo: iniciar **memory/**.

---

## 🚀 Próximos Passos
1. Implementar **memory/** (scanner, offsets, acesso seguro).  
2. Implementar **protection/** (anti-debug, injection, pipeline).  
3. Implementar **hooks/** (hook_manager, reentry_guard).  
4. Revisar logs e adicionar auditoria em todos os módulos.  

---