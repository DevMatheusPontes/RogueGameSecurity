# 📖 Planejamento dos Módulos Restantes — RogueGameSecurity (RGS)

## 4. **memory/**
Camada responsável por acesso e manipulação de memória, essencial para o cliente e servidor.

### Objetivos
- Fornecer leitura/escrita segura em memória de processo.
- Implementar scanner de padrões para localizar funções/estruturas.
- Centralizar offsets e ponteiros críticos.

### Componentes
- `memory_access` → funções de leitura/escrita seguras (com validação de permissões).  
- `pointer_utils` → resolução de ponteiros dinâmicos (multi-level pointers).  
- `scanner` → busca de padrões (signature scanning, AOB scan).  
- `offset_registry` → registro central de offsets e símbolos, acessível por outros módulos.  

### Integração
- Usado por **protection** (para validar integridade).  
- Usado por **hooks** (para localizar funções a serem hookadas).  

---

## 5. **protection/**
Camada de defesa ativa e passiva contra debugging, injeções e manipulações externas.

### Objetivos
- Detectar tentativas de debugging ou injeção.  
- Proteger memória crítica contra leitura/escrita não autorizada.  
- Interceptar eventos suspeitos e reportar ao servidor central.  

### Componentes
- `anti_debug` → detecta debuggers (API checks, timing, traps).  
- `injection_detector` → monitora módulos carregados e injeções de DLL.  
- `event_interceptor` → intercepta chamadas críticas (ex.: OpenProcess, WriteProcessMemory).  
- `interface_protection` → protege APIs expostas do cliente.  
- `memory_protection` → monitora regiões críticas de memória.  
- `reporter` → envia relatórios de incidentes para o servidor.  
- `protection_pipeline` → orquestra todos os módulos de proteção em uma sequência lógica.  

### Integração
- Usa **memory** para validar integridade.  
- Usa **network** para reportar incidentes.  
- Usa **utils/logger** para auditoria.  

---

## 6. **hooks/**
Camada que permite interceptar funções do jogo/cliente para aplicar proteções e monitoramento.

### Objetivos
- Interceptar funções críticas do jogo (render, input, rede).  
- Evitar reentrância e loops infinitos em hooks.  
- Fornecer API centralizada para instalar/remover hooks.  

### Componentes
- `hook_manager` → gerencia instalação e remoção de hooks (via MinHook).  
- `reentry_guard` → evita que um hook chame a si mesmo recursivamente.  

### Integração
- Usa **memory** para localizar endereços de funções.  
- Usa **protection** para validar integridade antes/depois do hook.  
- Usa **utils/logger** para registrar hooks instalados.  

---

## 📐 Ordem de Implementação Final
1. **memory/** → base para leitura/escrita e scanner.  
2. **protection/** → defesas ativas/passivas, pipeline de segurança.  
3. **hooks/** → interceptação de funções, integração com memory e protection.  

---

## 🚀 Resultado Esperado
- **Client**: protegido contra debugging, injeções e manipulações.  
- **Server**: validando integridade e recebendo relatórios.  
- **Central**: coordenando sessões, broadcast e auditoria.  
- **SDK**: modular, reutilizável e expansível.  

---
