Perfeito, Matheus 🙌. Vamos organizar um **plano de desenvolvimento sólido, por etapas**, garantindo consistência entre todos os projetos (Central, Client, Server, SDK/Modules). A ideia é que cada etapa seja **completa, compilável, testada e finalizada** antes de avançarmos.  

---

# 📑 Plano de Desenvolvimento

## **Etapa 1 — Base de Protocolo e Sessão**
- **Objetivo:** Garantir comunicação estável entre Central, Client e Server.
- **Ações:**
  - Implementar `Protocol` (header fixo, framing seguro, limites).
  - Implementar `Message` (camada semântica sobre o protocolo).
  - Implementar `Dispatcher` (roteamento por serviço).
  - Implementar `Session` (async_read header + body, validação, entrega ao dispatcher).
- **Critério de conclusão:**  
  - Central compila e roda.  
  - Client e Server conectam e trocam mensagens `Hello` sem crash.  
  - Logs mostram mensagens recebidas corretamente.  

---

## **Etapa 2 — Estrutura do Central**
- **Objetivo:** Central como hub estável.
- **Ações:**
  - Criar `SessionManager` (armazenar e gerenciar sessões ativas).
  - Criar `Router` (registrar handlers no Dispatcher e rotear mensagens).
  - Integrar `HealthMonitor` (ping/pong para detectar desconexões).
  - Integrar `ShutdownController` (encerramento limpo via sinal).
- **Critério de conclusão:**  
  - Central aceita múltiplos Clients/Servers.  
  - Mensagens roteadas corretamente.  
  - Desconexões detectadas e removidas.  

---

## **Etapa 3 — Segurança e Handshake**
- **Objetivo:** Estabelecer canal seguro.
- **Ações:**
  - Implementar handshake inicial (JWT → validação → derivação de chave via HKDF).
  - Implementar criptografia AES-GCM no payload.
  - Marcar no header (`flags`) quando criptografado.
- **Critério de conclusão:**  
  - Client/Server só conseguem enviar mensagens após handshake válido.  
  - Pacotes inválidos são rejeitados sem derrubar o Central.  

---

## **Etapa 4 — Funcionalidades de Negócio**
- **Objetivo:** Implementar recursos específicos do projeto.
- **Ações:**
  - Definir `ServiceCode` para cada funcionalidade (ex.: AntiCheat, Telemetria, Logs).
  - Implementar handlers no Router para cada serviço.
  - Garantir que Client/Server enviem e recebam dados conforme esperado.
- **Critério de conclusão:**  
  - Funcionalidades de negócio ativas e testadas ponta a ponta.  

---

## **Etapa 5 — Refinamento e Manutenção**
- **Objetivo:** Garantir qualidade e manutenibilidade.
- **Ações:**
  - Revisão de código (consistência, nomenclatura, logs).
  - Documentação mínima (README, fluxos).
  - Testes de carga e estabilidade.
- **Critério de conclusão:**  
  - Sistema estável em cenários reais.  
  - Código limpo, padronizado e documentado.  

---

# 🚀 Próximo passo imediato
Começamos pela **Etapa 1**.  
Ou seja: consolidar `Protocol`, `Message`, `Dispatcher` e `Session` no seu projeto atual, garantindo que Central, Client e Server troquem mensagens `Hello` de forma estável.

---

👉 Matheus, confirmando: seguimos agora para a **Etapa 1** e eu já te entrego os arquivos completos (`protocol`, `message`, `dispatcher`, `session`) prontos para compilar e testar?
