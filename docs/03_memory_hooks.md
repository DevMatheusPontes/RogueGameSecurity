# 03_memory_hooks.md - Módulos de Memória e Hooks (RGS_SDK/memory/ e RGS_SDK/hooks/)

Os módulos `RGS_SDK/memory/` e `RGS_SDK/hooks/` fornecem utilitários essenciais para interação segura com a memória do processo e para a instalação/gerenciamento de hooks.

## Módulo de Memória (`RGS_SDK/memory/`)

Este módulo encapsula operações de baixo nível com a memória, garantindo segurança e robustez através de validações e tratamento de exceções.

### `memory_access.hpp/cpp`

Fornece funções genéricas para leitura e escrita de memória.

*   **`isReadable(address, size)`:** Verifica se um bloco de memória é acessível para leitura, utilizando `VirtualQuery` para inspecionar as permissões da página.
*   **`read<T>(address)`:** Lê um valor de tipo `T` de um endereço. Envolve a operação em um bloco `__try/__except` para capturar exceções de acesso inválido e retorna um `std::optional<T>`.
*   **`write<T>(address, value)`:** Escreve um valor de tipo `T` em um endereço. Temporariamente altera as permissões da página para `PAGE_READWRITE` usando `VirtualProtect`, realiza a escrita e restaura as permissões originais. Também utiliza `__try/__except`.
*   **`readBuffer(address, size)`:** Lê um bloco de bytes de um endereço, com validação de tamanho máximo configurável.
*   **`writeBuffer(address, data)`:** Escreve um bloco de bytes em um endereço, com validação de tamanho máximo configurável e proteção temporária da página.

### `pointer_utils.hpp/cpp`

Oferece utilitários para resolver ponteiros multinível.

*   **`resolvePointer(baseAddress, offsets)`:** Resolve uma cadeia de ponteiros. Dada uma `baseAddress` e um vetor de `offsets`, ele dereferencia o ponteiro na base, adiciona o primeiro offset, dereferencia novamente, adiciona o segundo offset, e assim por diante, até o último offset. Retorna o endereço final ou `0` em caso de falha (ponteiro inválido ou nulo em qualquer etapa).

### `offset_registry.hpp/cpp`

Um singleton para gerenciar offsets de memória por nome, ID e versão.

*   **`registerOffset(name, id, version, address)`:** Registra um offset com suas informações.
*   **`getOffset(id)` / `getOffset(name)`:** Recupera o endereço de um offset registrado.

### `scanner.hpp/cpp`

Implementa a funcionalidade de varredura de padrões de bytes na memória.

*   **`scanPattern(moduleBase, pattern, mask)`:** Procura por um padrão de bytes (`pattern`) com uma máscara (`mask`) dentro de um módulo. A máscara usa 'x' para bytes que devem corresponder e '?' para curingas. Retorna o endereço encontrado ou `std::nullopt`.

## Módulo de Hooks (`RGS_SDK/hooks/`)

Este módulo fornece uma interface segura e gerenciada para a instalação e remoção de hooks, utilizando a biblioteca `MinHook`.

### `hook_manager.hpp/cpp`

Um singleton que atua como o gerenciador central de hooks.

*   **`initialize()` / `shutdown()`:** Inicializa e desinicializa a biblioteca MinHook.
*   **`installHook(id, targetAddress, detourFunction)`:** Cria e habilita um hook. Registra o hook com um `id` único, o endereço da função original (`targetAddress`) e a função de desvio (`detourFunction`). Armazena o trampoline gerado pelo MinHook para chamar a função original.
*   **`removeHook(id)`:** Desabilita e remove um hook registrado.
*   **`enableHook(id)` / `disableHook(id)`:** Habilita ou desabilita um hook existente sem removê-lo.
*   **`getHookState(id)`:** Retorna o estado atual de um hook (Created, Enabled, Disabled, Error).
*   **`getOriginal<T>(id)`:** Retorna o ponteiro para a função original (trampoline) para que possa ser chamada a partir da função de desvio.

### `reentry_guard.hpp`

Um utilitário header-only para prevenir recursão infinita em funções hookadas.

*   **`RGS_REENTRY_GUARD()` macro:** Deve ser usada no início de uma função de desvio para garantir que a função original possa ser chamada sem que o detour seja acionado novamente, evitando loops infinitos.

### Ausências Justificadas

*   **`trampoline.hpp` e `patch_utils.hpp`**: As funcionalidades de criação de trampolines e aplicação/verificação de patches são inteiramente abstraídas e gerenciadas pela biblioteca `MinHook` e encapsuladas dentro de `hook_manager.hpp`. Não foi necessário criar arquivos separados para estas utilidades, pois a integração direta com `MinHook` já provê a robustez e segurança necessárias.

## Configuração

O comportamento dos módulos de memória e hooks é configurável via `config.json`:

```json
{
  "memory": {
    "max_read_size": 4096,              // Tamanho máximo permitido para leitura de buffer
    "max_write_size": 4096,             // Tamanho máximo permitido para escrita de buffer
    "allow_protected_write": false,     // Permitir escrita em regiões de memória protegidas (ex: código)
    "max_scan_time_ms": 5000            // Tempo máximo em ms para operações de scan de padrão
  },
  "hooks": {
    "max_active_hooks": 128,            // Número máximo de hooks ativos permitidos
    "allow_protected_hooks": false      // Permitir hooks em regiões de memória protegidas
  }
}
```
