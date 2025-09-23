# 07_build_vcpkg.md - Instruções de Build e Uso do Vcpkg

Este documento detalha o processo de build do projeto RogueGameSecurity, incluindo a configuração do ambiente de desenvolvimento e o uso do `vcpkg` para gerenciamento de dependências.

## Requisitos

*   **Sistema Operacional:** Windows (Win32/x86)
*   **IDE:** Visual Studio 2022 (com o workload "Desenvolvimento para desktop com C++" instalado)
*   **Compilador:** MSVC (toolset v143 ou mais recente)
*   **Gerenciador de Pacotes:** `vcpkg`

## Configuração do Vcpkg

O `vcpkg` é utilizado para gerenciar todas as dependências de terceiros do projeto. Certifique-se de que o `vcpkg` esteja instalado e integrado ao Visual Studio.

1.  **Instalação do Vcpkg (se ainda não tiver):**
    ```bash
    git clone https://github.com/microsoft/vcpkg
    cd vcpkg
    .\bootstrap-vcpkg.bat
    ```

2.  **Integração com Visual Studio:**
    ```bash
    .\vcpkg integrate install
    ```
    Isso permite que o Visual Studio encontre automaticamente as bibliotecas instaladas pelo `vcpkg`.

3.  **Instalação das Dependências do Projeto:**
    Navegue até a raiz do projeto `RogueGameSecurity` (onde o `vcpkg.json` está localizado) e execute:
    ```bash
    vcpkg install
    ```
    Este comando lerá o `vcpkg.json` e instalará todas as dependências necessárias (Boost submódulos e MinHook) para a plataforma `x86-windows`.

    **Conteúdo atual do `vcpkg.json`:**
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

## Build do Projeto

O projeto é configurado para ser compilado diretamente pelo Visual Studio ou via `msbuild`.

### Via Visual Studio IDE

1.  Abra o arquivo de solução `RogueGameSecurity.sln` no Visual Studio 2022.
2.  Selecione a configuração `Release` e a plataforma `Win32`.
3.  Vá em `Build > Build Solution` (ou pressione `F7`).

### Via Linha de Comando (Developer Command Prompt)

É altamente recomendado usar o **Developer Command Prompt for VS 2022** para garantir que todas as variáveis de ambiente necessárias (`msbuild`, paths do compilador, etc.) estejam configuradas corretamente.

1.  Abra o **Developer Command Prompt for VS 2022**.
2.  Navegue até a raiz do projeto `RogueGameSecurity`.
3.  Execute o seguinte comando:
    ```bash
    msbuild RogueGameSecurity.sln /p:Configuration=Release /p:Platform=Win32
    ```

### Saída da Compilação

Após uma compilação bem-sucedida, os seguintes artefatos serão gerados nas respectivas pastas `Release` dentro de cada projeto:

*   `RGS_Central.exe`
*   `RGS_Server.dll`
*   `RGS_Client.dll`

## Configurações do Projeto (`.vcxproj`)

Os arquivos `.vcxproj` estão configurados com as seguintes opções:

*   **Toolset:** `v143`
*   **Plataforma:** `Win32`
*   **Linguagem C++:** C++20 (`/std:c++20`)
*   **Nível de Warning:** `/W4`
*   **Otimização:** `/O2` (MaxSpeed para Release)
*   **Conformidade:** `/permissive-` (para conformidade estrita com o padrão C++)
*   **Includes:** Apontando para `$(SolutionDir)RGS_SDK` e `$(VcpkgRoot)installed\x86-windows\include`.

Essas configurações garantem um build otimizado e conforme os padrões modernos do C++.
