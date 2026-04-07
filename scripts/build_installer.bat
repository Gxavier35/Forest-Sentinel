@echo off
set VERSION=1.1.1
echo ###########################################################
echo # Forest Sentinel - Gerador de Build v%VERSION%
echo ###########################################################

REM 1. Limpeza de builds anteriores
echo [1/4] Limpando pastas temporarias...
if exist build rd /s /q build
if exist dist rd /s /q dist

REM 2. Executar PyInstaller
echo [2/4] Iniciando PyInstaller (OneDir mode)...
pyinstaller ForestSentinel.spec --noconfirm

if %ERRORLEVEL% NEQ 0 (
    echo [ERRO] Falha no PyInstaller. Verifique as dependencias.
    pause
    exit /b %ERRORLEVEL%
)

REM 3. Verificar Pasta Instalador
echo [3/4] Verificando pasta de saída...
if not exist Instalador mkdir Instalador

REM 4. Finalização
echo [4/4] Build concluído com sucesso!
echo.
echo -> Pasta do Executavel: dist\Forest Sentinel
echo -> Script de Instalacao: installer.iss
echo.
echo Proximo passo: Abra o Inno Setup e compile o arquivo 'installer.iss'.
pause
