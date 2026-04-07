<#
.SYNOPSIS
Script para compilar o ForestSentinel em executável standalone para Windows.

.DESCRIPTION
Esse script utiliza PyInstaller para empacotar o main.py, incluindo os modelos (.pkl) e 
outros arquivos de recursos, criando um diretório final (onedir) ou arquivo único (onefile).
#>

param (
    [switch]$OneFile = $false
)

Write-Host "Verificando/Instalando PyInstaller..." -ForegroundColor Cyan
pip install pyinstaller scikit-learn numpy pandas psutil pyqt6 scapy

Write-Host "`nLimpando builds antigas..." -ForegroundColor Cyan
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "*.spec") { Remove-Item -Force "*.spec" }

$baseArgs = @(
    "src/main.py",
    "--noconsole",
    "--name=`"Forest Sentinel`"",
    "--paths=src",
    "--exclude-module=PySide6",
    "--exclude-module=PyQt5",
    "--add-data=`"models;models`"",
    "--add-data=`"assets;assets`"",
    "--add-data=`"config;config`""
)

if (Test-Path "assets/icon.ico") {
    $baseArgs += "--icon=assets/icon.ico"
}

if ($OneFile) {
    Write-Host "`nCompilando como Arquivo Único (--onefile)..." -ForegroundColor Yellow
    $baseArgs = @("--onefile") + $baseArgs
}
else {
    Write-Host "`nCompilando como Diretório (--onedir)... (RECOMENDADO PARA MODELOS GRANDES)" -ForegroundColor Yellow
    $baseArgs = @("--onedir") + $baseArgs
}

# Configurações de ocultação do cmd do TShark/Scapy, se necessário
$baseArgs += "--hidden-import=sklearn.ensemble._iforest"
$baseArgs += "--hidden-import=pandas"

Write-Host "`nExecutando PyInstaller: pyinstaller $($baseArgs -join ' ')" -ForegroundColor Cyan
Invoke-Expression "pyinstaller $($baseArgs -join ' ')"

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild concluída com sucesso! Os arquivos estão na pasta 'dist'." -ForegroundColor Green
}
else {
    Write-Host "`nErro durante o processo de build." -ForegroundColor Red
}
