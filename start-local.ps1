#!/usr/bin/env pwsh
# =============================================================
# DEMS – Script de arranque LOCAL (sem Docker)
# Corre MongoDB e PostgreSQL nativamente no Windows
# =============================================================

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  DEMS – Arranque Local (sem Docker)" -ForegroundColor Cyan  
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Verificar pré-requisitos ───────────────────────────────
Write-Host "🔍 A verificar pré-requisitos..." -ForegroundColor Yellow

$nodeOk    = (Get-Command node    -ErrorAction SilentlyContinue) -ne $null
$npmOk     = (Get-Command npm     -ErrorAction SilentlyContinue) -ne $null
$mongoOk   = (Get-Command mongod  -ErrorAction SilentlyContinue) -ne $null
$psqlOk    = (Get-Command psql    -ErrorAction SilentlyContinue) -ne $null
$mongoshOk = (Get-Command mongosh -ErrorAction SilentlyContinue) -ne $null

Write-Host "  Node.js : $(if ($nodeOk) { '✅ ' + (node --version) } else { '❌ Não instalado' })"
Write-Host "  npm     : $(if ($npmOk)  { '✅ ' + (npm --version)  } else { '❌ Não instalado' })"
Write-Host "  MongoDB : $(if ($mongoOk){ '✅ Instalado' } else { '❌ Não instalado' })"
Write-Host "  mongosh : $(if ($mongoshOk){ '✅ Instalado' } else { '❌ Não instalado' })"
Write-Host "  PostgreSQL: $(if ($psqlOk){ '✅ Instalado' } else { '❌ Não instalado' })"
Write-Host ""

# ── 2. Instalar dependências em falta ─────────────────────────
if (-not $mongoOk) {
    Write-Host "📦 A instalar MongoDB..." -ForegroundColor Yellow
    winget install MongoDB.Server --accept-package-agreements --accept-source-agreements
    winget install MongoDB.Shell  --accept-package-agreements --accept-source-agreements
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
}

if (-not $psqlOk) {
    Write-Host "📦 A instalar PostgreSQL..." -ForegroundColor Yellow
    winget install PostgreSQL.PostgreSQL --accept-package-agreements --accept-source-agreements
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
}

# ── 3. Criar directórios de dados ────────────────────────────
$mongoDataDir = "$env:USERPROFILE\dems-mongo-data"
if (-not (Test-Path $mongoDataDir)) {
    New-Item -ItemType Directory -Path $mongoDataDir | Out-Null
    Write-Host "📁 Criado: $mongoDataDir" -ForegroundColor Green
}

# ── 4. Arrancar MongoDB ───────────────────────────────────────
Write-Host ""
Write-Host "🍃 A arrancar MongoDB (porta 27017)..." -ForegroundColor Green
$mongoProcess = Start-Process -FilePath "mongod" `
    -ArgumentList "--dbpath `"$mongoDataDir`" --port 27017 --bind_ip 127.0.0.1" `
    -PassThru -WindowStyle Minimized
Write-Host "   PID MongoDB: $($mongoProcess.Id)"
Start-Sleep -Seconds 3

# ── 5. Arrancar PostgreSQL (se o serviço não estiver activo) ──
Write-Host "🐘 A verificar PostgreSQL..." -ForegroundColor Green
$pgService = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
if ($pgService) {
    if ($pgService.Status -ne "Running") {
        Start-Service $pgService.Name
        Write-Host "   PostgreSQL service iniciado: $($pgService.Name)"
    } else {
        Write-Host "   ✅ PostgreSQL já está a correr."
    }
} else {
    Write-Host "   ⚠️  Serviço PostgreSQL não encontrado — a usar SQLite para desenvolvimento" -ForegroundColor Yellow
}

Start-Sleep -Seconds 2

# ── 6. Configurar .env para modo local ────────────────────────
Write-Host ""
Write-Host "⚙️  A configurar variáveis de ambiente (modo local)..." -ForegroundColor Yellow
$env:DB_HOST             = "localhost"
$env:POSTGRES_USER       = "postgres"
$env:POSTGRES_PASSWORD   = "postgres"
$env:POSTGRES_DB         = "dems_orchestrator"
$env:JWT_SECRET          = "dems_local_dev_secret"
$env:ENCRYPTION_KEY      = "4465ms4e5363727970744b6579466f7245766964656e63655f4368616e6765"
$env:JWT_EXPIRES_IN      = "8h"
$env:PORT                = "8888"
$env:LOCAL_DEV           = "true"

Write-Host "   DB_HOST=localhost"
Write-Host "   PORT=8888"

# ── 7. Instalar dependências npm ──────────────────────────────
Write-Host ""
Write-Host "📦 A instalar dependências npm..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\orchestrator"
npm install --silent

# ── 8. Arrancar o Orquestrador ────────────────────────────────
Write-Host ""
Write-Host "🚀 A arrancar o Orquestrador DEMS..." -ForegroundColor Green
Write-Host "   → http://localhost:8888/api/v1/health" -ForegroundColor Cyan
Write-Host "   → http://localhost:8888/api/v1/auth/login" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Prima Ctrl+C para parar." -ForegroundColor Gray
Write-Host ""

npx ts-node-dev --respawn --transpile-only src/server.ts
