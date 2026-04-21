@echo off
title DEMS - http://localhost:8888
cd /d "%~dp0orchestrator"

echo.
echo  =====================================================
echo    DEMS - Orquestrador (Modo Local - Sem Docker)
echo  =====================================================
echo.
echo   Endpoints disponiveis:
echo     GET  http://localhost:8888/api/v1/health
echo     POST http://localhost:8888/api/v1/auth/login
echo     POST http://localhost:8888/api/v1/evidence/upload
echo.
echo   Credenciais de teste:
echo     investigador.silva@policia.pt / senha_super_segura
echo     perito.costa@policia.pt       / senha_super_segura
echo.
echo   NOTA: Na primeira vez, o MongoDB em memoria pode demorar
echo         30-60s a descarregar (~70MB). E normal.
echo.
echo   Aguarda a mensagem: "Orquestrador DEMS a correr"
echo   Carrega Ctrl+C para parar.
echo  =====================================================
echo.

set LOCAL_DEV=true
set PORT=8888
set JWT_SECRET=dems_local_dev_secret
set ENCRYPTION_KEY=4465ms4e5363727970744b6579466f7245766964656e63655f4368616e6765
set JWT_EXPIRES_IN=8h

call npm run dev:local
pause
