@echo off
title DEMS - Instalar dependencias
cd /d "%~dp0orchestrator"

echo.
echo  =========================================
echo    DEMS - Instalar dependencias
echo  =========================================
echo.
echo  A instalar tudo (cross-env, mongodb-memory-server, etc.)...
echo.
call npm install
echo.
echo  =========================================
echo    Instalacao concluida!
echo    Agora clica duas vezes em:
echo    2-arrancar-servidor.bat
echo  =========================================
echo.
pause
