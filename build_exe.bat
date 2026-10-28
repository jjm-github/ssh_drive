@echo off
chcp 65001 >nul
rem ---------------------------------------------------------------------------
rem  Сборка SSH Drive: exe (портативные) + MSI (установщик)
rem
rem   dist\SSHDrive.exe              ~24 МБ: Python и библиотеки внутри,
rem                                  rclone и WinFsp скачиваются при первом запуске
rem   dist\SSHDrive-offline.exe      ~53 МБ: плюс встроенные rclone.exe и MSI WinFsp
rem   dist\SSHDrive-1.0.0-x64.msi    установщик: Program Files, меню «Пуск»,
rem                                  ярлык на рабочем столе, rclone и WinFsp рядом
rem
rem  Нужен Python 3.10+ (лучше 3.13) и интернет для установки зависимостей.
rem  Зависимости и PyInstaller закреплены с хэшами (requirements*.txt).
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "APP_VERSION=1.1.0"

set "BASEPY="
py -3.13 -c "import sys" >nul 2>&1 && set "BASEPY=py -3.13"
if not defined BASEPY py -3 -c "import sys" >nul 2>&1 && set "BASEPY=py -3"
if not defined BASEPY python -c "import sys" >nul 2>&1 && set "BASEPY=python"
if not defined BASEPY (
    echo Python не найден. Установите Python 3.10+ с https://www.python.org/downloads/
    if not defined SSHDRIVE_NO_PAUSE pause
    exit /b 1
)

set "VENV=%~dp0.venv-build"
set "BPY=%VENV%\Scripts\python.exe"

if not exist "%BPY%" (
    echo [1/7] Создаю окружение сборки...
    %BASEPY% -m venv "%VENV%"
    if errorlevel 1 goto :error
)

echo [2/7] Устанавливаю зависимости...
"%BPY%" -m pip install --disable-pip-version-check -q --upgrade pip
"%BPY%" -m pip install --disable-pip-version-check -q -r requirements.txt -r requirements-build.txt
if errorlevel 1 goto :error

echo [3/7] Рисую иконку...
"%BPY%" tools\make_icon.py
if errorlevel 1 goto :error

echo [4/7] Собираю обычный exe...
set "SSHDRIVE_BUNDLE_TOOLS="
set "SSHDRIVE_EXE_NAME=SSHDrive"
"%BPY%" -m PyInstaller --noconfirm --distpath build\out --workpath build\pyi-light sshdrive.spec
if errorlevel 1 goto :error

echo [5/7] Скачиваю rclone/WinFsp и собираю offline-exe...
set "SSHDRIVE_BUNDLE_TOOLS=1"
set "SSHDRIVE_EXE_NAME=SSHDrive-offline"
"%BPY%" tools\fetch_tools.py
if errorlevel 1 (
    echo.
    echo Не удалось скачать rclone/WinFsp — offline-exe и MSI пропущены.
    goto :done
)
"%BPY%" -m PyInstaller --noconfirm --distpath build\out --workpath build\pyi-offline sshdrive.spec
if errorlevel 1 goto :error

echo [6/7] Собираю SSHShare.exe...
%BPY% -m PyInstaller --noconfirm --distpath build\out --workpath build\pyi-share sshshare.spec
if errorlevel 1 goto :error

echo [7/7] Собираю MSI-установщик...
"%BPY%" tools\fetch_wix.py
if errorlevel 1 goto :error
if not exist "build\winfsp.msi" (
    echo Не найден build\winfsp.msi — MSI пропущен.
    goto :done
)
if not exist "build\msi" mkdir "build\msi"
for /d %%D in ("%TEMP%\cab_0_WixUIExtension*") do rmdir /s /q "%%D"
if exist "dist\SSHDrive-%APP_VERSION%-x64.msi" del /q "dist\SSHDrive-%APP_VERSION%-x64.msi"
"build\wix\candle.exe" -nologo -arch x64 -ext WixUIExtension -dAppVersion=%APP_VERSION% -out "build\msi\sshdrive.wixobj" "installer\sshdrive.wxs"
if errorlevel 1 goto :error
"build\wix\light.exe" -nologo -ext WixUIExtension -cultures:en-us -b "%CD%" -out "dist\SSHDrive-%APP_VERSION%-x64.msi" "build\msi\sshdrive.wixobj"
if errorlevel 1 goto :error

:done
echo.
echo Копирую exe в dist...
copy /y "build\out\SSHDrive.exe" "dist\SSHDrive.exe" >nul || echo   ВНИМАНИЕ: dist\SSHDrive.exe занят запущенной программой — закройте её и скопируйте файл вручную.
copy /y "build\out\SSHDrive-offline.exe" "dist\SSHDrive-offline.exe" >nul
copy /y "build\out\SSHShare.exe" "dist\SSHShare.exe" >nul
echo.
echo Готово. Файлы:
dir /b dist\*.exe dist\*.msi 2>nul
echo.
if not defined SSHDRIVE_NO_PAUSE pause
exit /b 0

:error
echo.
echo Сборка не удалась. Смотрите сообщения выше.
if not defined SSHDRIVE_NO_PAUSE pause
exit /b 1
