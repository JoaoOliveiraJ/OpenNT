@echo off
setlocal
set "OPENNT_IMAGE=%~f1"
cd /d "%~dp0.."
if not defined OPENNT_IMAGE set "OPENNT_IMAGE=output-Clang-amd64-debug\OpenNT.img"
set "OPENNT_QEMU=qemu-system-x86_64.exe"
if defined ROSBE_ROOT if exist "%ROSBE_ROOT%\qemu-11.1.0\qemu-system-x86_64.exe" set "OPENNT_QEMU=%ROSBE_ROOT%\qemu-11.1.0\qemu-system-x86_64.exe"
if not defined OPENNT_ACCEL set "OPENNT_ACCEL=whpx"
if not exist "%OPENNT_IMAGE%" (
    echo OpenNT disk image not found: %OPENNT_IMAGE%
    exit /b 1
)
"%OPENNT_QEMU%" -name OpenNT -machine pc -accel %OPENNT_ACCEL% -m 4096 -smp 4 -drive "file=%OPENNT_IMAGE%,format=raw,if=ide" -boot order=c -vga std -usb -device usb-tablet -nic user,model=e1000 -rtc base=localtime -display sdl
exit /b %errorlevel%
