rem @echo off

setlocal enabledelayedexpansion

for /f %%i in ("%1") do set dllpath=%%~dpni
for /f %%i in ("%1") do set libname=%%~ni
echo LIBRARY %libname% > %dllpath%.def
echo EXPORTS  >> %dllpath%.def

for /f "skip=19 tokens=1-4" %%1 in ('dumpbin /exports %1') do (
    set /a ordinal=%%1 2>nul
    set /a hint=0x%%2 2>nul
    set /a rva=0x%%3 2>nul
    if !ordinal! equ %%1 if !hint! equ 0x%%2 if !rva! equ 0x%%3 echo %%4 >> %dllpath%.def
)

start lib /out:%dllpath%.lib /machine:x86 /def:%dllpath%.def