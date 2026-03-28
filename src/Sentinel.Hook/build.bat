@echo off
setlocal

REM Build SentinelHook.dll (x86) using MSVC
REM Run from a Visual Studio Developer Command Prompt, or let this script find it.

where cl >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Looking for Visual Studio...
    for %%v in (2026 2022 2019) do (
        if exist "C:\Program Files\Microsoft Visual Studio\%%v\Community\VC\Auxiliary\Build\vcvarsall.bat" (
            echo [*] Found VS %%v Community
            call "C:\Program Files\Microsoft Visual Studio\%%v\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
            goto :found
        )
        if exist "C:\Program Files\Microsoft Visual Studio\%%v\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
            echo [*] Found VS %%v Professional
            call "C:\Program Files\Microsoft Visual Studio\%%v\Professional\VC\Auxiliary\Build\vcvarsall.bat" x86
            goto :found
        )
        if exist "C:\Program Files\Microsoft Visual Studio\%%v\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
            echo [*] Found VS %%v Enterprise
            call "C:\Program Files\Microsoft Visual Studio\%%v\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x86
            goto :found
        )
    )
    echo [!] Visual Studio not found. Run this from a Developer Command Prompt.
    exit /b 1
)
:found

echo [*] Compiling SentinelHook.dll (x86)...

if not exist build mkdir build

cl /nologo /O2 /MT /LD /W3 ^
    /D_CRT_SECURE_NO_WARNINGS /DWIN32 ^
    /I. /Iminhook\include /Iminhook\src ^
    SentinelHook.cpp ^
    minhook\src\buffer.c ^
    minhook\src\hook.c ^
    minhook\src\trampoline.c ^
    minhook\src\hde\hde32.c ^
    minhook\src\hde\hde64.c ^
    /Fe:build\SentinelHook.dll ^
    /Fo:build\ ^
    /link /DLL ws2_32.lib kernel32.lib

if %ERRORLEVEL% EQU 0 (
    echo [+] Build succeeded: build\SentinelHook.dll
) else (
    echo [!] Build failed
    exit /b 1
)

endlocal
