@echo off
title FraudLens - Automated GitHub Upload
echo ==============================================================================
echo                 FraudLens - Automated GitHub Upload Script
echo ==============================================================================
echo.
echo Target Repository: https://github.com/nrnjn-06/FraudLens.git
echo Working Directory:  %~dp0
echo.

cd /d "%~dp0"

where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Git is not installed or not found in PATH!
    echo.
    echo Please install Git for Windows by running the installer in your Downloads folder:
    echo C:\Users\HP\Downloads\Git-Installer.exe
    echo or download it directly from: https://git-scm.com/download/win
    echo.
    pause
    exit /b 1
)

echo [1/5] Initializing local Git repository...
git init
if %errorlevel% neq 0 (
    echo [ERROR] Git init failed!
    pause
    exit /b 1
)

:: Ensure user identity is set so git commit succeeds
git config user.email >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Setting default Git author identity for this repository...
    git config user.name "nrnjn-06"
    git config user.email "nrnjn-06@users.noreply.github.com"
)

echo [2/5] Staging files (automatically respecting .gitignore exclusions)...
git add .

echo [3/5] Creating initial commit...
git commit -m "feat: initial commit for FraudLens v1.0.0 platform"
if %errorlevel% neq 0 (
    echo [INFO] Working directory already committed or clean.
)

echo [4/5] Configuring main branch and remote origin...
git branch -M main
git remote remove origin >nul 2>&1
git remote add origin https://github.com/nrnjn-06/FraudLens.git

echo [5/5] Pushing files to GitHub...
echo (A browser window will open asking you to sign in to your GitHub account)
echo.
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ==============================================================================
    echo [SUCCESS] FraudLens successfully uploaded to GitHub!
    echo Visit your project: https://github.com/nrnjn-06/FraudLens
    echo ==============================================================================
) else (
    echo.
    echo [NOTE] If GitHub asked for authentication or rejected the push, please ensure
    echo you are signed in to your account nrnjn-06.
)

echo.
pause
