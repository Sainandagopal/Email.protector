@echo off
set "PATH=%LOCALAPPDATA%\Programs\Git\cmd;%LOCALAPPDATA%\Programs\Git Credential Manager;%PATH%"
echo ========================================================
echo Pushing Email.protector to GitHub...
echo Target: https://github.com/Sainandagopal/Email.protector.git
echo ========================================================
echo.
git push -u origin main
if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Successfully pushed to GitHub!
    echo View your repository at: https://github.com/Sainandagopal/Email.protector
) else (
    echo.
    echo [NOTE] If a browser window opened, complete the GitHub sign-in to authorize.
)
echo.
pause
