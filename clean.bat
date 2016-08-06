@echo off
del *.sdf
del *.VC.db
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q x64
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q EopMon\x64
rmdir /s /q EopMon\Debug
rmdir /s /q EopMon\Release
cd HyperPlatform
clean.bat
