@echo off
echo =============================================================
echo FocusGuard Build Script
echo =============================================================
echo Compiling C++20 source files...
cl.exe /std:c++20 /O2 /I external/WinDivert/include src/main.cpp src/packet_parser.cpp src/connection_tracker.cpp /link /LIBPATH:external/WinDivert/x64 WinDivert.lib /OUT:FocusGuard.exe
echo Done.
