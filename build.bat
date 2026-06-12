@echo off
echo =============================================================
echo DoomGuard Build Script
echo =============================================================
echo Compiling C++20 source files...
cl.exe /std:c++20 /EHsc /O2 /I external/WinDivert/include src/main.cpp src/packet_parser.cpp src/connection_tracker.cpp src/packet_throttler.cpp src/schedule.cpp /link /LIBPATH:external/WinDivert/x64 WinDivert.lib /subsystem:windows /OUT:DoomGuard.exe
echo Done.
