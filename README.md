# DoomGuard

DoomGuard is a Windows network traffic shaping utility designed to reduce access to distracting streaming services during configured focus hours.

What started as a simple attempt to make Netflix unusably slow during work hours evolved into a packet-level traffic shaper built on WinDivert. Instead of blocking websites outright, DoomGuard identifies streaming-related traffic and selectively throttles it to a configurable bandwidth limit.

## Features

* **Kernel-level Traffic Interception**
  Uses WinDivert to inspect outbound TCP/UDP traffic.

* **TLS SNI Inspection**
  Parses TLS Client Hello packets to classify connections by hostname (Netflix, YouTube, etc.).

* **QUIC Mitigation**
  Drops UDP traffic on port 443, forcing supported applications to fall back to TCP where traffic shaping can be applied reliably.

* **Token Bucket Rate Limiting**
  Uses a thread-safe token bucket implementation to throttle matching connections to approximately 30 Kbps.

* **Focus Scheduling**
  Applies throttling automatically during configured work and sleep hours.

* **IP Classification Cache**
  Stores previously classified endpoints to accelerate future connection handling.

## Build

Requirements:

* Windows
* MSVC / Visual Studio Build Tools
* Administrator privileges
* WinDivert

Build using:

```bat
build.bat
```

The build process generates:

```text
DoomGuard.exe
```

Run as Administrator.
