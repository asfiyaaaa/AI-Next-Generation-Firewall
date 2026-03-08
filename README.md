# Unified Firewall (Windows Only)

This application is a **high-performance, Windows-exclusive** firewall integrating Layer 3/4 packet filtering with Layer 7 Deep Packet Inspection (DPI).

## Platform Support
**Operating System:** Windows 10/11 or Windows Server (64-bit)
**Drivers:** Requires `WinDivert` driver (automatically handled by `pydivert` or installed separately).
**Linux/MacOS:** NOT SUPPORTED.

## Features
- **Core (Phase 1):** WinDivert packet capture, stateful connection tracking, L3/L4 rules.
- **DPI (Phase 2):** 8-layer inspection (AppID, TLS, IPS, Threat Intel, etc.).
- **Windows Optimized:** Designed for Windows threading model and network stack.

## Installation
1. Install Python 3.10+ (Windows installer).
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

## Usage
Run with Administrator privileges (required for packet capture):
```powershell
python main.py
```
To run in Mock Mode (no driver required, safe for testing):
```powershell
python main.py --test
```
