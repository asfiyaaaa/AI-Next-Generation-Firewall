# NGFW Firewall Rules Policy

This document lists the active firewall rules in **processing order** (by Priority).

**Default Policy:** `DROP` (Any packet not matching a rule below is blocked)

## Rules Table

| Priority | ID | Name | Action | Protocol | Source / Dest | Ports | Description |
|:---:|:---:|---|:---:|:---:|---|---|---|
| **1** | 1 | Allow Established | **ALLOW** | ANY | Any | Any | Permits return traffic for existing connections |
| **2** | 2 | Allow Loopback | **ALLOW** | ANY | Localhost | Any | Internal system communication (127.0.0.1) |
| **10** | 10 | Allow ICMP | **ALLOW** | ICMP | Any | Any | Ping / Traceroute |
| **11** | 11 | Allow DNS | **ALLOW** | UDP | Any | **53** | Domain Name Resolution |
| **20** | 20 | Allow HTTP/HTTPS | **ALLOW** | TCP | Any | **80, 443** | Web Browsing |
| **100** | 100 | Block Telnet | **DROP** | TCP | Any | **23** | Block insecure remote shell |
| **101** | 101 | Block FTP | **DROP** | TCP | Any | **21** | Block insecure file transfer |
| **102** | 102 | Block SMB | **DROP** | TCP | Any | **445** | Block Windows File Sharing (Security Risk) |
| **103** | 103 | Block RDP | **DROP** | TCP | Any | **3389** | Block Remote Desktop |
| **9999** | 9999 | Log Drop | **LOG DROP**| ANY | Any | Any | **Catch-All:** Logs and drops everything else |

## Legend
- **Priority**: Lower numbers are processed first.
- **Action**: 
  - `ALLOW`: Traffic passes through.
  - `DROP`: Traffic is silently blocked.
  - `LOG DROP`: Traffic is blocked and recorded in logs.
