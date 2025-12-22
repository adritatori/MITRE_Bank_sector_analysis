# Banking Sector MITRE ATT&CK - Extended NIDS Classification Analysis

**Generated:** 2025-12-22
**Source:** banking_analysis_nids_classified_20251222_003800.csv
**Total Techniques Analyzed:** 217

---

## Summary Statistics

| Category | Count | Percentage |
|----------|-------|------------|
| **YES** (Fully Network Detectable) | 18 | 8.3% |
| **PARTIAL** (Partially Detectable) | 56 | 25.8% |
| **NO** (Not Network Detectable) | 143 | 65.9% |

---

## 🔴 Fully Network Detectable Techniques (YES)

These techniques generate clear network artifacts that can be detected by NIDS.

| # | Technique ID | Technique Name | Tactic | Classification | Reasoning | Network Artifact | Priority | Score | Threat Groups |
|---|--------------|----------------|--------|----------------|-----------|------------------|----------|-------|---------------|
| 1 | T1105 | Ingress Tool Transfer | command-and-control | YES | File transfer over network protocols | HTTP/HTTPS, FTP, SMB traffic with file transfers | High-Priority | 72.4 | APT38, Andariel, Cobalt Group, Indrik Spider, Lazarus Group, Silence, TA505, Wizard Spider |
| 2 | T1071.001 | Web Protocols | command-and-control | YES | C2 using HTTP/HTTPS web protocols | HTTP/HTTPS POST/GET requests to C2 servers | High-Priority | 72.4 | APT38, Cobalt Group, Lazarus Group, TA505, Wizard Spider |
| 3 | T1566.001 | Spearphishing Attachment | initial-access | YES | Email with malicious attachments | SMTP traffic with attachments, email headers | High-Priority | 65.6 | APT38, Andariel, Cobalt Group, Lazarus Group, Malteiro, Silence, TA505, Wizard Spider |
| 4 | T1021.001 | Remote Desktop Protocol | lateral-movement | YES | Remote desktop protocol connections | RDP traffic on port 3389, encrypted session data | High-Priority | 56.8 | Cobalt Group, Indrik Spider, Lazarus Group, Silence, Wizard Spider |
| 5 | T1018 | Remote System Discovery | discovery | YES | Network scanning and enumeration commands | ICMP, ARP, NetBIOS, LDAP queries for host discovery | Common | 55.8 | Indrik Spider, Silence, Wizard Spider |
| 6 | T1566.002 | Spearphishing Link | initial-access | YES | Email with malicious links | SMTP traffic, HTTP redirects, DNS queries | High-Priority | 51.6 | Cobalt Group, Lazarus Group, TA505, Wizard Spider |
| 7 | T1041 | Exfiltration Over C2 Channel | exfiltration | YES | Data exfiltration over C2 channel | Encrypted outbound traffic, large data volumes | High-Priority | 40.4 | Lazarus Group, Wizard Spider |
| 8 | T1219 | Remote Access Tools | command-and-control | YES | Remote access software usage | TeamViewer, VNC, AnyDesk network traffic | Common | 40.4 | Carbanak, Cobalt Group |
| 9 | T1046 | Network Service Discovery | discovery | YES | Network port and service scanning | SYN scans, service probes, port sweep traffic | Medium | 36.8 | Cobalt Group, Lazarus Group |
| 10 | T1571 | Non-Standard Port | command-and-control | YES | Non-standard ports for C2 | Known protocols on unusual ports, custom protocols | Medium | 35.4 | Lazarus Group, Silence |
| 11 | T1021.004 | SSH | lateral-movement | YES | SSH remote access | SSH traffic on port 22, encrypted sessions | Medium | 33.8 | GCMAN, Indrik Spider, Lazarus Group |
| 12 | T1557.001 | LLMNR/NBT-NS Poisoning and SMB Relay | credential-access | YES | LLMNR/NBT-NS poisoning | Spoofed LLMNR/NBT-NS responses, name resolution anomalies | Medium | 28.6 | Lazarus Group, Wizard Spider |
| 13 | T1572 | Protocol Tunneling | command-and-control | YES | Protocol tunneling for C2 | Encapsulated protocols, unusual port/protocol combinations | Medium | 26.4 | Cobalt Group |
| 14 | T1021.002 | SMB/Windows Admin Shares | lateral-movement | YES | SMB/Windows Admin Shares access | SMB traffic on ports 445/139, authentication attempts | Medium | 24.8 | Lazarus Group, Wizard Spider |
| 15 | T1071.004 | DNS | command-and-control | YES | C2 using DNS protocol | High volume DNS queries, long domain names, TXT records | Rare | 21.4 | Cobalt Group |
| 16 | T1095 | Non-Application Layer Protocol | command-and-control | YES | Non-application layer protocols | Raw socket traffic, custom network protocols | Rare | 17.4 | N/A |
| 17 | T1090 | Proxy | command-and-control | YES | Proxy usage for C2 | Traffic to known proxy IPs, SOCKS/HTTP proxy protocols | Rare | 17.4 | N/A |
| 18 | T1021.006 | Windows Remote Management | lateral-movement | YES | Windows Remote Management | WinRM traffic on ports 5985/5986, HTTP(S) protocol | Rare | 15.8 | Wizard Spider |

---

## 🟡 Partially Network Detectable Techniques (PARTIAL)

These techniques may generate network artifacts depending on implementation or usage context.

| # | Technique ID | Technique Name | Tactic | Classification | Reasoning | Network Artifact | Priority | Score | Threat Groups |
|---|--------------|----------------|--------|----------------|-----------|------------------|----------|-------|---------------|
| 1 | T1562.004 | Disable or Modify System Firewall | defense-evasion | PARTIAL | Firewall changes local, may block network detection | Sudden drop in expected network traffic patterns | Medium | 67.0 | APT38, Carbanak, Lazarus Group |
| 2 | T1078 | Valid Accounts | defense-evasion, persistence, privilege-escalation, initial-access | PARTIAL | Valid accounts used locally or remotely | Successful auth from unusual locations, off-hours logins | Common | 62.8 | Carbanak, Indrik Spider, Lazarus Group, Silence, Wizard Spider |
| 3 | T1016 | System Network Configuration Discovery | discovery | PARTIAL | Network config discovery, usually local | DHCP requests, ARP queries if network enumeration occurs | Common | 51.8 | Lazarus Group, Wizard Spider |
| 4 | T1049 | System Network Connections Discovery | discovery | PARTIAL | Network connection enumeration, local or remote | NetBIOS, SMB queries if remote, none if local commands | Common | 50.8 | APT38, Andariel, Lazarus Group |
| 5 | T1204.001 | Malicious Link | execution | PARTIAL | Clicking malicious link triggers network | HTTP requests to malicious URLs, redirects, downloads | Common | 50.4 | APT38, Cobalt Group, TA505, Wizard Spider |
| 6 | T1059.007 | JavaScript | execution | PARTIAL | JavaScript execution, may fetch remote content | HTTP requests if script downloads additional payloads | Common | 50.4 | Cobalt Group, Indrik Spider, Silence, TA505 |
| 7 | T1562.013 | Disable or Modify Network Device Firewall | defense-evasion | PARTIAL | Network device firewall changes | Changes visible in firewall logs, SNMP, config backups | Rare | 49.0 | APT38 |
| 8 | T1135 | Network Share Discovery | discovery | PARTIAL | Network share discovery | SMB/CIFS queries, NetBIOS enumeration traffic | Common | 46.8 | APT38, Wizard Spider |
| 9 | T1573.001 | Symmetric Cryptography | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Common | 41.4 | Lazarus Group |
| 10 | T1090.002 | External Proxy | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Common | 40.4 | Lazarus Group, Silence |
| 11 | T1056.001 | Keylogging | collection | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Common | 38.6 | APT38, Lazarus Group |
| 12 | T1132.001 | Standard Encoding | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Common | 36.4 | Lazarus Group |
| 13 | T1585.002 | Email Accounts | resource-development | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 34.6 | Indrik Spider, Lazarus Group, Wizard Spider |
| 14 | T1518 | Software Discovery | discovery | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 33.8 | N/A |
| 15 | T1189 | Drive-by Compromise | initial-access | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 32.6 | APT38, Andariel, Lazarus Group |
| 16 | T1102.002 | Bidirectional Communication | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 30.4 | Carbanak, Lazarus Group |
| 17 | T1558.003 | Kerberoasting | credential-access | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 29.8 | Indrik Spider, Wizard Spider |
| 18 | T1482 | Domain Trust Discovery | discovery | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 28.8 | N/A |
| 19 | T1113 | Screen Capture | collection | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 28.4 | Silence |
| 20 | T1518.002 | Backup Software Discovery | discovery | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 27.8 | Wizard Spider |
| 21 | T1680 | Local Storage Discovery | discovery | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 27.8 | Lazarus Group |
| 22 | T1559.002 | Dynamic Data Exchange | execution | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 27.4 | Cobalt Group, TA505 |
| 23 | T1573.002 | Asymmetric Cryptography | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 26.4 | Cobalt Group |
| 24 | T1008 | Fallback Channels | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 26.4 | Lazarus Group |
| 25 | T1561.002 | Disk Structure Wipe | impact | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 26.2 | APT38, Lazarus Group |
| 26 | T1529 | System Shutdown/Reboot | impact | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 26.2 | APT38, Lazarus Group |
| 27 | T1210 | Exploitation of Remote Services | lateral-movement | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 25.8 | Wizard Spider |
| 28 | T1110 | Brute Force | credential-access | PARTIAL | Brute force can be local or remote | Multiple failed auth attempts via SMB, RDP, SSH, LDAP | Medium | 25.8 | APT38 |
| 29 | T1021.005 | VNC | lateral-movement | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 25.8 | GCMAN |
| 30 | T1588.001 | Malware | resource-development | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 25.6 | Andariel, TA505 |
| 31 | T1584.004 | Server | resource-development | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 25.6 | Indrik Spider, Lazarus Group |
| 32 | T1587.001 | Malware | resource-development | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 25.6 | Indrik Spider, Lazarus Group |
| 33 | T1016.001 | Internet Connection Discovery | discovery | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 23.8 | N/A |
| 34 | T1505.003 | Web Shell | persistence | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 21.4 | APT38 |
| 35 | T1090.001 | Internal Proxy | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 21.4 | Lazarus Group |
| 36 | T1568.001 | Fast Flux DNS | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 21.4 | TA505 |
| 37 | T1104 | Multi-Stage Channels | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 21.4 | Lazarus Group |
| 38 | T1136 | Create Account | persistence | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 21.4 | Indrik Spider |
| 39 | T1001.003 | Protocol or Service Impersonation | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 21.4 | Lazarus Group |
| 40 | T1110.003 | Password Spraying | credential-access | PARTIAL | Password spraying against network services | Multiple login attempts across accounts, SMB, LDAP, HTTP | Rare | 20.8 | Lazarus Group |
| 41 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 20.4 | Lazarus Group, Wizard Spider |
| 42 | T1567.002 | Exfiltration to Cloud Storage | exfiltration | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Medium | 20.4 | Indrik Spider, Wizard Spider |
| 43 | T1560.003 | Archive via Custom Method | collection | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 18.4 | Lazarus Group |
| 44 | T1560.001 | Archive via Utility | collection | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 18.4 | Wizard Spider |
| 45 | T1560.002 | Archive via Library | collection | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 18.4 | Lazarus Group |
| 46 | T1560 | Archive Collected Data | collection | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 18.4 | Lazarus Group |
| 47 | T1133 | External Remote Services | persistence, initial-access | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 18.0 | Wizard Spider |
| 48 | T1090.003 | Multi-hop Proxy | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 17.4 | N/A |
| 49 | T1568.002 | Domain Generation Algorithms | command-and-control | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 17.4 | N/A |
| 50 | T1561.001 | Disk Content Wipe | impact | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 17.2 | Lazarus Group |
| 51 | T1072 | Software Deployment Tools | execution, lateral-movement | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 17.1 | Silence |
| 52 | T1608.001 | Upload Malware | resource-development | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 16.6 | TA505 |
| 53 | T1583.006 | Web Services | resource-development | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 16.6 | Lazarus Group |
| 54 | T1021 | Remote Services | lateral-movement | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 15.8 | Wizard Spider |
| 55 | T1590 | Gather Victim Network Information | reconnaissance | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 12.2 | Indrik Spider |
| 56 | T1091 | Replication Through Removable Media | lateral-movement, initial-access | PARTIAL | May involve network communication based on implementation | Protocol-specific traffic if network variant used | Rare | 11.2 | N/A |

---

## 🔵 Not Network Detectable Techniques (NO)

These techniques operate locally on the host and do not generate network artifacts detectable by NIDS.

**Count:** 143 techniques (see full CSV for complete list)

**Examples include:**
- T1562.001: Disable or Modify Tools (100.0) - Disabling security tools is local host activity
- T1070.004: File Deletion (95.0) - Local file deletion operations only
- T1140: Deobfuscate/Decode Files or Information (91.0) - Local file deobfuscation and decoding
- T1218.011: Rundll32 (90.0) - Local process execution via rundll32
- T1553.002: Code Signing (86.0) - Code signing is local file operation

---

## Key Findings & Recommendations

### 1. **Network Detection Coverage**
- Only **8.3%** of techniques are fully detectable via NIDS
- **25.8%** are partially detectable (context-dependent)
- **65.9%** require host-based detection mechanisms

### 2. **High-Priority Network Detectable Techniques**
Focus NIDS rules on these high-value targets:
- **T1105** - Ingress Tool Transfer (HTTP/HTTPS/FTP/SMB file transfers)
- **T1071.001** - Web Protocols (C2 over HTTP/HTTPS)
- **T1566.001** - Spearphishing Attachment (SMTP with attachments)
- **T1021.001** - RDP (Port 3389 traffic)

### 3. **Critical Threat Actors**
Most active groups in banking sector:
- **Lazarus Group** - 18 network-detectable techniques
- **APT38** - North Korean state-sponsored, banking-focused
- **Wizard Spider** - TrickBot/Ryuk operators
- **Cobalt Group** - ATM and SWIFT attacks
- **TA505** - Banking trojans and ransomware

### 4. **Recommended NIDS Signatures**
Prioritize detection for:
1. **C2 Communications** - HTTP/HTTPS beaconing patterns
2. **Lateral Movement** - RDP, SMB, SSH anomalies
3. **Data Exfiltration** - Large outbound transfers, cloud storage uploads
4. **Initial Access** - Spearphishing emails, drive-by downloads
5. **Reconnaissance** - Port scans, service discovery, network enumeration

### 5. **Defense Strategy**
- Deploy **layered detection**: NIDS + EDR + SIEM
- Focus host-based monitoring for the 66% non-network techniques
- Implement behavioral analytics for PARTIAL techniques
- Monitor authentication logs for Valid Accounts (T1078)
- Deploy email security for phishing (T1566.001/002)

---

**File Outputs:**
- `banking_nids_extended_analysis_20251222_020548.csv` - Full data export
- `NIDS_Classification_Extended_Table.md` - This document

**Analysis Date:** December 22, 2025
