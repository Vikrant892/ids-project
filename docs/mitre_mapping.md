# MITRE ATT&CK Mapping

## Detections by Tactic

| Alert Type | Tactic | Technique ID | Technique Name |
|---|---|---|---|
| PORT_SCAN | Reconnaissance | T1046 | Network Service Discovery |
| KNOWN_BAD_IP | Initial Access | T1133 | External Remote Services |
| SQL_INJECTION | Initial Access | T1190 | Exploit Public-Facing Application |
| SYN_FLOOD | Impact | T1498.001 | Direct Network Flood |
| DATA_EXFILTRATION | Exfiltration | T1041 | Exfiltration Over C2 Channel |
| LATERAL_MOVEMENT | Lateral Movement | T1021.002 | SMB/Windows Admin Shares |
| HIGH_RISK_PORT_ACCESS | Lateral Movement | T1021 | Remote Services |
| SSH_BRUTE_FORCE | Credential Access | T1110.001 | Password Guessing |
| AUTH_FAIL | Credential Access | T1110 | Brute Force |
| PASSWD_CHANGE | Credential Access | T1098 | Account Manipulation |
| FILE_MODIFIED | Defense Evasion | T1565.001 | Stored Data Manipulation |
| FILE_DELETED | Defense Evasion | T1070 | Indicator Removal |
| PERMISSION_CHANGE | Defense Evasion | T1222 | File Permissions Modification |
| NEW_USER | Persistence | T1136 | Create Account |
| FILE_CREATED | Persistence | T1543 | Create or Modify System Process |
| SUSPICIOUS_PROCESS | Execution | T1059 | Command and Scripting Interpreter |
| PRIVILEGE_ESCALATION_ATTEMPT | Privilege Escalation | T1068 | Exploitation for Privilege Escalation |

## Coverage by Tactic

- Reconnaissance: ✅
- Initial Access: ✅
- Execution: ✅
- Persistence: ✅
- Privilege Escalation: ✅
- Defense Evasion: ✅
- Credential Access: ✅
- Lateral Movement: ✅
- Exfiltration: ✅
- Impact: ✅
- Command & Control: ⚠️ Partial (via data exfiltration pattern)
- Collection: ❌ Phase 2
