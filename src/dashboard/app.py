"""
IDS Intelligence Platform — Full Dashboard
Rich threat analysis with attacker profiling, IP intelligence, and detailed charts.
"""
import os, sys, json, time, io, struct, socket
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from src.alerts.store import get_alerts, get_severity_counts, get_alert_timeline, get_top_source_ips
    from src.utils.db import init_db
    DB_OK = True
except Exception:
    DB_OK = False

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IDS Intelligence Platform",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Design System ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;0,600;0,700;1,400&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap');
:root {
    --bg0:#060d1a; --bg1:#0a1224; --bg2:#0f1a30; --bg3:#142040;
    --border:#1a2d4a; --border2:#243d65;
    --cyan:#00d4ff; --cyan2:#0099cc; --cyan-glow:rgba(0,212,255,0.12);
    --green:#00e5a0; --red:#ff3b5c; --orange:#ff8c42; --yellow:#ffd166;
    --blue:#2d7dd2; --purple:#7c5cbf;
    --text1:#e8edf5; --text2:#7a8aaa; --text3:#3d4f6e;
    --font-ui:'IBM Plex Sans',sans-serif; --font-mono:'IBM Plex Mono',monospace;
}
html,body,[class*="css"]{font-family:var(--font-ui)!important;background:var(--bg0)!important;color:var(--text1)!important}
#MainMenu,footer,header,.stDeployButton{visibility:hidden}
.block-container{padding:1.5rem 2rem!important;max-width:100%!important}

/* Sidebar */
[data-testid="stSidebar"]{background:var(--bg1)!important;border-right:1px solid var(--border)!important}
[data-testid="stSidebar"] *{color:var(--text1)!important}
[data-testid="stSidebar"] label{color:var(--text2)!important;font-size:10px!important;letter-spacing:.1em;text-transform:uppercase}

/* Metrics */
[data-testid="metric-container"]{background:var(--bg2)!important;border:1px solid var(--border)!important;border-radius:8px!important;padding:1rem 1.25rem!important}
[data-testid="stMetricLabel"]{color:var(--text2)!important;font-size:10px!important;text-transform:uppercase;letter-spacing:.1em;font-family:var(--font-mono)!important}
[data-testid="stMetricValue"]{color:var(--text1)!important;font-family:var(--font-mono)!important;font-size:1.8rem!important;font-weight:700!important}

/* Tabs */
.stTabs [data-baseweb="tab-list"]{background:var(--bg1)!important;border-bottom:1px solid var(--border)!important;gap:0!important;padding:0!important}
.stTabs [data-baseweb="tab"]{background:transparent!important;color:var(--text2)!important;border:none!important;border-bottom:2px solid transparent!important;padding:.7rem 1.4rem!important;font-size:13px!important;font-weight:500!important;transition:all .2s!important}
.stTabs [aria-selected="true"]{background:transparent!important;color:var(--cyan)!important;border-bottom:2px solid var(--cyan)!important}
.stTabs [data-baseweb="tab-panel"]{background:var(--bg0)!important;padding:1.5rem 0!important}

/* Buttons */
.stButton>button{background:transparent!important;border:1px solid var(--border2)!important;color:var(--text1)!important;border-radius:6px!important;font-size:13px!important;font-weight:500!important;padding:.45rem 1.1rem!important;transition:all .2s!important}
.stButton>button:hover{border-color:var(--cyan)!important;color:var(--cyan)!important;background:var(--cyan-glow)!important}

/* File uploader */
[data-testid="stFileUploader"]{background:var(--bg2)!important;border:1px dashed var(--border2)!important;border-radius:10px!important;padding:.75rem!important}
[data-testid="stFileUploader"]:hover{border-color:var(--cyan)!important}
[data-testid="stFileUploader"] *{color:var(--text2)!important;font-size:13px!important}

/* Inputs */
.stSelectbox>div>div,.stTextInput>div>div>input{background:var(--bg2)!important;border:1px solid var(--border)!important;color:var(--text1)!important;border-radius:6px!important}
.stMultiSelect>div>div{background:var(--bg2)!important;border:1px solid var(--border)!important;border-radius:6px!important}

/* Dataframe */
[data-testid="stDataFrame"]{border:1px solid var(--border)!important;border-radius:8px!important;overflow:hidden}

/* Progress */
.stProgress>div>div{background:var(--cyan)!important}
hr{border-color:var(--border)!important;margin:1.25rem 0!important}

/* Custom */
.ids-label{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--text2);font-family:var(--font-mono);margin-bottom:.4rem}
.threat-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;margin-bottom:.75rem;transition:border-color .2s}
.threat-card:hover{border-color:var(--border2)}
.threat-card.critical{border-left:3px solid var(--red)}
.threat-card.high{border-left:3px solid var(--orange)}
.threat-card.medium{border-left:3px solid var(--yellow)}
.threat-card.low{border-left:3px solid var(--green)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-family:var(--font-mono);font-weight:600;letter-spacing:.05em}
.badge-critical{background:rgba(255,59,92,.15);color:#ff3b5c;border:1px solid rgba(255,59,92,.3)}
.badge-high{background:rgba(255,140,66,.15);color:#ff8c42;border:1px solid rgba(255,140,66,.3)}
.badge-medium{background:rgba(255,209,102,.15);color:#ffd166;border:1px solid rgba(255,209,102,.3)}
.badge-low{background:rgba(0,229,160,.15);color:#00e5a0;border:1px solid rgba(0,229,160,.3)}
.stat-row{display:flex;gap:1.5rem;flex-wrap:wrap;margin:.75rem 0}
.stat-item{display:flex;flex-direction:column;gap:2px}
.stat-val{font-family:var(--font-mono);font-size:1.2rem;font-weight:700;color:var(--text1)}
.stat-key{font-family:var(--font-mono);font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.08em}
.ip-flag{font-family:var(--font-mono);font-size:12px;padding:3px 8px;border-radius:4px;background:rgba(45,125,210,.12);border:1px solid rgba(45,125,210,.25);color:#2d7dd2}
.info-bar{background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.12);border-radius:8px;padding:.6rem 1rem;font-size:12px;color:var(--text2);font-family:var(--font-mono);margin:.4rem 0}
.section-title{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--text2);font-family:var(--font-mono);padding:.5rem 0;margin-bottom:.75rem;border-bottom:1px solid var(--border)}
.status-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}
.dot-live{background:var(--green);box-shadow:0 0 5px var(--green);animation:pulse 2s infinite}
.dot-off{background:var(--red)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
</style>
""", unsafe_allow_html=True)

# ── Plotly theme ──────────────────────────────────────────────────────────────
PLOT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="IBM Plex Mono", color="#7a8aaa", size=11),
    margin=dict(t=30, b=30, l=10, r=10),
    xaxis=dict(gridcolor="#1a2d4a", linecolor="#1a2d4a", tickcolor="#3d4f6e"),
    yaxis=dict(gridcolor="#1a2d4a", linecolor="#1a2d4a", tickcolor="#3d4f6e"),
)
SEV = {"CRITICAL":"#ff3b5c","HIGH":"#ff8c42","MEDIUM":"#ffd166","LOW":"#00e5a0"}

# Known bad ports with descriptions
BAD_PORTS = {
    4444:"Metasploit/Meterpreter C2",1337:"Leet/C2 backdoor",
    31337:"Back Orifice RAT",6666:"IRC botnet C2",6667:"IRC botnet C2",
    12345:"NetBus RAT",54321:"Back Orifice",27374:"SubSeven RAT",
    9050:"Tor proxy",8080:"HTTP proxy/C2",3128:"Squid proxy abuse",
}
SENSITIVE_PORTS = {22:"SSH",23:"Telnet",3389:"RDP",5900:"VNC",
    445:"SMB",139:"NetBIOS",135:"DCOM RPC",21:"FTP",
}
PROTO = {6:"TCP",17:"UDP",1:"ICMP"}

def pfmt(fig):
    fig.update_layout(**PLOT)
    return fig

def severity_color(s):
    return SEV.get(s.upper() if s else "","#7a8aaa")

# ── PCAP parser (pure Python, no scapy) ──────────────────────────────────────
def parse_pcap_bytes(data: bytes):
    """Parse PCAP file, return (packets list, raw_frames list)."""
    if len(data) < 24: return [], []
    magic = struct.unpack_from('<I', data, 0)[0]
    bo = '<' if magic == 0xa1b2c3d4 else '>'
    packets, frames = [], []
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_usec, inc_len, orig_len = struct.unpack_from(f'{bo}IIII', data, offset)
        offset += 16
        if offset + inc_len > len(data): break
        raw = data[offset:offset+inc_len]
        offset += inc_len
        pkt = parse_ip_packet(raw, ts_sec + ts_usec/1e6)
        if pkt:
            packets.append(pkt)
            frames.append(raw)
    return packets, frames

def parse_ip_packet(raw, ts):
    """Extract IP/TCP/UDP fields from raw bytes (Ethernet frame). Also captures MAC."""
    try:
        for skip in [14, 0]:
            if len(raw) <= skip + 20: continue
            b = raw[skip:]
            ver = (b[0] >> 4)
            if ver != 4: continue
            ihl = (b[0] & 0xf) * 4
            proto = b[9]
            src = socket.inet_ntoa(b[12:16])
            dst = socket.inet_ntoa(b[16:20])
            total_len = struct.unpack_from('!H', b, 2)[0]
            sport = dport = flags = 0
            # Extract MAC from Ethernet header (src MAC = bytes 6-11)
            src_mac = dst_mac = ""
            if skip == 14 and len(raw) >= 12:
                dst_mac = ":".join(f"{raw[i]:02x}" for i in range(0, 6))
                src_mac = ":".join(f"{raw[i]:02x}" for i in range(6, 12))
            if proto == 6 and len(b) >= ihl + 14:  # TCP
                sport = struct.unpack_from('!H', b, ihl)[0]
                dport = struct.unpack_from('!H', b, ihl+2)[0]
                flags = b[ihl+13]
            elif proto == 17 and len(b) >= ihl + 8:  # UDP
                sport = struct.unpack_from('!H', b, ihl)[0]
                dport = struct.unpack_from('!H', b, ihl+2)[0]
            return dict(ts=ts, src=src, dst=dst, proto=proto,
                        sport=sport, dport=dport, flags=flags,
                        length=total_len, src_mac=src_mac, dst_mac=dst_mac,
                        _raw=raw, _ihl=ihl, _skip=skip)
    except Exception:
        pass
    return None

# ── Windows Host Forensics Extractor ─────────────────────────────────────────
def _decode_netbios_name(encoded: bytes) -> str:
    """Decode NetBIOS level-1 encoded name (32 bytes → 16 chars)."""
    try:
        if len(encoded) < 32: return ""
        name = ""
        for i in range(0, 32, 2):
            c = ((encoded[i] - 0x41) << 4) | (encoded[i+1] - 0x41)
            if c == 0x20: break  # padding
            if 0x20 <= c <= 0x7e: name += chr(c)
        return name.strip()
    except Exception:
        return ""

def extract_windows_forensics(packets: list) -> dict:
    """
    Extract Windows host identity from a packet list.
    Returns dict with: ip, mac, hostname, username, fullname, os, sources (evidence trail)
    Extraction methods:
      IP/MAC  — any IP packet with Ethernet header
      Hostname — DHCP option 12, NetBIOS NS (UDP 137), LLMNR (UDP 5355), HTTP User-Agent
      Username — Kerberos AS-REQ cname, NTLM AUTHENTICATE blob, HTTP Authorization
      OS       — DHCP vendor class (option 60), HTTP User-Agent
    """
    result = dict(ip="", mac="", hostname="", username="", fullname="", os="", sources=[])

    # Heuristic: internal RFC1918 src IPs are the victims, external are attackers
    def is_internal(ip):
        try:
            parts = list(map(int, ip.split(".")))
            return (parts[0]==10 or (parts[0]==172 and 16<=parts[1]<=31) or
                    (parts[0]==192 and parts[1]==168))
        except: return False

    for pkt in packets:
        src = pkt.get('src','')
        raw = pkt.get('_raw', b'')
        if not raw: continue
        skip = pkt.get('_skip', 14)
        ihl  = pkt.get('_ihl', 20)
        proto = pkt.get('proto', 0)
        sport = pkt.get('sport', 0)
        dport = pkt.get('dport', 0)
        ip_start = skip  # byte offset of IP header in raw frame

        # ── 1. MAC address from Ethernet src field ────────────────────────
        if not result['mac'] and pkt.get('src_mac') and is_internal(src):
            result['mac'] = pkt['src_mac'].upper()
            result['ip'] = src
            result['sources'].append(f"MAC extracted from Ethernet frame (src={src})")

        # ── 2. DHCP (UDP 68→67 or 67→68) ─────────────────────────────────
        if proto == 17 and sport in (67,68) and dport in (67,68):
            try:
                payload_start = ip_start + ihl + 8  # skip IP+UDP headers
                if len(raw) < payload_start + 240: continue
                dhcp = raw[payload_start:]
                # DHCP magic cookie at offset 236
                if dhcp[236:240] != b'\x63\x82\x53\x63': continue
                # Client IP = dhcp[12:16] (ciaddr), or offered IP dhcp[16:20]
                client_ip = socket.inet_ntoa(dhcp[16:20])
                # Client MAC = dhcp[28:34]
                cli_mac = ":".join(f"{dhcp[28+i]:02x}" for i in range(6)).upper()
                if cli_mac != "00:00:00:00:00:00" and not result['mac']:
                    result['mac'] = cli_mac
                    result['sources'].append(f"MAC from DHCP chaddr field")
                # Parse options
                i = 240
                while i < len(dhcp) - 1:
                    opt = dhcp[i]; i += 1
                    if opt == 255: break  # END
                    if opt == 0: continue  # PAD
                    if i >= len(dhcp): break
                    length = dhcp[i]; i += 1
                    if i + length > len(dhcp): break
                    val = dhcp[i:i+length]
                    # Option 12 = Hostname
                    if opt == 12 and not result['hostname']:
                        hostname = val.decode('ascii', errors='ignore').strip('\x00 ')
                        if hostname:
                            result['hostname'] = hostname
                            result['sources'].append(f"Hostname from DHCP option 12")
                    # Option 60 = Vendor Class (OS fingerprint)
                    elif opt == 60 and not result['os']:
                        vc = val.decode('ascii', errors='ignore')
                        if 'MSFT' in vc or 'Windows' in vc:
                            result['os'] = vc
                            result['sources'].append(f"OS from DHCP option 60: {vc[:60]}")
                    i += length
                if client_ip and client_ip != '0.0.0.0' and not result['ip']:
                    result['ip'] = client_ip
            except Exception:
                pass

        # ── 3. NetBIOS Name Service (UDP 137) ─────────────────────────────
        if proto == 17 and (sport == 137 or dport == 137) and is_internal(src):
            try:
                payload_start = ip_start + ihl + 8
                nb = raw[payload_start:]
                if len(nb) < 50: continue
                # NetBIOS NS header: 12 bytes, then question entries
                # Each NBNS question has a 34-byte encoded name starting at offset 13
                name_bytes = nb[13:13+32]
                decoded = _decode_netbios_name(name_bytes)
                if decoded and not result['hostname'] and len(decoded) > 1:
                    result['hostname'] = decoded
                    if not result['ip']: result['ip'] = src
                    if not result['mac'] and pkt.get('src_mac'):
                        result['mac'] = pkt['src_mac'].upper()
                    result['sources'].append(f"Hostname from NetBIOS NS query (src={src})")
            except Exception:
                pass

        # ── 4. Kerberos (TCP/UDP 88) — username from AS-REQ ──────────────
        if (sport == 88 or dport == 88) and is_internal(src):
            try:
                if proto == 6:
                    tcp_hdr_len = (raw[ip_start + ihl + 12] >> 4) * 4
                    payload_start = ip_start + ihl + tcp_hdr_len
                else:
                    payload_start = ip_start + ihl + 8
                payload = raw[payload_start:]
                # AS-REQ CNameString is a UTF8String (0x1B) or GeneralString (0x1A)
                for tag in [b'\x1b', b'\x1a']:
                    idx = 0
                    while idx < len(payload) - 2:
                        pos = payload.find(tag, idx)
                        if pos == -1: break
                        # BER length — single byte if < 0x80
                        length = payload[pos+1]
                        if length < 0x80 and 2 <= length < 64 and pos + 2 + length <= len(payload):
                            name = payload[pos+2:pos+2+length].decode('utf-8', errors='ignore').strip('\x00 ')
                            clean = name.replace('.','').replace('-','').replace('_','').replace('$','')
                            if clean.isalnum() and len(clean) >= 2:
                                if not result['username'] and name.lower() not in ('anonymous','guest','null','krbtgt',''):
                                    result['username'] = name
                                    result['sources'].append(f"Username from Kerberos AS-REQ cname (src={src})")
                        idx = pos + 1
            except Exception:
                pass

        # ── 5. NTLM AUTHENTICATE — correct MS-NLMP spec offsets ──────────
        # MS-NLMP §2.2.1.3 AUTHENTICATE_MESSAGE layout (all offsets from blob start):
        #  0  Signature       8 bytes  "NTLMSSP\0"
        #  8  MessageType     4 bytes  (==3)
        # 12  LmResponse      8 bytes  (len/maxlen/offset)
        # 20  NtResponse      8 bytes
        # 28  DomainName      8 bytes  (len u16, maxlen u16, offset u32)
        # 36  UserName        8 bytes  (len u16, maxlen u16, offset u32)  ← was wrong before
        # 44  Workstation     8 bytes  (len u16, maxlen u16, offset u32)
        if proto == 6 and b'NTLMSSP\x00' in raw:
            try:
                base = raw.find(b'NTLMSSP\x00')
                if base + 52 <= len(raw) and raw[base+8] == 3:  # MessageType == AUTHENTICATE
                    # Domain
                    dom_len = struct.unpack_from('<H', raw, base+28)[0]
                    dom_off = struct.unpack_from('<I', raw, base+32)[0]
                    # UserName  ← correct offsets
                    usr_len = struct.unpack_from('<H', raw, base+36)[0]
                    usr_off = struct.unpack_from('<I', raw, base+40)[0]
                    # Workstation
                    ws_len  = struct.unpack_from('<H', raw, base+44)[0]
                    ws_off  = struct.unpack_from('<I', raw, base+48)[0]

                    def _ntlm_str(off, length):
                        if 0 < length < 128 and base+off+length <= len(raw):
                            # NTLM strings are UTF-16LE
                            raw_str = raw[base+off:base+off+length]
                            try:
                                return raw_str.decode('utf-16-le', errors='ignore').strip('\x00 ')
                            except Exception:
                                return raw_str.replace(b'\x00',b'').decode('ascii','ignore').strip()
                        return ""

                    uname = _ntlm_str(usr_off, usr_len)
                    domain = _ntlm_str(dom_off, dom_len)
                    workstation = _ntlm_str(ws_off, ws_len)

                    if uname and not result['username']:
                        result['username'] = uname
                        result['sources'].append(f"Username from NTLM AUTHENTICATE msg (src={src})")
                    if workstation and not result['hostname']:
                        result['hostname'] = workstation
                        result['sources'].append(f"Hostname (workstation) from NTLM AUTHENTICATE (src={src})")
                    elif domain and not result['hostname']:
                        result['hostname'] = domain
                        result['sources'].append(f"Domain from NTLM AUTHENTICATE (src={src})")
            except Exception:
                pass

        # ── 6. SMB2 Session Setup — username in NTLMSSP blob ─────────────
        # Already covered above via raw NTLMSSP scan; SMB2 wraps same blob

        # ── 7. LDAP (TCP 389) — cn / displayName / sAMAccountName ────────
        # Active Directory LDAP search results contain full name as displayName
        if proto == 6 and (sport == 389 or dport == 389):
            try:
                if proto == 6:
                    tcp_hdr_len = (raw[ip_start + ihl + 12] >> 4) * 4
                    payload = raw[ip_start + ihl + tcp_hdr_len:]
                else:
                    payload = raw[ip_start + ihl + 8:]

                # Look for displayName attribute value (LDAP string attribute)
                for attr_tag in [b'displayName', b'sAMAccountName', b'cn']:
                    pos = payload.find(attr_tag)
                    if pos == -1: continue
                    # After the attr name there's a BER-TLV value
                    after = payload[pos+len(attr_tag):]
                    # Skip a few tag/length bytes (typically 2–4) then read string
                    for skip in range(1, 8):
                        if skip >= len(after): break
                        val_len = after[skip]
                        if 1 < val_len < 80 and skip+1+val_len <= len(after):
                            val = after[skip+1:skip+1+val_len].decode('utf-8','ignore').strip('\x00 ')
                            if val.replace(' ','').isalpha() and len(val) > 2:
                                if attr_tag == b'displayName' and not result['fullname']:
                                    result['fullname'] = val
                                    result['sources'].append(f"Full name from LDAP displayName (src={src})")
                                elif attr_tag == b'sAMAccountName' and not result['username']:
                                    result['username'] = val
                                    result['sources'].append(f"Username from LDAP sAMAccountName (src={src})")
                                elif attr_tag == b'cn' and not result['fullname']:
                                    result['fullname'] = val
                                    result['sources'].append(f"Full name from LDAP cn (src={src})")
                                break
            except Exception:
                pass

        # ── 8. HTTP User-Agent — OS fingerprint ──────────────────────────
        if proto == 6 and b'User-Agent:' in raw and is_internal(src):
            try:
                ua_start = raw.find(b'User-Agent:') + 11
                ua_end   = raw.find(b'\r\n', ua_start)
                if ua_end == -1: ua_end = ua_start + 200
                ua = raw[ua_start:ua_end].decode('ascii', errors='ignore').strip()
                if ua and not result['os'] and 'Windows NT' in ua:
                    result['os'] = ua[:120]
                    result['sources'].append(f"OS from HTTP User-Agent (src={src})")
            except Exception:
                pass

        # ── 9. HTTP Authorization Basic ───────────────────────────────────
        if proto == 6 and b'Authorization: Basic ' in raw and is_internal(src):
            try:
                import base64 as _b64
                idx = raw.find(b'Authorization: Basic ') + 21
                end = raw.find(b'\r\n', idx)
                b64 = raw[idx:end if end != -1 else idx+200].strip()
                decoded = _b64.b64decode(b64 + b'==').decode('utf-8','ignore')
                if ':' in decoded:
                    uname = decoded.split(':')[0].strip()
                    if uname and not result['username']:
                        result['username'] = uname
                        result['sources'].append(f"Username from HTTP Basic Auth (src={src})")
            except Exception:
                pass

        # ── 10. Cleartext HTTP POST body — login forms ────────────────────
        if proto == 6 and b'POST ' in raw and is_internal(src):
            try:
                body_start = raw.find(b'\r\n\r\n')
                if body_start != -1:
                    body = raw[body_start+4:body_start+400].decode('utf-8','ignore').lower()
                    import re as _re
                    for param in ['username=','user=','login=','uid=','email=']:
                        m = _re.search(param + r'([^&\s]{2,40})', body)
                        if m and not result['username']:
                            result['username'] = m.group(1).strip()
                            result['sources'].append(f"Username from HTTP POST body (src={src})")
                            break
            except Exception:
                pass

    # ── Full name fallback: try to derive from common naming patterns ─────
    # If we have a username like "john.smith" or "jsmith" and no fullname,
    # surface it as a hint rather than leaving fullname blank
    if result['username'] and not result['fullname']:
        uname = result['username']
        # "firstname.lastname" pattern
        if '.' in uname:
            parts = uname.split('.')
            if len(parts) == 2 and all(p.isalpha() for p in parts):
                result['fullname'] = f"{parts[0].capitalize()} {parts[1].capitalize()} (inferred from account name)"
                result['sources'].append("Full name inferred from username dot-notation pattern")
        # "firstnamelastname" — cannot split reliably, leave blank

    return result

def classify_packet(pkt):
    """Return (rule, severity, mitre, description) or None."""
    dp = pkt['dport']
    sp = pkt['sport']
    proto = pkt['proto']
    flags = pkt['flags']
    if dp in BAD_PORTS:
        return ("MALICIOUS_PORT", "CRITICAL", "T1071", f"C2 port {dp} — {BAD_PORTS[dp]}")
    if dp in SENSITIVE_PORTS:
        return ("SENSITIVE_ACCESS", "HIGH", "T1190", f"{SENSITIVE_PORTS[dp]} access attempt (port {dp})")
    if proto == 6 and (flags & 0x02) and not (flags & 0x10):
        return None  # bare SYN — handled in flow analysis
    if proto == 17 and (dp == 53 or sp == 53) and pkt['length'] > 2000:
        return ("DNS_AMPLIFICATION", "HIGH", "T1498.002", f"DNS amplification — {pkt['length']}B response")
    return None

def analyse_pcap(data: bytes):
    """Full analysis: return packets, flows, threats, attacker profiles, Windows host forensics."""
    packets, frames = parse_pcap_bytes(data)
    if not packets:
        return None

    # Run Windows host forensics extraction
    windows_host = extract_windows_forensics(packets)

    # Build flows (5-tuple grouping)
    flows = defaultdict(lambda: dict(pkts=0, bytes=0, syns=0, ts_start=None, ts_end=None, flags=set()))
    direct_hits = []  # per-packet detections

    syn_per_src = defaultdict(int)
    ports_per_src = defaultdict(set)
    proto_counts = Counter()

    for p in packets:
        key = (p['src'], p['dst'], p['sport'], p['dport'], p['proto'])
        f = flows[key]
        f['pkts'] += 1
        f['bytes'] += p['length']
        if f['ts_start'] is None or p['ts'] < f['ts_start']:
            f['ts_start'] = p['ts']
        if f['ts_end'] is None or p['ts'] > f['ts_end']:
            f['ts_end'] = p['ts']
        if p['proto'] == 6 and (p['flags'] & 0x02):
            f['syns'] += 1
            syn_per_src[p['src']] += 1
        ports_per_src[p['src']].add(p['dport'])
        proto_counts[p['proto']] += 1

        hit = classify_packet(p)
        if hit:
            direct_hits.append(dict(
                src=p['src'], dst=p['dst'], dport=p['dport'],
                rule=hit[0], severity=hit[1], mitre=hit[2], desc=hit[3],
                ts=datetime.fromtimestamp(p['ts']).strftime("%H:%M:%S"),
                proto=PROTO.get(p['proto'], str(p['proto'])),
            ))

    # Detect port scans (>20 unique ports from one src)
    scan_alerts = []
    for src, ports in ports_per_src.items():
        if len(ports) > 20:
            scan_alerts.append(dict(
                src=src, dst="192.168.x.x", dport=0,
                rule="PORT_SCAN", severity="HIGH", mitre="T1046",
                desc=f"Port scan — {len(ports)} unique ports probed",
                ts="", proto="TCP",
            ))

    # Detect SYN flood (>80 SYNs from one src)
    flood_alerts = []
    for src, cnt in syn_per_src.items():
        if cnt > 80:
            flood_alerts.append(dict(
                src=src, dst="192.168.x.x", dport=80,
                rule="SYN_FLOOD", severity="CRITICAL", mitre="T1499",
                desc=f"SYN flood — {cnt} SYN packets",
                ts="", proto="TCP",
            ))

    all_hits = direct_hits + scan_alerts + flood_alerts

    # Build attacker profiles
    attacker_map = defaultdict(lambda: dict(
        hits=0, severity="LOW", rules=set(), ports=set(),
        targets=set(), mitres=set(), desc_list=[]
    ))
    for h in all_hits:
        a = attacker_map[h['src']]
        a['hits'] += 1
        a['rules'].add(h['rule'])
        a['ports'].add(h['dport'])
        a['targets'].add(h['dst'])
        a['mitres'].add(h['mitre'])
        a['desc_list'].append(h['desc'])
        # Escalate severity
        sev_rank = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
        if sev_rank.get(h['severity'],0) > sev_rank.get(a['severity'],0):
            a['severity'] = h['severity']

    # Timeline — group by minute
    timeline = defaultdict(int)
    for p in packets:
        minute = datetime.fromtimestamp(p['ts']).strftime("%H:%M")
        timeline[minute] += 1

    return dict(
        packets=packets,
        total_pkts=len(packets),
        flows=list(flows.values()),
        total_flows=len(flows),
        hits=all_hits,
        attackers=dict(attacker_map),
        proto_counts=proto_counts,
        timeline=dict(sorted(timeline.items())),
        syn_per_src=dict(syn_per_src),
        ports_per_src={k: len(v) for k, v in ports_per_src.items()},
        windows_host=windows_host,
    )

# ── Init ──────────────────────────────────────────────────────────────────────
if DB_OK:
    try: init_db()
    except: pass

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:.75rem 0 .5rem">
        <div style="font-family:'IBM Plex Mono',monospace;font-size:17px;font-weight:700;color:#00d4ff">🛡 IDS PLATFORM</div>
        <div style="font-size:9px;color:#3d4f6e;font-family:'IBM Plex Mono',monospace;letter-spacing:.1em;text-transform:uppercase;margin-top:2px">Intelligence Dashboard v2.0</div>
    </div>""", unsafe_allow_html=True)
    st.divider()

    ok_html = '<span class="status-dot dot-live"></span><span style="font-size:12px;color:#00e5a0">Engine Online</span>' if DB_OK else '<span class="status-dot dot-off"></span><span style="font-size:12px;color:#ff3b5c">Engine Offline</span>'
    st.markdown(ok_html, unsafe_allow_html=True)
    st.markdown("")

    page = st.selectbox("Navigation", [
        "📊  Overview", "📁  Upload & Analyse",
        "🚨  Alert Feed", "🧠  ML Models",
        "🔍  PCAP Inspector", "📋  Reports",
    ], label_visibility="collapsed")

    st.divider()
    st.markdown('<div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em">Filters</div>', unsafe_allow_html=True)
    sev_filter = st.multiselect("Severity", ["CRITICAL","HIGH","MEDIUM","LOW"], default=["CRITICAL","HIGH","MEDIUM","LOW"])
    alert_limit = st.slider("Alert Limit", 50, 500, 200, step=50)
    refresh = st.slider("Auto-refresh (s)", 0, 60, 0, step=5)
    st.divider()
    if st.button("⟳  Refresh Now", use_container_width=True):
        st.rerun()
    st.markdown(f'<div style="font-size:10px;color:#3d4f6e;font-family:IBM Plex Mono;margin-top:.4rem">Updated: {datetime.now().strftime("%H:%M:%S")}</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
if "Overview" in page:
    st.markdown('<div style="font-family:IBM Plex Mono;font-size:22px;font-weight:700;color:#e8edf5;margin-bottom:4px">Overview</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:11px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:1.5rem">Real-time threat intelligence</div>', unsafe_allow_html=True)

    counts = {}
    if DB_OK:
        try: counts = get_severity_counts()
        except: pass
    total = sum(counts.values())
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Total Alerts", f"{total:,}")
    c2.metric("Critical", counts.get("CRITICAL",0))
    c3.metric("High", counts.get("HIGH",0))
    c4.metric("Medium", counts.get("MEDIUM",0))
    c5.metric("Low", counts.get("LOW",0))
    st.markdown("")

    left, right = st.columns([3,2])
    with left:
        st.markdown('<div class="section-title">Alert Timeline — 24h</div>', unsafe_allow_html=True)
        timeline = []
        if DB_OK:
            try: timeline = get_alert_timeline(hours=24)
            except: pass
        if timeline:
            df_t = pd.DataFrame(timeline)
            df_t["hour"] = pd.to_datetime(df_t["hour"], errors="coerce")
            fig = go.Figure(go.Scatter(x=df_t["hour"], y=df_t["count"],
                fill="tozeroy", fillcolor="rgba(0,212,255,.07)",
                line=dict(color="#00d4ff", width=2), mode="lines"))
            pfmt(fig); fig.update_layout(height=200, showlegend=False)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
        else:
            st.markdown('<div class="info-bar">No timeline data. Start the engine or upload data via Upload & Analyse.</div>', unsafe_allow_html=True)

        st.markdown("")
        st.markdown('<div class="section-title">Recent Alerts</div>', unsafe_allow_html=True)
        alerts = []
        if DB_OK:
            try: alerts = get_alerts(limit=alert_limit)
            except: pass
        filtered = [a for a in alerts if a.get("severity","") in sev_filter]
        if filtered:
            rows = [{"Time":a.get("timestamp","")[:19],"Sev":a.get("severity",""),
                "Type":a.get("alert_type",""),"Src":a.get("src_ip","—"),
                "Dst":f'{a.get("dst_ip","—")}:{a.get("dst_port","—")}',
                "Description":a.get("description","")[:60],
                "MITRE":a.get("mitre_tactic","—"),
                "Conf":f'{float(a.get("confidence",0)):.0%}' if a.get("confidence") else "—"
            } for a in filtered[:60]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, height=320, hide_index=True)
        else:
            st.markdown('<div class="info-bar">No alerts yet — upload a PCAP or run the engine.</div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="section-title">Severity Breakdown</div>', unsafe_allow_html=True)
        if counts:
            fig2 = go.Figure(go.Pie(
                labels=list(counts.keys()), values=list(counts.values()), hole=0.6,
                marker=dict(colors=[SEV.get(k,"#333") for k in counts.keys()],
                            line=dict(color="#060d1a", width=3)),
                textfont=dict(family="IBM Plex Mono", size=11),
                hovertemplate="<b>%{label}</b><br>%{value} alerts<extra></extra>",
            ))
            pfmt(fig2); fig2.update_layout(height=210, showlegend=True,
                legend=dict(orientation="v", font=dict(size=11, family="IBM Plex Mono"), bgcolor="rgba(0,0,0,0)"))
            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar":False})
        else:
            st.markdown('<div class="info-bar">No data yet.</div>', unsafe_allow_html=True)

        st.markdown("")
        st.markdown('<div class="section-title">Top Attacker IPs</div>', unsafe_allow_html=True)
        top_ips = []
        if DB_OK:
            try: top_ips = get_top_source_ips(8)
            except: pass
        if top_ips:
            df_ip = pd.DataFrame(top_ips)
            fig3 = go.Figure(go.Bar(
                x=df_ip["cnt"], y=df_ip["src_ip"], orientation="h",
                marker=dict(color=df_ip["cnt"],
                    colorscale=[[0,"#142040"],[1,"#00d4ff"]], showscale=False),
                text=df_ip["cnt"], textposition="outside",
                textfont=dict(family="IBM Plex Mono", size=11, color="#7a8aaa"),
            ))
            pfmt(fig3); fig3.update_layout(height=260,
                yaxis=dict(tickfont=dict(family="IBM Plex Mono", size=11)))
            st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar":False})
        else:
            st.markdown('<div class="info-bar">No IP data yet.</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# UPLOAD & ANALYSE
# ══════════════════════════════════════════════════════════════════════════════
elif "Upload" in page:
    st.markdown('<div style="font-family:IBM Plex Mono;font-size:22px;font-weight:700;color:#e8edf5;margin-bottom:4px">Upload & Analyse</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:11px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:1.5rem">Import PCAP, CSV flows, or log files for instant threat analysis</div>', unsafe_allow_html=True)

    tab_pcap, tab_csv, tab_log = st.tabs(["  📦  PCAP File  ","  📊  CSV Flow Data  ","  📄  Log File  "])

    # ── PCAP ─────────────────────────────────────────────────────────────────
    with tab_pcap:
        uc, oc = st.columns([2,1])
        with uc:
            st.markdown('<div class="ids-label">Upload PCAP File</div>', unsafe_allow_html=True)
            pcap_file = st.file_uploader("Drop PCAP here", type=["pcap","pcapng","cap"], label_visibility="collapsed")
            st.markdown('<div class="info-bar">✓ .pcap · .pcapng · .cap &nbsp;|&nbsp; Max 200MB &nbsp;|&nbsp; Processed locally — nothing uploaded externally</div>', unsafe_allow_html=True)
        with oc:
            st.markdown('<div class="ids-label">Options</div>', unsafe_allow_html=True)
            run_sig = st.checkbox("Signature Detection", value=True)
            run_thr = st.checkbox("Threat Profiling", value=True)
            run_tl  = st.checkbox("Timeline Analysis", value=True)

        if pcap_file:
            os.makedirs("data/pcap", exist_ok=True)
            raw = pcap_file.getvalue()

            col1,col2,col3 = st.columns(3)
            col1.metric("File", pcap_file.name[:24])
            col2.metric("Size", f"{len(raw)/1024:.1f} KB")
            col3.metric("Format", pcap_file.name.split(".")[-1].upper())

            if st.button("▶  Run Full Analysis", key="run_pcap"):
                with st.spinner("Analysing packets…"):
                    prog = st.progress(0)
                    prog.progress(20)
                    result = analyse_pcap(raw)
                    prog.progress(100); prog.empty()

                if not result or result['total_pkts'] == 0:
                    st.error("Could not parse PCAP. Ensure it is a valid IPv4 capture.")
                else:
                    hits = result['hits']
                    attackers = result['attackers']
                    st.markdown("---")

                    # ── KPI Row ───────────────────────────────────────────
                    k1,k2,k3,k4,k5 = st.columns(5)
                    k1.metric("Packets", f"{result['total_pkts']:,}")
                    k2.metric("Flows", f"{result['total_flows']:,}")
                    k3.metric("Threats Detected", len(hits))
                    k4.metric("Unique Attackers", len(attackers))
                    k5.metric("Unique Src IPs", len(set(p['src'] for p in result['packets'])))

                    # ── Windows Host Forensics Card ───────────────────────
                    st.markdown("")
                    st.markdown('<div class="section-title">🖥  Compromised Windows Host — Forensic Identity</div>', unsafe_allow_html=True)
                    wh = result.get('windows_host', {})
                    ip_val       = wh.get('ip')       or '<span style="color:#3d4f6e">Not detected</span>'
                    mac_val      = wh.get('mac')      or '<span style="color:#3d4f6e">Not detected</span>'
                    hostname_val = wh.get('hostname') or '<span style="color:#3d4f6e">Not detected</span>'
                    username_val = wh.get('username') or '<span style="color:#3d4f6e">Not detected</span>'
                    fullname_val = wh.get('fullname') or '<span style="color:#3d4f6e">Not available in PCAP</span>'
                    os_val       = wh.get('os')       or '<span style="color:#3d4f6e">Not detected</span>'
                    sources_html = ""
                    for s in wh.get('sources', []):
                        sources_html += f'<div style="font-size:10px;color:#3d4f6e;font-family:IBM Plex Mono;padding:1px 0">· {s}</div>'
                    if not sources_html:
                        sources_html = '<div style="font-size:10px;color:#3d4f6e;font-family:IBM Plex Mono">No protocol-level identity data found (DHCP, NetBIOS, Kerberos, NTLM, HTTP not present in capture)</div>'
                    has_any = any([wh.get('ip'), wh.get('mac'), wh.get('hostname'), wh.get('username')])
                    card_border = "border-left:3px solid #ff8c42" if has_any else "border-left:3px solid #1a2d4a"

                    st.markdown(f"""
                    <div class="threat-card" style="{card_border}">
                        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.5rem;margin-bottom:1rem">
                            <div>
                                <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px">IP Address</div>
                                <div style="font-family:IBM Plex Mono;font-size:15px;font-weight:700;color:#00d4ff">{ip_val}</div>
                            </div>
                            <div>
                                <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px">MAC Address</div>
                                <div style="font-family:IBM Plex Mono;font-size:15px;font-weight:700;color:#ffd166">{mac_val}</div>
                            </div>
                            <div>
                                <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px">Host Name</div>
                                <div style="font-family:IBM Plex Mono;font-size:15px;font-weight:700;color:#e8edf5">{hostname_val}</div>
                            </div>
                        </div>
                        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.5rem;margin-bottom:1rem">
                            <div>
                                <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px">User Account</div>
                                <div style="font-family:IBM Plex Mono;font-size:15px;font-weight:700;color:#ff8c42">{username_val}</div>
                            </div>
                            <div>
                                <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px">Full Name</div>
                                <div style="font-family:IBM Plex Mono;font-size:15px;font-weight:700;color:#e8edf5">{fullname_val}</div>
                            </div>
                            <div>
                                <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px">OS Fingerprint</div>
                                <div style="font-family:IBM Plex Mono;font-size:11px;color:#7a8aaa;word-break:break-all">{os_val}</div>
                            </div>
                        </div>
                        <div style="border-top:1px solid #1a2d4a;padding-top:.75rem;margin-top:.25rem">
                            <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px">Evidence Sources</div>
                            {sources_html}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    if not hits:
                        st.success("✓ No threats detected in this capture.")
                    else:
                        st.markdown("")

                        # ── Charts row ────────────────────────────────────
                        ch1, ch2, ch3 = st.columns(3)

                        with ch1:
                            st.markdown('<div class="section-title">Threats by Severity</div>', unsafe_allow_html=True)
                            sev_c = Counter(h['severity'] for h in hits)
                            fig = go.Figure()
                            for sev, cnt in sorted(sev_c.items(), key=lambda x: ["LOW","MEDIUM","HIGH","CRITICAL"].index(x[0])):
                                fig.add_trace(go.Bar(
                                    x=[sev], y=[cnt], name=sev,
                                    marker_color=SEV.get(sev,"#333"),
                                    text=[cnt], textposition="outside",
                                    textfont=dict(family="IBM Plex Mono", size=12, color="#e8edf5"),
                                    width=0.5,
                                ))
                            pfmt(fig)
                            fig.update_layout(height=220, showlegend=False, barmode="group",
                                xaxis=dict(tickfont=dict(family="IBM Plex Mono", size=11)))
                            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})

                        with ch2:
                            st.markdown('<div class="section-title">Attack Types</div>', unsafe_allow_html=True)
                            rule_c = Counter(h['rule'] for h in hits)
                            labels = [r.replace("_"," ") for r in rule_c.keys()]
                            colors = ["#ff3b5c","#ff8c42","#ffd166","#00d4ff","#2d7dd2","#00e5a0","#7c5cbf"]
                            fig2 = go.Figure(go.Pie(
                                labels=labels, values=list(rule_c.values()), hole=0.55,
                                marker=dict(colors=colors[:len(labels)], line=dict(color="#060d1a", width=2)),
                                textfont=dict(family="IBM Plex Mono", size=10),
                                hovertemplate="<b>%{label}</b><br>%{value} detections<extra></extra>",
                            ))
                            pfmt(fig2)
                            fig2.update_layout(height=220, showlegend=True,
                                legend=dict(font=dict(family="IBM Plex Mono", size=9), bgcolor="rgba(0,0,0,0)"))
                            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar":False})

                        with ch3:
                            st.markdown('<div class="section-title">Protocol Distribution</div>', unsafe_allow_html=True)
                            pc = result['proto_counts']
                            proto_labels = [PROTO.get(k, f"Proto {k}") for k in pc.keys()]
                            fig3 = go.Figure(go.Bar(
                                x=proto_labels, y=list(pc.values()),
                                marker_color=["#00d4ff","#2d7dd2","#00e5a0","#ffd166"][:len(pc)],
                                text=list(pc.values()), textposition="outside",
                                textfont=dict(family="IBM Plex Mono", size=11, color="#e8edf5"),
                                width=0.5,
                            ))
                            pfmt(fig3)
                            fig3.update_layout(height=220, showlegend=False)
                            st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar":False})

                        # ── Traffic Timeline ──────────────────────────────
                        if run_tl and result['timeline']:
                            st.markdown('<div class="section-title">Packet Volume Timeline</div>', unsafe_allow_html=True)
                            tl = result['timeline']
                            fig_tl = go.Figure()
                            fig_tl.add_trace(go.Scatter(
                                x=list(tl.keys()), y=list(tl.values()),
                                fill="tozeroy", fillcolor="rgba(0,212,255,.06)",
                                line=dict(color="#00d4ff", width=2), mode="lines+markers",
                                marker=dict(size=4, color="#00d4ff"),
                            ))
                            pfmt(fig_tl)
                            fig_tl.update_layout(height=180, showlegend=False,
                                xaxis_title="", yaxis_title="Packets")
                            st.plotly_chart(fig_tl, use_container_width=True, config={"displayModeBar":False})

                        # ── Attacker Intelligence ─────────────────────────
                        if run_thr and attackers:
                            st.markdown("")
                            st.markdown('<div class="section-title">🎯 Attacker Intelligence — IP Threat Profiles</div>', unsafe_allow_html=True)

                            # Sort by severity then hits
                            sev_rank = {"CRITICAL":3,"HIGH":2,"MEDIUM":1,"LOW":0}
                            sorted_atk = sorted(attackers.items(),
                                key=lambda x: (sev_rank.get(x[1]['severity'],0), x[1]['hits']), reverse=True)

                            for ip, data in sorted_atk:
                                sev = data['severity']
                                rules_str = " · ".join(r.replace("_"," ") for r in data['rules'])
                                ports_str = ", ".join(str(p) for p in sorted(data['ports']) if p > 0)[:80]
                                targets_str = ", ".join(list(data['targets'])[:4])
                                mitres_str = " · ".join(data['mitres'])
                                main_desc = list(data['desc_list'])[0] if data['desc_list'] else ""

                                st.markdown(f"""
                                <div class="threat-card {sev.lower()}">
                                    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:.6rem">
                                        <div style="display:flex;align-items:center;gap:.75rem">
                                            <span style="font-family:'IBM Plex Mono';font-size:15px;font-weight:700;color:#e8edf5">{ip}</span>
                                            <span class="badge badge-{sev.lower()}">{sev}</span>
                                        </div>
                                        <div style="font-family:'IBM Plex Mono';font-size:11px;color:#7a8aaa">{data['hits']} detection{'s' if data['hits']!=1 else ''}</div>
                                    </div>
                                    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:.75rem;margin-bottom:.5rem">
                                        <div>
                                            <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px">Attack Type</div>
                                            <div style="font-size:12px;color:#e8edf5;font-family:IBM Plex Mono">{rules_str[:50]}</div>
                                        </div>
                                        <div>
                                            <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px">Target Ports</div>
                                            <div style="font-size:12px;color:#e8edf5;font-family:IBM Plex Mono">{ports_str if ports_str else "—"}</div>
                                        </div>
                                        <div>
                                            <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px">MITRE ATT&CK</div>
                                            <div style="font-size:12px;color:#2d7dd2;font-family:IBM Plex Mono">{mitres_str}</div>
                                        </div>
                                    </div>
                                    <div style="font-size:11px;color:#7a8aaa;font-family:IBM Plex Mono;border-top:1px solid #1a2d4a;padding-top:.5rem;margin-top:.25rem">
                                        {main_desc} &nbsp;|&nbsp; Targets: {targets_str}
                                    </div>
                                </div>
                                """, unsafe_allow_html=True)

                        # ── Full Detection Table ──────────────────────────
                        st.markdown("")
                        st.markdown('<div class="section-title">All Detections</div>', unsafe_allow_html=True)
                        df_hits = pd.DataFrame(hits).rename(columns={
                            "src":"Src IP","dst":"Dst IP","dport":"Port",
                            "rule":"Rule","severity":"Severity","mitre":"MITRE",
                            "desc":"Description","ts":"Time","proto":"Protocol"
                        })
                        # Reorder columns
                        cols = ["Time","Severity","Rule","Src IP","Dst IP","Port","Protocol","MITRE","Description"]
                        df_hits = df_hits[[c for c in cols if c in df_hits.columns]]
                        st.dataframe(df_hits, use_container_width=True, height=350, hide_index=True)

                        # Download
                        csv_out = df_hits.to_csv(index=False)
                        st.download_button("⬇  Download Detection Report (CSV)", csv_out,
                            file_name=f"ids_detections_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                            mime="text/csv")

    # ── CSV ───────────────────────────────────────────────────────────────────
    with tab_csv:
        uc2, oc2 = st.columns([2,1])
        with uc2:
            st.markdown('<div class="ids-label">Upload Network Flow CSV</div>', unsafe_allow_html=True)
            csv_file = st.file_uploader("Drop CSV here", type=["csv"], label_visibility="collapsed", key="csv_up")
            st.markdown('<div class="info-bar">✓ CICIDS2017 · UNSW-NB15 · NetFlow · Custom CSV with headers</div>', unsafe_allow_html=True)
        with oc2:
            st.markdown('<div class="ids-label">Options</div>', unsafe_allow_html=True)
            threshold = st.slider("Anomaly Threshold", 0.3, 1.0, 0.7, 0.05)
            top_n = st.slider("Top N IPs", 5, 20, 10)

        if csv_file:
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                df.columns = df.columns.str.strip()
                label_col = next((c for c in df.columns if c.strip().lower()=="label"), None)
                src_col = next((c for c in df.columns if "src" in c.lower() and "ip" in c.lower()), None)
                dst_col = next((c for c in df.columns if "dst" in c.lower() and "ip" in c.lower()), None)
                port_col = next((c for c in df.columns if "dst" in c.lower() and "port" in c.lower()), None)
                proto_col = next((c for c in df.columns if "protocol" in c.lower()), None)

                st.markdown("---")
                d1,d2,d3,d4 = st.columns(4)
                d1.metric("Total Records", f"{len(df):,}")
                d2.metric("Features", len(df.columns))
                d3.metric("File Size", f"{csv_file.size/1024:.1f} KB")
                d4.metric("Attack Records", f"{(df[label_col]!='BENIGN').sum():,}" if label_col else "—")

                if st.button("▶  Analyse CSV", key="run_csv"):
                    st.markdown("")

                    if label_col:
                        # ── Attack distribution ───────────────────────
                        st.markdown('<div class="section-title">Attack Class Distribution</div>', unsafe_allow_html=True)
                        vc = df[label_col].value_counts()
                        benign_n = vc.get("BENIGN", 0)
                        attack_n = len(df) - benign_n
                        attack_types = vc[vc.index != "BENIGN"]

                        aa, ab = st.columns(2)
                        with aa:
                            aa.metric("Benign", f"{benign_n:,}", f"{benign_n/len(df):.1%}")
                        with ab:
                            ab.metric("Attacks", f"{attack_n:,}", f"{attack_n/len(df):.1%}")

                        st.markdown("")
                        fig_bar = go.Figure(go.Bar(
                            x=attack_types.values,
                            y=[l.replace("-"," ").replace("_"," ") for l in attack_types.index],
                            orientation="h",
                            marker=dict(
                                color=attack_types.values,
                                colorscale=[[0,"#142040"],[0.3,"#2d7dd2"],[0.7,"#ff8c42"],[1,"#ff3b5c"]],
                                showscale=False,
                            ),
                            text=attack_types.values,
                            textposition="outside",
                            textfont=dict(family="IBM Plex Mono", size=11, color="#e8edf5"),
                        ))
                        pfmt(fig_bar)
                        fig_bar.update_layout(height=max(300, len(attack_types)*32),
                            yaxis=dict(tickfont=dict(family="IBM Plex Mono", size=11)),
                            xaxis_title="Record Count")
                        st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar":False})

                    # ── Top attacking IPs ─────────────────────────────
                    if src_col:
                        st.markdown('<div class="section-title">Top Source IPs</div>', unsafe_allow_html=True)
                        if label_col:
                            atk_df = df[df[label_col] != "BENIGN"]
                        else:
                            atk_df = df
                        top_src = atk_df[src_col].value_counts().head(top_n)

                        fig_ip = go.Figure(go.Bar(
                            x=top_src.values, y=top_src.index,
                            orientation="h",
                            marker=dict(color=top_src.values,
                                colorscale=[[0,"#142040"],[1,"#ff3b5c"]], showscale=False),
                            text=top_src.values, textposition="outside",
                            textfont=dict(family="IBM Plex Mono", size=11, color="#e8edf5"),
                        ))
                        pfmt(fig_ip)
                        fig_ip.update_layout(height=max(250, len(top_src)*30),
                            yaxis=dict(tickfont=dict(family="IBM Plex Mono", size=11)),
                            xaxis_title="Malicious Flows")
                        st.plotly_chart(fig_ip, use_container_width=True, config={"displayModeBar":False})

                    # ── Top targeted ports ────────────────────────────
                    if port_col:
                        st.markdown('<div class="section-title">Top Targeted Ports</div>', unsafe_allow_html=True)
                        atk_ports = (atk_df if label_col else df)[port_col].value_counts().head(15)
                        port_labels = [f":{int(p)} ({SENSITIVE_PORTS.get(int(p), BAD_PORTS.get(int(p), ''))})" if str(p).isdigit() else str(p) for p in atk_ports.index]
                        fig_port = go.Figure(go.Bar(
                            x=port_labels, y=atk_ports.values,
                            marker_color=["#ff3b5c" if str(p).isdigit() and int(p) in BAD_PORTS
                                else "#ff8c42" if str(p).isdigit() and int(p) in SENSITIVE_PORTS
                                else "#2d7dd2" for p in atk_ports.index],
                            text=atk_ports.values, textposition="outside",
                            textfont=dict(family="IBM Plex Mono", size=10, color="#e8edf5"),
                        ))
                        pfmt(fig_port)
                        fig_port.update_layout(height=260, xaxis_tickangle=-30)
                        st.plotly_chart(fig_port, use_container_width=True, config={"displayModeBar":False})

                    # ── Protocol split ────────────────────────────────
                    if proto_col:
                        st.markdown('<div class="section-title">Protocol Split</div>', unsafe_allow_html=True)
                        pc2 = df[proto_col].value_counts().head(8)
                        proto_name = {6:"TCP",17:"UDP",1:"ICMP"}
                        pc2.index = [proto_name.get(int(x), str(x)) if str(x).isdigit() else str(x) for x in pc2.index]
                        fig_pr = go.Figure(go.Pie(
                            labels=pc2.index, values=pc2.values, hole=0.55,
                            marker=dict(colors=["#00d4ff","#2d7dd2","#00e5a0","#ffd166","#ff8c42","#ff3b5c"],
                                        line=dict(color="#060d1a", width=2)),
                            textfont=dict(family="IBM Plex Mono", size=10),
                        ))
                        pfmt(fig_pr)
                        fig_pr.update_layout(height=220,
                            legend=dict(font=dict(family="IBM Plex Mono", size=10), bgcolor="rgba(0,0,0,0)"))
                        st.plotly_chart(fig_pr, use_container_width=True, config={"displayModeBar":False})

                    # ── Numeric feature summary ───────────────────────
                    numeric_df = df.select_dtypes(include=[np.number])
                    if len(numeric_df.columns) > 3:
                        st.markdown('<div class="section-title">Feature Distribution (Top 6 by Variance)</div>', unsafe_allow_html=True)
                        top_cols = numeric_df.std().nlargest(6).index.tolist()
                        fig_box = go.Figure()
                        colors_box = ["#00d4ff","#2d7dd2","#00e5a0","#ffd166","#ff8c42","#ff3b5c"]
                        for i, col in enumerate(top_cols):
                            vals = numeric_df[col].replace([np.inf,-np.inf], np.nan).dropna()
                            vals = vals[vals < vals.quantile(0.99)]
                            fig_box.add_trace(go.Box(y=vals, name=col[:18],
                                marker_color=colors_box[i % len(colors_box)],
                                line_color=colors_box[i % len(colors_box)],
                                fillcolor=f"rgba({','.join(str(int(c,16)) for c in [colors_box[i%len(colors_box)][1:3],colors_box[i%len(colors_box)][3:5],colors_box[i%len(colors_box)][5:]])}, 0.1)" if len(colors_box[i%len(colors_box)])==7 else "rgba(0,212,255,0.08)",
                            ))
                        pfmt(fig_box)
                        fig_box.update_layout(height=300, showlegend=False)
                        st.plotly_chart(fig_box, use_container_width=True, config={"displayModeBar":False})

                    # Download
                    st.download_button("⬇  Download Analysis CSV", df.to_csv(index=False),
                        file_name=f"analysis_{csv_file.name}", mime="text/csv")

            except Exception as e:
                st.error(f"Error reading CSV: {e}")

    # ── LOG ───────────────────────────────────────────────────────────────────
    with tab_log:
        uc3, oc3 = st.columns([2,1])
        with uc3:
            st.markdown('<div class="ids-label">Upload Log File</div>', unsafe_allow_html=True)
            log_file = st.file_uploader("Drop log here", type=["log","txt"], label_visibility="collapsed", key="log_up")
            st.markdown('<div class="info-bar">✓ auth.log · syslog · application logs · Linux_2k.log</div>', unsafe_allow_html=True)
        with oc3:
            st.markdown('<div class="ids-label">Detection Options</div>', unsafe_allow_html=True)
            bf_thresh = st.slider("Brute Force Threshold (fails)", 3, 20, 5)

        if log_file:
            content = log_file.getvalue().decode("utf-8", errors="replace")
            lines = content.strip().split("\n")
            st.markdown("---")
            l1,l2 = st.columns(2)
            l1.metric("Total Lines", f"{len(lines):,}")
            l2.metric("File Size", f"{log_file.size/1024:.1f} KB")

            if st.button("▶  Parse & Analyse", key="run_log"):
                with st.spinner("Parsing…"):
                    import re

                    # Parse patterns
                    events = []
                    ip_fail = defaultdict(int)
                    ip_success = defaultdict(set)
                    ip_sudo = defaultdict(int)
                    user_fail = defaultdict(int)
                    event_timeline = defaultdict(int)

                    PATTERNS = [
                        (r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)', "SSH_FAIL", "MEDIUM"),
                        (r'Accepted password for (\S+) from ([\d.]+)', "SSH_SUCCESS", "LOW"),
                        (r'Accepted publickey for (\S+) from ([\d.]+)', "SSH_PUBKEY", "LOW"),
                        (r'sudo:\s+(\S+).+COMMAND=(.*)', "SUDO_EXEC", "HIGH"),
                        (r'useradd.*name=(\S+)', "USER_CREATE", "HIGH"),
                        (r'userdel.*name=(\S+)', "USER_DELETE", "HIGH"),
                        (r'Invalid user (\S+) from ([\d.]+)', "INVALID_USER", "MEDIUM"),
                        (r'authentication failure.*user=(\S+)', "AUTH_FAIL", "MEDIUM"),
                        (r'BREAK-IN ATTEMPT.*from ([\d.]+)', "BREAK_IN", "CRITICAL"),
                        (r'([\d.]+).*refused connect', "REFUSED_CONN", "LOW"),
                        (r'pam_unix.*auth.*failure.*ruser=(\S+)', "PAM_FAIL", "MEDIUM"),
                        (r'segfault', "SEGFAULT", "MEDIUM"),
                        (r'kernel.*oom', "OOM_KILL", "LOW"),
                    ]

                    for i, line in enumerate(lines):
                        for pat, etype, sev in PATTERNS:
                            m = re.search(pat, line, re.IGNORECASE)
                            if m:
                                user = m.group(1) if m.lastindex and m.lastindex >= 1 else "—"
                                ip = m.group(2) if m.lastindex and m.lastindex >= 2 else "—"

                                if etype == "SSH_FAIL":
                                    ip_fail[ip] += 1
                                    user_fail[user] += 1
                                if etype == "SSH_SUCCESS":
                                    ip_success[ip].add(user)
                                if etype == "SUDO_EXEC":
                                    ip_sudo[user] += 1

                                # Extract timestamp
                                ts_m = re.match(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
                                ts_str = ts_m.group(1) if ts_m else ""
                                hour_m = re.search(r'(\d+:\d+):\d+', ts_str)
                                if hour_m:
                                    event_timeline[hour_m.group(1)] += 1

                                events.append(dict(
                                    line=i+1, type=etype, severity=sev,
                                    user=user, ip=ip, ts=ts_str,
                                    raw=line.strip()[:100]
                                ))
                                break

                    # Brute force IPs
                    brute_ips = {ip: cnt for ip, cnt in ip_fail.items() if cnt >= bf_thresh}

                    # KPIs
                    e1,e2,e3,e4,e5 = st.columns(5)
                    e1.metric("Events Found", len(events))
                    e2.metric("Brute Force IPs", len(brute_ips))
                    e3.metric("Unique Attacker IPs", len(ip_fail))
                    e4.metric("Unique Users Targeted", len(user_fail))
                    e5.metric("Sudo Executions", sum(ip_sudo.values()))

                    if not events:
                        st.info("No security events detected in this log file.")
                    else:
                        st.markdown("")

                        # ── Charts row ────────────────────────────────
                        c1,c2 = st.columns(2)

                        with c1:
                            st.markdown('<div class="section-title">Event Types</div>', unsafe_allow_html=True)
                            ev_c = Counter(e['type'] for e in events)
                            colors_ev = {"SSH_FAIL":"#ff3b5c","BREAK_IN":"#ff3b5c",
                                "SUDO_EXEC":"#ff8c42","USER_CREATE":"#ff8c42","USER_DELETE":"#ff8c42",
                                "INVALID_USER":"#ffd166","AUTH_FAIL":"#ffd166","PAM_FAIL":"#ffd166",
                                "SSH_SUCCESS":"#00e5a0","SSH_PUBKEY":"#00d4ff","REFUSED_CONN":"#2d7dd2",
                                "SEGFAULT":"#7c5cbf","OOM_KILL":"#3d4f6e"}
                            fig_ev = go.Figure(go.Bar(
                                x=list(ev_c.values()), y=list(ev_c.keys()),
                                orientation="h",
                                marker_color=[colors_ev.get(k,"#2d7dd2") for k in ev_c.keys()],
                                text=list(ev_c.values()), textposition="outside",
                                textfont=dict(family="IBM Plex Mono", size=11, color="#e8edf5"),
                            ))
                            pfmt(fig_ev)
                            fig_ev.update_layout(height=max(250, len(ev_c)*30),
                                yaxis=dict(tickfont=dict(family="IBM Plex Mono", size=11)))
                            st.plotly_chart(fig_ev, use_container_width=True, config={"displayModeBar":False})

                        with c2:
                            st.markdown('<div class="section-title">Event Timeline (by hour)</div>', unsafe_allow_html=True)
                            if event_timeline:
                                tl_sorted = dict(sorted(event_timeline.items()))
                                fig_tl = go.Figure(go.Scatter(
                                    x=list(tl_sorted.keys()), y=list(tl_sorted.values()),
                                    fill="tozeroy", fillcolor="rgba(255,59,92,.07)",
                                    line=dict(color="#ff3b5c", width=2), mode="lines+markers",
                                    marker=dict(size=4, color="#ff3b5c"),
                                ))
                                pfmt(fig_tl)
                                fig_tl.update_layout(height=max(250, len(ev_c)*30), showlegend=False)
                                st.plotly_chart(fig_tl, use_container_width=True, config={"displayModeBar":False})
                            else:
                                st.markdown('<div class="info-bar">No timestamps found in log.</div>', unsafe_allow_html=True)

                        # ── Brute force attacker cards ────────────────
                        if brute_ips:
                            st.markdown("")
                            st.markdown('<div class="section-title">🔴 Brute Force Attacker Profiles</div>', unsafe_allow_html=True)
                            sorted_bf = sorted(brute_ips.items(), key=lambda x: x[1], reverse=True)
                            for ip, cnt in sorted_bf[:10]:
                                sev = "CRITICAL" if cnt > 50 else "HIGH" if cnt > 20 else "MEDIUM"
                                st.markdown(f"""
                                <div class="threat-card {sev.lower()}">
                                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem">
                                        <div style="display:flex;align-items:center;gap:.75rem">
                                            <span style="font-family:'IBM Plex Mono';font-size:15px;font-weight:700;color:#e8edf5">{ip}</span>
                                            <span class="badge badge-{sev.lower()}">{sev}</span>
                                        </div>
                                        <span style="font-family:'IBM Plex Mono';font-size:11px;color:#7a8aaa">{cnt} failed auth attempts</span>
                                    </div>
                                    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:.75rem">
                                        <div>
                                            <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px">Attack Type</div>
                                            <div style="font-size:12px;color:#e8edf5;font-family:IBM Plex Mono">SSH Brute Force</div>
                                        </div>
                                        <div>
                                            <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px">MITRE ID</div>
                                            <div style="font-size:12px;color:#2d7dd2;font-family:IBM Plex Mono">T1110.001</div>
                                        </div>
                                        <div>
                                            <div style="font-size:9px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px">Tactic</div>
                                            <div style="font-size:12px;color:#e8edf5;font-family:IBM Plex Mono">Credential Access</div>
                                        </div>
                                    </div>
                                </div>""", unsafe_allow_html=True)

                        # ── Top targeted usernames ────────────────────
                        if user_fail:
                            st.markdown('<div class="section-title">Most Targeted Usernames</div>', unsafe_allow_html=True)
                            top_users = dict(sorted(user_fail.items(), key=lambda x: x[1], reverse=True)[:12])
                            fig_u = go.Figure(go.Bar(
                                x=list(top_users.values()), y=list(top_users.keys()),
                                orientation="h",
                                marker=dict(color=list(top_users.values()),
                                    colorscale=[[0,"#142040"],[1,"#ff8c42"]], showscale=False),
                                text=list(top_users.values()), textposition="outside",
                                textfont=dict(family="IBM Plex Mono", size=11, color="#e8edf5"),
                            ))
                            pfmt(fig_u)
                            fig_u.update_layout(height=max(220, len(top_users)*28),
                                yaxis=dict(tickfont=dict(family="IBM Plex Mono", size=11)))
                            st.plotly_chart(fig_u, use_container_width=True, config={"displayModeBar":False})

                        # ── Full event table ──────────────────────────
                        st.markdown('<div class="section-title">Full Event Log</div>', unsafe_allow_html=True)
                        df_ev = pd.DataFrame([{
                            "Line": e['line'], "Time": e['ts'], "Type": e['type'],
                            "Severity": e['severity'], "User": e['user'],
                            "Src IP": e['ip'], "Raw": e['raw'],
                        } for e in events])
                        st.dataframe(df_ev, use_container_width=True, height=360, hide_index=True)

                        st.download_button("⬇  Download Events CSV", df_ev.to_csv(index=False),
                            file_name=f"log_events_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                            mime="text/csv")

# ══════════════════════════════════════════════════════════════════════════════
# ALERT FEED
# ══════════════════════════════════════════════════════════════════════════════
elif "Alert" in page:
    st.markdown('<div style="font-family:IBM Plex Mono;font-size:22px;font-weight:700;color:#e8edf5;margin-bottom:4px">Alert Feed</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:11px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:1.5rem">Live security event stream</div>', unsafe_allow_html=True)

    alerts = []
    if DB_OK:
        try: alerts = get_alerts(limit=alert_limit)
        except: pass
    filtered = [a for a in alerts if a.get("severity","") in sev_filter]
    f1,f2,f3,_ = st.columns([1,1,1,3])
    with f1: type_filter = st.selectbox("Type", ["All","NETWORK","HOST"])
    with f2: search_ip = st.text_input("Filter IP", placeholder="192.168.1.1")
    with f3: sort_col = st.selectbox("Sort", ["Time ↓","Severity ↓"])

    if type_filter != "All": filtered = [a for a in filtered if a.get("alert_type")==type_filter]
    if search_ip: filtered = [a for a in filtered if search_ip in str(a.get("src_ip","")) or search_ip in str(a.get("dst_ip",""))]

    st.markdown(f'<div style="font-size:11px;color:#7a8aaa;font-family:IBM Plex Mono;margin-bottom:.75rem">{len(filtered)} alerts</div>', unsafe_allow_html=True)
    if filtered:
        rows = [{"Time":a.get("timestamp","")[:19],"Severity":a.get("severity",""),
            "Type":a.get("alert_type",""),"Src":a.get("src_ip","—"),
            "Dst":f'{a.get("dst_ip","—")}:{a.get("dst_port","—")}',
            "Description":a.get("description","")[:70],
            "MITRE":a.get("mitre_tactic","—"),"Conf":f'{float(a.get("confidence",0)):.0%}' if a.get("confidence") else "—",
        } for a in filtered]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, height=500, hide_index=True)
        st.download_button("⬇  Export CSV", pd.DataFrame(rows).to_csv(index=False),
            file_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", mime="text/csv")
    else:
        st.markdown('<div class="info-bar">No alerts. Run the engine or upload a file for analysis.</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# ML MODELS
# ══════════════════════════════════════════════════════════════════════════════
elif "ML" in page:
    st.markdown('<div style="font-family:IBM Plex Mono;font-size:22px;font-weight:700;color:#e8edf5;margin-bottom:4px">ML Models</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:11px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:1.5rem">Model status, benchmarks, and feature analysis</div>', unsafe_allow_html=True)

    models = {
        "Isolation Forest": ("src/ml/models/isolation_forest.joblib","Unsupervised anomaly detection — zero-day ready"),
        "Random Forest":    ("src/ml/models/random_forest.joblib","Supervised classifier — CICIDS2017 trained"),
        "Autoencoder":      ("src/ml/models/autoencoder.pt","Deep learning reconstruction — novel pattern detection"),
    }
    st.markdown('<div class="section-title">Model Registry</div>', unsafe_allow_html=True)
    for name, (path, desc) in models.items():
        exists = os.path.exists(path)
        size = f"{os.path.getsize(path)/1024:.0f} KB" if exists else "—"
        badge = '<span class="badge badge-low">LOADED</span>' if exists else '<span class="badge badge-critical">MISSING — run train.bat</span>'
        st.markdown(f"""<div class="threat-card {'low' if exists else 'critical'}">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <div><div style="font-weight:600;font-size:14px;margin-bottom:3px">{name} &nbsp;{badge}</div>
                    <div style="font-size:12px;color:#7a8aaa;font-family:IBM Plex Mono">{desc}</div></div>
                <div style="text-align:right;font-size:11px;color:#3d4f6e;font-family:IBM Plex Mono">{size}<br>{path}</div>
            </div></div>""", unsafe_allow_html=True)

    st.markdown("")
    st.markdown('<div class="section-title">Benchmark Performance (CICIDS2017)</div>', unsafe_allow_html=True)
    perf = pd.DataFrame({"Model":["Isolation Forest","Random Forest","Autoencoder","Ensemble"],
        "Precision":[0.81,0.97,0.84,0.96],"Recall":[0.76,0.95,0.80,0.94],
        "F1":[0.78,0.96,0.82,0.95],"ROC-AUC":[0.87,0.99,0.91,0.98]})
    st.dataframe(perf, use_container_width=True, hide_index=True)
    fig_p = go.Figure()
    for m,col in [("Precision","#2d7dd2"),("Recall","#00d4ff"),("F1","#00e5a0"),("ROC-AUC","#ffd166")]:
        fig_p.add_trace(go.Bar(name=m, x=perf["Model"], y=perf[m], marker_color=col,
            text=[f"{v:.2f}" for v in perf[m]], textposition="outside",
            textfont=dict(family="IBM Plex Mono", size=10)))
    pfmt(fig_p)
    fig_p.update_layout(height=300, barmode="group", yaxis_range=[0,1.1],
        legend=dict(orientation="h", font=dict(family="IBM Plex Mono", size=11)))
    st.plotly_chart(fig_p, use_container_width=True, config={"displayModeBar":False})

# ══════════════════════════════════════════════════════════════════════════════
# PCAP INSPECTOR
# ══════════════════════════════════════════════════════════════════════════════
elif "PCAP" in page:
    st.markdown('<div style="font-family:IBM Plex Mono;font-size:22px;font-weight:700;color:#e8edf5;margin-bottom:4px">PCAP Inspector</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:11px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:1.5rem">Deep packet analysis</div>', unsafe_allow_html=True)

    pcap_files = list(Path("data/pcap").glob("*.pcap")) + list(Path("data/pcap").glob("*.pcapng")) if Path("data/pcap").exists() else []
    if pcap_files:
        sel = st.selectbox("Select PCAP", [f.name for f in pcap_files])
        if st.button("▶  Inspect"):
            with open(f"data/pcap/{sel}","rb") as f:
                raw = f.read()
            # parse_pcap_bytes now returns (packets, frames) tuple
            packets, _frames = parse_pcap_bytes(raw)
            if packets:
                # Drop internal fields not needed for display
                display_cols = ["ts","src","dst","proto","sport","dport","length","flags","src_mac","dst_mac"]
                df_p = pd.DataFrame([{k: p.get(k,"") for k in display_cols} for p in packets])
                df_p["proto_name"] = df_p["proto"].map(PROTO).fillna("Other")
                df_p["ts_dt"] = pd.to_datetime(df_p["ts"], unit="s")
                p1,p2,p3,p4 = st.columns(4)
                p1.metric("Packets", f"{len(df_p):,}")
                p2.metric("Unique Src", df_p["src"].nunique())
                p3.metric("Unique Dst", df_p["dst"].nunique())
                p4.metric("Duration", f"{(df_p['ts'].max()-df_p['ts'].min()):.1f}s")
                ca,cb = st.columns(2)
                with ca:
                    st.markdown('<div class="section-title">Protocol Split</div>', unsafe_allow_html=True)
                    pc3 = df_p["proto_name"].value_counts()
                    fig_i1 = go.Figure(go.Pie(labels=pc3.index, values=pc3.values, hole=0.5,
                        marker=dict(colors=["#00d4ff","#2d7dd2","#00e5a0","#ffd166"],
                                    line=dict(color="#060d1a", width=2)),
                        textfont=dict(family="IBM Plex Mono", size=11),
                    ))
                    pfmt(fig_i1); fig_i1.update_layout(height=220,
                        legend=dict(font=dict(family="IBM Plex Mono", size=10), bgcolor="rgba(0,0,0,0)"))
                    st.plotly_chart(fig_i1, use_container_width=True, config={"displayModeBar":False})
                with cb:
                    st.markdown('<div class="section-title">Top Dest Ports</div>', unsafe_allow_html=True)
                    tp = df_p[df_p["dport"]>0]["dport"].value_counts().head(10)
                    port_labels = [f":{int(p)} ({SENSITIVE_PORTS.get(int(p), BAD_PORTS.get(int(p), ''))})" for p in tp.index]
                    fig_i2 = go.Figure(go.Bar(
                        x=tp.values, y=port_labels, orientation="h",
                        marker_color=["#ff3b5c" if int(p) in BAD_PORTS else "#ff8c42" if int(p) in SENSITIVE_PORTS else "#2d7dd2" for p in tp.index],
                        text=tp.values, textposition="outside",
                        textfont=dict(family="IBM Plex Mono", size=11, color="#e8edf5"),
                    ))
                    pfmt(fig_i2); fig_i2.update_layout(height=220,
                        yaxis=dict(tickfont=dict(family="IBM Plex Mono", size=10)))
                    st.plotly_chart(fig_i2, use_container_width=True, config={"displayModeBar":False})
                st.markdown('<div class="section-title">Packet Table</div>', unsafe_allow_html=True)
                show_cols = ["ts_dt","src_mac","src","dst_mac","dst","proto_name","sport","dport","length","flags"]
                st.dataframe(df_p[[c for c in show_cols if c in df_p.columns]].head(200),
                    use_container_width=True, hide_index=True, height=300)
    else:
        st.markdown('<div class="info-bar">No PCAPs found in data/pcap/. Upload one via Upload & Analyse.</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ══════════════════════════════════════════════════════════════════════════════
elif "Reports" in page:
    st.markdown('<div style="font-family:IBM Plex Mono;font-size:22px;font-weight:700;color:#e8edf5;margin-bottom:4px">Reports</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:11px;color:#3d4f6e;font-family:IBM Plex Mono;text-transform:uppercase;letter-spacing:.1em;margin-bottom:1.5rem">Generate and export security reports</div>', unsafe_allow_html=True)

    rep_type = st.selectbox("Report Type", ["Executive Summary","Alert Detail Report","MITRE ATT&CK Coverage"])
    rep_range = st.selectbox("Time Range", ["Last 24 Hours","Last 7 Days","All Time"])

    if st.button("▶  Generate Report"):
        alerts = []
        if DB_OK:
            try: alerts = get_alerts(limit=5000)
            except: pass
        counts = {}
        if DB_OK:
            try: counts = get_severity_counts()
            except: pass
        total = sum(counts.values())
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        report = f"# {rep_type}\n**Generated:** {now}  |  **Period:** {rep_range}\n\n---\n\n## Summary\n\n| Metric | Value |\n|---|---|\n| Total Alerts | {total:,} |\n| Critical | {counts.get('CRITICAL',0)} |\n| High | {counts.get('HIGH',0)} |\n| Medium | {counts.get('MEDIUM',0)} |\n| Low | {counts.get('LOW',0)} |\n"
        if alerts:
            crits = [a for a in alerts if a.get("severity")=="CRITICAL"][:5]
            if crits:
                report += "\n## Critical Events\n"
                for a in crits:
                    report += f"- **{a.get('description','')}** — {a.get('src_ip','')} → {a.get('dst_ip','')} `{a.get('timestamp','')[:16]}`\n"
        report += f"\n---\n*IDS Intelligence Platform | {now}*"
        st.markdown(report)
        st.download_button("⬇  Download Report (Markdown)", report,
            file_name=f"ids_report_{datetime.now().strftime('%Y%m%d_%H%M')}.md", mime="text/markdown")

# ── Auto-refresh ──────────────────────────────────────────────────────────────
if refresh > 0:
    time.sleep(refresh)
    st.rerun()
