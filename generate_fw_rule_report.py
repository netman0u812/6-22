#!/usr/bin/env python3
"""
generate_fw_rule_report.py
==========================
Analyses Palo Alto firewall Splunk logs and generates an interactive HTML
firewall rule recommendation report.

Focuses on sessions that actually established and exchanged data (packets_out +
packets_in > MIN_PKTS). Enriches source IPs against all_IP_networks (v4.0 SSOT)
and destination IPs against the ip_dataset registry (AWS, Azure, GCP, CrowdStrike
and any other registered providers).

Rule logic:  SRC_IP (ephemeral src port >1024)  -->  DEST_IP : DEST_PORT
Recommendation actions: ALLOW | MONITOR | REVIEW | BLOCK

Usage:
  python generate_fw_rule_report.py --log NOT_80_OR_443_NOT_TCP-FIN.csv
  python generate_fw_rule_report.py --log *.csv --dataset-dir ./ipam --ip-dataset-dir .
  python generate_fw_rule_report.py --log file.csv --min-pkts 5 --out-dir ./fw-reports

Options:
  --log FILE [FILE...]      Input Splunk CSV log file(s) (required)
  --dataset-dir DIR         Directory containing all_IP_networks_v*.csv [default: ./]
  --ip-dataset-dir DIR      Directory containing ip_dataset_*.csv files [default: ./]
  --out-dir DIR             Output directory [default: ./fw-reports]
  --ent-master FILE         Path to ent_host_master.csv (preferred over ent-ipdataset-*.csv)
  --min-pkts N              Minimum total packet count to consider session
                            established [default: 10]
  --title TEXT              Report title [default: auto from filename]
  --dry-run                 Parse and analyse; print stats; write no files
  -v, --verbose             Verbose output
"""

import argparse
import base64
import csv
import glob
import gzip
import ipaddress
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = '2.0'

# ── v2.0 — Performance overhaul ───────────────────────────────────────────────
# Bootstrap reduced from ~387 MB JSON to ~50-80 MB by:
#   • Deduping `ipam` blobs by src24 (161K inline → 1 dict of ~300 keys)
#   • Deduping `dest` blobs by dest_ip (161K inline → 1 dict of ~1.6K keys)
#   • Dropping empty-string / empty-collection fields
#   • Pre-computing per-rule search haystack (_hay) so the client never
#     rebuilds it on every keystroke
#   • Pre-splitting rules by action so the BLOCK/REVIEW/MONITOR/ALLOW tabs
#     don't scan the full 161K array
# Client (HTML template) is rewritten to:
#   • Virtualize the rule list (render only viewport + buffer)
#   • Lazy-build rule body HTML on expand (not upfront)
#   • Debounce search (250ms)
#   • Use event delegation (one listener, not 161K inline onclicks)

# Maximum ip_dataset LPM records before a performance warning is emitted.
# At 100K records the per-session linear scan is still fast; above this
# threshold lookup latency grows noticeably on large log files.
MAX_LPM_ROWS = 300_000

# ── Port risk classification ──────────────────────────────────────────────────
PORT_RISK = {
    # (service_name, risk_level, note)
    # CRITICAL — should never traverse the perimeter uncontrolled
    25:    ('SMTP',          'CRITICAL', 'Direct internet SMTP — mail relay / C2 exfil risk. Block and route through mail gateway.'),
    23:    ('Telnet',        'CRITICAL', 'Cleartext remote access. Unconditional block — replace with SSH.'),
    135:   ('MS-RPC',        'CRITICAL', 'Windows RPC endpoint mapper — lateral movement / ransomware vector. Never allow to internet.'),
    139:   ('NetBIOS-SSN',   'CRITICAL', 'NetBIOS session service — should never reach the internet.'),
    445:   ('SMB',           'CRITICAL', 'SMB — primary ransomware vector (EternalBlue/WannaCry). Block at perimeter.'),
    3389:  ('RDP',           'CRITICAL', 'Remote Desktop Protocol — brute force and ransomware primary attack surface.'),
    5900:  ('VNC',           'CRITICAL', 'VNC remote desktop — cleartext, unauthenticated by default. Block.'),
    1723:  ('PPTP',          'CRITICAL', 'PPTP VPN — deprecated protocol, cryptographically broken (MS-CHAPv2). Block.'),
    515:   ('LPD',           'CRITICAL', 'BSD line printer daemon — legacy, no authentication. Block.'),
    9100:  ('Raw-Print',     'CRITICAL', 'Raw/JetDirect printing — data exfil via print spool. Block to internet.'),
    111:   ('RPCbind',       'CRITICAL', 'RPC portmapper — remote exploit history. Block at perimeter.'),
    162:   ('SNMP-Trap',     'HIGH',     'SNMP trap receiver — exposes device reachability. Restrict to monitoring subnet.'),
    389:   ('LDAP',          'HIGH',     'LDAP cleartext — credential exposure. Use LDAPS (636) or restrict to LAN.'),
    88:    ('Kerberos',      'HIGH',     'Kerberos — ticket harvesting attacks if exposed externally.'),
    143:   ('IMAP',          'HIGH',     'IMAP cleartext — migrate to IMAPS (993). Block cleartext.'),
    631:   ('IPP',           'HIGH',     'Internet Printing Protocol — restrict to LAN printing subnet only.'),
    # HIGH — significant risk, needs justification
    5938:  ('TeamViewer',    'HIGH',     'TeamViewer remote access — verify business need and restrict to approved IPs.'),
    8089:  ('Splunk-Mgmt',   'HIGH',     'Splunk management/REST API port — restrict to Splunk infrastructure IPs only.'),
    5061:  ('SIP-TLS',       'MEDIUM',   'SIP over TLS — VoIP signalling. Allow if voice infrastructure, else investigate.'),
    993:   ('IMAPS',         'MEDIUM',   'IMAP over SSL — encrypted mail access. Verify business need vs webmail policy.'),
    5228:  ('Google-FCM',    'MEDIUM',   'Google Firebase Cloud Messaging (Android push notifications). Likely legitimate MDM/app traffic.'),
    5222:  ('XMPP',          'MEDIUM',   'XMPP/Jabber instant messaging. Verify approved collaboration tool.'),
    8100:  ('Alt-HTTP',      'MEDIUM',   'Alternate HTTP port — identify the application before allowing.'),
    4318:  ('OTLP',          'MEDIUM',   'OpenTelemetry collector protocol — verify destination is approved observability platform.'),
    3478:  ('STUN',          'LOW',      'STUN/TURN — NAT traversal for WebRTC, MS Teams, Zoom. Expected if UC platforms in use.'),
    19302: ('STUN-Google',   'LOW',      'Google STUN — NAT traversal for Google Meet / WebRTC. Expected with Google Workspace.'),
    9930:  ('Unknown',       'MEDIUM',   'Unclassified port — identify application before creating rule.'),
    8613:  ('Unknown',       'MEDIUM',   'Unclassified port — identify application before creating rule.'),
    9999:  ('Alt-Web',       'MEDIUM',   'Alternate web port — identify the application.'),
    2114:  ('Unknown',       'MEDIUM',   'Unclassified port — investigate traffic pattern.'),
    1443:  ('Alt-HTTPS',     'MEDIUM',   'Non-standard HTTPS alternate port — verify application.'),
    4500:  ('IKE-NAT-T',     'MEDIUM',   'IKE NAT-traversal — IPSec VPN. Verify VPN endpoint.'),
    8801:  ('Zoom',          'LOW',      'Zoom video/audio — expected if Zoom is approved collaboration tool.'),
    # ── Application-specific ports ───────────────────────────────────────────
    17472: ('Tanium',        'LOW',      'Tanium endpoint management platform — expected traffic to Tanium Cloud (Azure). Port 17472 is Tanium default.'),
    27017: ('MongoDB',       'HIGH',     'MongoDB default port — database traffic to internet is a critical finding. Verify this is intentional cloud MongoDB (Atlas) and not a misconfigured instance.'),
    27016: ('MongoDB-Alt',   'HIGH',     'MongoDB alternate port — same concern as 27017. Verify destination is authorised MongoDB service.'),
    1883:  ('MQTT',          'MEDIUM',   'MQTT — IoT/OT messaging protocol (cleartext). Identify devices and verify destination broker is authorised.'),
    8883:  ('MQTT-TLS',      'MEDIUM',   'MQTT over TLS — IoT/OT messaging (encrypted). Identify devices and verify destination broker.'),
    5671:  ('AMQP-TLS',      'MEDIUM',   'AMQP over TLS — RabbitMQ / Azure Service Bus messaging. Verify destination is authorised messaging service.'),
    5672:  ('AMQP',          'MEDIUM',   'AMQP cleartext — RabbitMQ messaging. Prefer TLS on 5671.'),
    5223:  ('XMPP-SSL',      'MEDIUM',   'XMPP over SSL — Cisco Jabber/Webex client traffic. Allow if Jabber/Webex is approved.'),
    5229:  ('Google-FCM2',   'LOW',      'Google FCM alternate port — Android push notifications. Expected MDM/mobile traffic.'),
    9377:  ('CrowdStrike',   'LOW',      'CrowdStrike Falcon sensor cloud comms. Expected endpoint security traffic.'),
    7806:  ('New-Relic',     'LOW',      'New Relic infrastructure agent reporting. Expected APM/observability traffic.'),
    # ── SSH alternates — elevated risk ───────────────────────────────────────
    2222:  ('SSH-Alt',       'HIGH',     'SSH on alternate port — common evasion technique. Verify legitimate admin use and restrict to known jump hosts.'),
    10022: ('SSH-Alt',       'HIGH',     'SSH on alternate port — verify legitimate admin use.'),
    60022: ('SSH-Alt',       'HIGH',     'SSH on alternate port — verify legitimate admin use.'),
    # ── Mail submission ports ─────────────────────────────────────────────────
    587:   ('SMTP-Sub',      'MEDIUM',   'SMTP submission — should route through authorised mail gateway (O365/SendGrid). Verify destination.'),
    465:   ('SMTPS',         'MEDIUM',   'SMTP over TLS — verify routing through authorised mail gateway.'),
    990:   ('FTPS',          'MEDIUM',   'FTP over TLS — verify destination and business need.'),
    # ── Web alternates ────────────────────────────────────────────────────────
    8082:  ('Alt-HTTP',      'MEDIUM',   'Alternate HTTP port — identify the application.'),
    8083:  ('Alt-HTTP',      'MEDIUM',   'Alternate HTTP port — identify the application.'),
    8443:  ('Alt-HTTPS',     'MEDIUM',   'Alternate HTTPS port — identify the application.'),
    8022:  ('Alt-SSH-Web',   'MEDIUM',   'Non-standard port — identify application.'),
    9000:  ('SonarQube',     'MEDIUM',   'SonarQube / custom app port — verify destination.'),
    # ── Database / middleware ports ──────────────────────────────────────────
    11222: ('Couchbase',     'MEDIUM',   'Couchbase / Infinispan cache port — database traffic should not traverse perimeter.'),
    9999:  ('Alt-Web',       'MEDIUM',   'Alternate web port — identify the application.'),
    32137: ('IBM-MQ-Alt',    'MEDIUM',   'Possible IBM MQ / custom middleware port — verify destination.'),
    21000: ('Oracle-Alt',    'MEDIUM',   'Possible Oracle / custom application port — verify destination.'),
    # ── Kubernetes / container ports ─────────────────────────────────────────
    10255: ('Kubelet-RO',    'HIGH',     'Kubernetes kubelet read-only API — should never be internet-accessible. Verify source/dest.'),
    # ── 50000-range — often application-specific ─────────────────────────────
    50001: ('App-50001',     'MEDIUM',   'Application-specific port range (50001-50010) — likely custom middleware. Identify application.'),
    50002: ('App-50002',     'MEDIUM',   'Application-specific port range — identify application.'),
    50003: ('App-50003',     'MEDIUM',   'Application-specific port range — identify application.'),
    50004: ('App-50004',     'MEDIUM',   'Application-specific port range — identify application.'),
    50005: ('App-50005',     'MEDIUM',   'Application-specific port range — identify application.'),
    50006: ('App-50006',     'MEDIUM',   'Application-specific port range — identify application.'),
    50007: ('App-50007',     'MEDIUM',   'Application-specific port range — identify application.'),
    50008: ('App-50008',     'MEDIUM',   'Application-specific port range — identify application.'),
    50009: ('App-50009',     'MEDIUM',   'Application-specific port range — identify application.'),
    50010: ('App-50010',     'MEDIUM',   'Application-specific port range — identify application.'),
    55555: ('Alt-App',       'MEDIUM',   'Non-standard high port — identify application.'),
    # ── Other known ports ────────────────────────────────────────────────────
    3018:  ('Alt-App',       'MEDIUM',   'Non-standard port — identify application.'),
    2032:  ('Alt-App',       'MEDIUM',   'Non-standard port — identify application.'),
    1420:  ('Alt-App',       'MEDIUM',   'Non-standard port — identify application.'),
    1490:  ('Alt-App',       'MEDIUM',   'Non-standard port — identify application.'),
    7100:  ('Alt-App',       'MEDIUM',   'Non-standard port — identify application.'),
    7275:  ('Alt-App',       'MEDIUM',   'Non-standard port — identify application.'),
    8093:  ('Couchbase-Admin','MEDIUM',  'Couchbase admin REST API port — should not be internet-accessible.'),
    20024: ('Alt-App',       'MEDIUM',   'Non-standard port — check App-ID and destination.'),
    37560: ('Alt-App',       'MEDIUM',   'Non-standard port — check App-ID and destination.'),
    12321: ('Alt-App',       'MEDIUM',   'Non-standard port — check App-ID and destination.'),
    65534: ('Alt-App',       'MEDIUM',   'Non-standard high port (65534) — high session volume warrants investigation. Check App-ID.'),
    10546: ('Alt-App',       'MEDIUM',   'Non-standard port — identify application.'),
}

RISK_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

# Action mapping based on port risk + destination classification


def _ver_key(f):
    """Version-aware sort key: v3.9 < v3.14, v20260410 < v20260415."""
    import re as _r
    m = _r.search(r'_v(\d+)[._](\d+)', os.path.basename(f))
    if m: return (int(m.group(1)), int(m.group(2)))
    m2 = _r.search(r'_v(\d+)', os.path.basename(f))
    return (0, int(m2.group(1))) if m2 else (0, 0)


def find_latest(pattern):
    """Find most recent file matching glob pattern — handles vX.Y and vYYYYMMDD."""
    import glob as _glob, re as _re
    def _ver_key(f):
        m = _re.search(r'_v(\d+)\.(\d+)', os.path.basename(f))
        if m: return (int(m.group(1)), int(m.group(2)))
        m2 = _re.search(r'_v(\d+)', os.path.basename(f))
        if m2: return (0, int(m2.group(1)))
        return (0, 0)
    matches = _glob.glob(pattern)
    return max(matches, key=_ver_key) if matches else None


def get_canonical_location(row):
    """Prefer CANONICAL_LOCATION over LOCATION in ent_host_master rows."""
    return (str(row.get('CANONICAL_LOCATION','') or '').strip() or
            str(row.get('LOCATION','') or '').strip())


def derive_action(port_risk, dest_class, session_end, app, dest_enriched=None,
                  dominant_tier='LIGHT', app_taxonomy=None):
    """Return (action, reason) for this session combination.
    dest_enriched:  full lookup_dest() result — used for geo risk escalation.
    dominant_tier:  PROBE/LIGHT/NORMAL/ACTIVE/BULK — affects escalation logic.
    app_taxonomy:   fw_app_taxonomy dict — App-ID is checked FIRST before port risk.
    """
    risk = port_risk[1] if port_risk else 'MEDIUM'
    svc  = port_risk[0] if port_risk else 'Unknown'
    de   = dest_enriched or {}
    at   = app_taxonomy or {}

    # ── CPC-CORE-SERVICES match — existing enterprise policy covers this ────────
    # Check dest_enriched for CPC match
    cpc_svc = de.get('cpc_service', '')
    if cpc_svc and de.get('cpc_match') == 'Y':
        tier_sfx = f' [{dominant_tier}]' if dominant_tier not in ('LIGHT','NORMAL') else ''
        return ('ALLOW',
                f'Covered by CPC policy: {cpc_svc} — existing enterprise service group.{tier_sfx} '
                f'Validate rule aligns with CPC-CORE-SERVICES specification.')

    # ── App-ID first: PA positive identification overrides port-based logic ───
    # App-ID is ground truth — if PA fingerprinted it, trust that over port heuristics
    app_key = (app or '').lower().strip()
    app_rec = at.get(app_key, {})
    if app_rec:
        cat      = app_rec.get('category', '')
        app_act  = app_rec.get('action', '')
        app_desc = app_rec.get('description', app)
        app_note = app_rec.get('notes', '')

        # PA_UNIDENTIFIED: incomplete/unknown — escalate regardless of port
        if cat == 'PA_UNIDENTIFIED':
            cc = de.get('country_code', '')
            geo_note = f' Dest country: {cc}.' if cc else ''
            return ('REVIEW',
                    f'PA App-ID: {app} — {app_desc}.{geo_note} '
                    f'Investigate before creating rule — unidentified traffic on port {port_risk[0] if port_risk else "?"} '
                    f'could be custom protocol, misconfiguration, or evasion.{app_note and " "+app_note or ""}')

        # High-risk geo always overrides ALLOW from app taxonomy
        if de.get('is_high_risk') == 'Y' and app_act == 'ALLOW':
            cc  = de.get('country_code', '?')
            why = de.get('risk_reason', 'Sanctions/Watchlist')
            return ('REVIEW',
                    f'PA App-ID: {app} ({app_desc}) — normally ALLOW, but destination country '
                    f'{cc} is on the high-risk watchlist ({why}). Security review required.')

        # Trusted app taxonomy action
        if app_act in ('ALLOW', 'MONITOR', 'REVIEW', 'BLOCK'):
            tier_sfx = f' [{dominant_tier} traffic tier]' if dominant_tier not in ('LIGHT','NORMAL') else ''
            notes_sfx = f' {app_note}' if app_note else ''
            return (app_act,
                    f'PA App-ID: {app} — {app_desc}.{notes_sfx}{tier_sfx}')

    # ── Traffic tier modifiers ────────────────────────────────────────────────
    # PROBE sessions (PA app inspection / TCP handshake only) on high-risk ports
    # are escalated to REVIEW — they indicate the FW is probing, not real traffic.
    # BULK sessions on MONITOR-class rules get flagged for volume review.
    is_probe = dominant_tier == 'PROBE'
    is_bulk  = dominant_tier == 'BULK'
    tier_note = ''
    if is_probe:
        tier_note = ' [PROBE — PA app-inspect or handshake-only; verify if real traffic]'
    elif is_bulk:
        tier_note = ' [BULK — high packet volume; verify data transfer is authorised]'


    # ── Probe escalation: PROBE tier on risky ports → REVIEW ────────────────────
    if is_probe and risk in ('CRITICAL', 'HIGH'):
        cc  = de.get('country_code', '')
        geo = f' Dest: {cc}.' if cc else ''
        return ('REVIEW',
                f'{svc} — PROBE-tier session (PA app inspection or TCP handshake only).{geo} '
                f'Confirm this represents real traffic before creating allow rule.{tier_note}')

    # ── Geo: high-risk country → always REVIEW (overrides all else except CRITICAL) ─
    if de.get('is_high_risk') == 'Y' and risk != 'CRITICAL':
        cc  = de.get('country_code', 'Unknown')
        why = de.get('risk_reason', 'Sanctions/Watchlist country')
        return ('REVIEW',
                f'Destination country {cc} is on the high-risk watchlist ({why}). '
                f'Traffic to sanctioned/watchlisted destinations requires security '
                f'review and legal sign-off before any allow rule is created.')

    # ── BLOCK conditions ─────────────────────────────────────────────────────
    if risk == 'CRITICAL':
        geo_note = f' [Dest country: {de.get("country_code","?")}]' if de.get('country_code') else ''
        return ('BLOCK', f'Critical port ({svc}) — should never traverse the perimeter.{geo_note} Create explicit deny rule with logging.{tier_note}')

    # ── Supplement / well-known providers (Cisco Umbrella, Cloudflare etc) ──
    is_known_saas = dest_class in ('IAAS', 'SAAS', 'CLOUD', 'ISP', 'TRANSIT', 'OTHER') or de.get('svc_type') in ('DNS-SEC','CDN','PROXY')

    # Special: Cisco Umbrella DNS — ALLOW (it is the enterprise DNS resolver)
    if de.get('provider') == 'Cisco Umbrella' and de.get('svc_type') == 'DNS-SEC':
        return ('ALLOW', 'Cisco Umbrella DNS resolver — this is the enterprise DNS security service. Allow unconditionally on port 443/80 (DNScrypt).')

    # ── Provider-known traffic ────────────────────────────────────────────────
    if is_known_saas:
        prov = de.get('provider') or dest_class
        if risk == 'LOW':
            return ('ALLOW', f'{svc} to {prov} — expected traffic. Allow with application filter and logging.')
        if risk == 'MEDIUM':
            return ('MONITOR', f'{svc} to {prov} — allow with enhanced logging and anomaly alerting.')
        if risk == 'HIGH':
            return ('REVIEW', f'{svc} to {prov} — high-risk port to known provider. Security review required.')

    # RST from server
    if session_end == 'tcp-rst-from-server' and risk in ('LOW', 'MEDIUM'):
        return ('MONITOR', f'{svc} — server actively rejected. Verify if expected or misconfiguration.')

    # Unknown destinations
    if dest_class in ('UNKNOWN', 'EXTERNAL') and not de.get('svc_type'):
        asn = de.get('asn_display', '')
        asn_note = f' ASN: {asn}.' if asn else ''
        if risk in ('CRITICAL', 'HIGH'):
            return ('BLOCK', f'{svc} to unclassified external IP.{asn_note} Block until destination is verified and approved.')
        if risk == 'MEDIUM':
            return ('REVIEW', f'{svc} to unclassified destination.{asn_note} Security review required — identify the destination.')
        return ('MONITOR', f'{svc} — low-risk port to unclassified destination.{asn_note} Monitor for volume anomalies.')

    # Default by risk
    if risk == 'HIGH':
        return ('REVIEW', f'{svc} — high-risk port requires security sign-off and business justification.')
    if risk == 'MEDIUM':
        if is_bulk:
            return ('REVIEW', f'{svc} — BULK data transfer to unclassified destination. Volume review required.{tier_note}')
        return ('MONITOR', f'{svc} — allow provisionally with logging. Revisit if volume grows unexpectedly.{tier_note}')
    return ('ALLOW', f'{svc} — low-risk port to known destination. Standard allow rule with logging.{tier_note}')


# ── Helpers ───────────────────────────────────────────────────────────────────

def s(v):
    sv = str(v) if v is not None else ''
    return '' if sv in ('None', 'nan', 'NaN', '') else sv


def ip_to_int(ip_str):
    try:
        return int(ipaddress.ip_address(ip_str.split('/')[0]))
    except Exception:
        return None


def log(msg, verbose=False, force=False):
    if force or verbose:
        ts = datetime.now().strftime('%H:%M:%S')
        print(f'[{ts}] {msg}', file=sys.stderr)


def compress_blob(obj):
    raw = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    gz  = gzip.compress(raw, compresslevel=9)
    return base64.b64encode(gz).decode('ascii')


def collapse_monitor_to_src24(rule_list, verbose=False):
    """Collapse MONITOR-action rules at (src_ip, dest_ip, port) granularity
    to (src24, dest_ip, port) granularity. Other actions (BLOCK/REVIEW/ALLOW)
    keep per-host precision because rule-authoring decisions at those risk
    levels typically care about which specific host is involved.

    The representative collapsed row carries:
      • src_ip = '' (explicitly blanked — use src24 as the source address)
      • collapsed_n — how many individual hosts rolled up
      • collapsed_hosts — list of {ip, hostname, os, app, env, count, pkts}
      • count, pkts_out, pkts_in, traffic_tiers — summed across hosts
      • apps, end_reasons, devices — unioned across hosts
    """
    monitor_rules = [r for r in rule_list if r.get('action') == 'MONITOR']
    other_rules   = [r for r in rule_list if r.get('action') != 'MONITOR']

    if not monitor_rules:
        return rule_list

    collapsed = {}
    for r in monitor_rules:
        key = (r.get('src24', ''), r.get('dest_ip', ''), r.get('dest_port', 0))
        host_entry = {
            'ip':       r.get('src_ip', ''),
            'hostname': r.get('hostname', ''),
            'fqdn':     r.get('fqdn', ''),
            'os':       r.get('src_os', ''),
            'app':      r.get('src_app_acronym') or r.get('src_app', ''),
            'apm':      (r.get('src_apm_ids') or '').split('|')[0].strip(),
            'env':      r.get('src_env', ''),
            'bu':       r.get('src_bu', ''),
            'site':     r.get('src_site_name') or r.get('src_dc_name', ''),
            'count':    r.get('count', 0),
            'pkts':     (r.get('pkts_out', 0) or 0) + (r.get('pkts_in', 0) or 0),
        }
        if key not in collapsed:
            # Seed the collapsed row from this rule — first host wins as the
            # representative row, then we aggregate/union everything else into it.
            c = dict(r)                           # shallow copy
            c['collapsed_hosts'] = [host_entry]
            c['collapsed_n']     = 1
            # Normalize union-set fields into lists we can grow
            c['apps']        = list(r.get('apps') or [])
            c['end_reasons'] = list(r.get('end_reasons') or [])
            c['devices']     = list(r.get('devices') or [])
            c['traffic_tiers'] = dict(r.get('traffic_tiers') or {})
            collapsed[key] = c
            continue

        c = collapsed[key]
        c['collapsed_hosts'].append(host_entry)
        c['collapsed_n'] += 1
        c['count']    += r.get('count', 0)
        c['pkts_out'] += r.get('pkts_out', 0) or 0
        c['pkts_in']  += r.get('pkts_in', 0)  or 0
        for a in (r.get('apps') or []):
            if a not in c['apps']:        c['apps'].append(a)
        for e in (r.get('end_reasons') or []):
            if e not in c['end_reasons']: c['end_reasons'].append(e)
        for d in (r.get('devices') or []):
            if d not in c['devices']:     c['devices'].append(d)
        for t, v in (r.get('traffic_tiers') or {}).items():
            c['traffic_tiers'][t] = c['traffic_tiers'].get(t, 0) + v

    # Post-process: clean up representative row
    for c in collapsed.values():
        n = c['collapsed_n']
        if n > 1:
            # Blank per-host fields that no longer apply — the src24 is now
            # the source address, and individual host detail lives in
            # collapsed_hosts.
            c['src_ip']          = ''
            c['hostname']        = ''
            c['fqdn']            = ''
            c['src_os']          = ''
            c['src_os_detail']   = ''
            c['src_app']         = ''
            c['src_app_acronym'] = ''
            c['src_apm_ids']     = ''
            c['src_server_class']= ''
            c['src_site_code']   = ''
            # Reason gets a notation so it's obvious in the UI
            c['reason']          = f'[{n} hosts in /24] ' + (c.get('reason') or '')
        c['total_pkts'] = (c.get('pkts_out', 0) or 0) + (c.get('pkts_in', 0) or 0)
        c['pkts_avg']   = round(c['total_pkts'] / max(c.get('count', 1), 1))
        # Recompute dominant tier across all collapsed hosts
        if c.get('traffic_tiers'):
            c['dominant_tier'] = max(c['traffic_tiers'].items(),
                                     key=lambda x: x[1])[0]
        # Sort apps/end_reasons/devices for stable output
        c['apps']        = sorted(c['apps'])
        c['end_reasons'] = sorted(c['end_reasons'])
        c['devices']     = sorted(c['devices'])
        # Sort collapsed_hosts by session count desc — most-active host first
        c['collapsed_hosts'].sort(key=lambda h: -h.get('count', 0))

    result = other_rules + list(collapsed.values())
    # Preserve the original sort order: risk, then count desc
    RISK_ORDER_LOCAL = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    result.sort(key=lambda x: (RISK_ORDER_LOCAL.get(x.get('risk'), 99),
                               -x.get('count', 0)))

    if verbose:
        n_in  = len(monitor_rules)
        n_out = len(collapsed)
        log(f'  MONITOR collapse: {n_in:,} per-host rules → {n_out:,} per-/24 rules '
            f'({(1 - n_out / max(n_in, 1)) * 100:.0f}% reduction)',
            verbose, force=True)

    return result


def _is_empty(v):
    """Fields we want to drop from the wire payload — empty string, empty list/dict,
    None. We keep 0, False, 'N' because those are meaningful."""
    if v is None:
        return True
    if isinstance(v, str) and v == '':
        return True
    if isinstance(v, (list, dict, set, tuple)) and len(v) == 0:
        return True
    return False


def strip_empty(d):
    """Return a copy of dict `d` with empty-valued fields removed."""
    return {k: v for k, v in d.items() if not _is_empty(v)}


def build_lookup_tables(rule_list):
    """Extract common ipam/dest blobs into shared lookup tables keyed by
    src24 / dest_ip respectively. Each rule then carries only the key, not
    the whole blob. Also precomputes a lowercase search haystack per rule.

    Returns (compact_rules, ipam_by_src24, dest_by_ip).
    """
    ipam_by_src24 = {}
    dest_by_ip    = {}

    # First pass — build the lookup tables using the first observed blob per key.
    # IMPORTANT: we add EVERY src24 we encounter, even if its IPAM blob is empty.
    # Subnets with no IPAM entry are not noise — they are unregistered infrastructure
    # and the most interesting rules from a security standpoint. We write a sentinel
    # {'cidr': s24, 'unregistered': True} so the client can flag them clearly.
    for r in rule_list:
        s24 = r.get('src24', '')
        dip = r.get('dest_ip', '')
        if s24 and s24 not in ipam_by_src24:
            ip_blob = r.get('ipam') or {}
            if ip_blob:
                ipam_by_src24[s24] = strip_empty(ip_blob)
            else:
                # Unregistered subnet — write a sentinel so the UI can flag it
                ipam_by_src24[s24] = {'cidr': s24, 'unregistered': True}
        if dip and dip not in dest_by_ip:
            d_blob = r.get('dest') or {}
            if d_blob:
                dest_by_ip[dip] = strip_empty(d_blob)

    # Second pass — build compact rules, precompute haystack, drop empty fields.
    compact = []
    for r in rule_list:
        # Search haystack — matches current client-side search semantics:
        #   src_ip || src24, hostname, dest_ip, dest_port, svc, action,
        #   dest.provider, apps
        # For collapsed MONITOR rules, also include individual hosts' IPs
        # and hostnames so the user can search for specific hosts and find
        # the collapsed row they rolled up into.
        dest_blob = dest_by_ip.get(r.get('dest_ip', ''), {})
        hay_parts = [
            r.get('src_ip', '') or r.get('src24', ''),
            r.get('hostname', ''),
            r.get('dest_ip', ''),
            str(r.get('dest_port', '')),
            r.get('svc', ''),
            r.get('action', ''),
            dest_blob.get('provider', ''),
            dest_blob.get('svc_type', ''),    # CDN / EC2 / CLOUD-INFRA etc.
            dest_blob.get('svc_label', ''),   # "Content Delivery Network" etc.
            dest_blob.get('ds_class', ''),    # IAAS / SAAS / CLOUD / OTHER
            dest_blob.get('service', ''),     # specific named service range
            'unregistered' if ipam_by_src24.get(r.get('src24',''), {}).get('unregistered') else '',
            ' '.join(r.get('apps', []) or []),
        ]
        # Collapsed-host search terms
        for h in (r.get('collapsed_hosts') or []):
            if h.get('ip'):       hay_parts.append(h['ip'])
            if h.get('hostname'): hay_parts.append(h['hostname'])
            if h.get('app'):      hay_parts.append(h['app'])
        hay = ' '.join(p for p in hay_parts if p).lower()

        compact_r = dict(r)
        # Remove dedup'd fields — client resolves via D.ipam_by_src24 / D.dest_by_ip
        compact_r.pop('ipam', None)
        compact_r.pop('dest', None)
        compact_r['_hay'] = hay
        compact.append(strip_empty(compact_r))

    return compact, ipam_by_src24, dest_by_ip


# ── IPAM loader ───────────────────────────────────────────────────────────────

def load_ipam(dataset_dir, verbose):
    """Load all_IP_networks (single source of truth — v4.0).

    v1.3: all_IP_networks_v3.14+ is the sole IPAM source.
    cidr_24 is permanently abolished — no fallback.
    Returns:
        ipam_lpm  — LPM structure for binary-search lookup
        ipam_c24  — dict keyed by /24 CIDR for rollup context
    """
    import bisect

    def _row_to_info(row):
        return {
            'cidr':         row.get('CIDR','').strip(),
            'location':     s(row.get('Location') or get_canonical_location(row)),
            'site':         s(row.get('CANONICAL_SITE_ID') or row.get('SITE_DC_NAME') or row.get('PRIMARY_SITE','')),
            'site_class':   s(row.get('SITE_CLASS','')),
            'facility':     s(row.get('FACILITY_TYPE','')),
            'net_type':     s(row.get('NET_TYPE','')),
            'owner':        s(row.get('OWNER','')),
            'bu':           s(row.get('BU','')),
            'division':     s(row.get('DIVISION','')),
            'routing_dom':  s(row.get('ROUTING_DOMAIN','')),
            'pci':          s(row.get('PCI_DESIGNATION','')),
            'risk':         s(row.get('RISK_TIER','')),
            'heritage':     s(row.get('HERITAGE','')),
            'os':           s(row.get('OS_DOMINANT','')),
            'servers':      s(row.get('SERVER_COUNT','')),
            'apps':         s(row.get('APP_COUNT','')),
            'app_acronyms': s(row.get('APP_ACRONYMS','')),
            'apm_ids':      s(row.get('APM_IDS','')),
            'prod_apps':    s(row.get('PROD_APP_COUNT','')),
            'app_envs':     s(row.get('APP_ENV_TYPES','')),
            'pci_mixed':    s(row.get('APP_PCI_MIXED','')),
            'ipam_app_id':  s(row.get('IPAM_APP_ID','')),
            'compliance':   s(row.get('COMPLIANCE','')),
            'cpc_svc':      s(row.get('CPC_SERVICES','')),
            'sox':          s(row.get('SOX_CRITICAL','')),
            'hitrust':      s(row.get('HITRUST','')),
            'contested':    s(row.get('CONTESTED_BLOCK','')),
            'nat_type':     s(row.get('NAT_TYPE','')),
            'nat_public':   s(row.get('NAT_PUBLIC_IP','')),
            'fw_policy':    s(row.get('FW_POLICY','')),
            'store_num':    s(row.get('STORE_NUMBER','')),
            'store_type':   s(row.get('STORE_COMM_TYPE','')),
            'cloud':        s(row.get('CLOUD_PLATFORM','')),
            'infra_role':   s(row.get('INFRA_ROLE','')),
            'cities':       s(row.get('CITIES','')),
            'states':       s(row.get('STATES','')),
        }

    # ── Try all_IP_networks first ─────────────────────────────────────────────
    all_ip_pattern = os.path.join(dataset_dir, 'all_IP_networks_v*.csv')
    all_ip_matches = sorted(glob.glob(all_ip_pattern), key=_ver_key)

    lpm_raw  = []   # (prefixlen, net_int, bcast_int, info)
    ipam_c24 = {}   # /24 CIDR → info (for rollup context)

    if all_ip_matches:
        path = all_ip_matches[-1]
        log(f'  Loading all_IP_networks: {os.path.basename(path)}', verbose, force=True)
        count = 0
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(l for l in f if not l.startswith('#'))
            for row in reader:
                cidr = row.get('CIDR','').strip()
                if not cidr or ':' in cidr:  # skip IPv6
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    info = _row_to_info(row)
                    lpm_raw.append((net.prefixlen,
                                    int(net.network_address),
                                    int(net.broadcast_address),
                                    info))
                    # Also index /24s for rollup
                    if net.prefixlen == 24:
                        ipam_c24[cidr] = info
                    count += 1
                except Exception:
                    pass
        log(f'  all_IP_networks: {count:,} records loaded', verbose, force=True)
    else:
        log('  ERROR: all_IP_networks_v*.csv not found — source enrichment disabled.', force=True)
        log(f'  Searched: {os.path.join(dataset_dir, "all_IP_networks_v*.csv")}', force=True)
        log('  NOTE: cidr_24 is abolished (v4.0). Use all_IP_networks_v3.14+.', force=True)
        return [], {}

    # Build binary-search LPM structure (group by prefix length)
    from collections import defaultdict as _dd
    by_prefix = _dd(list)
    for pl, ni, bi, info in lpm_raw:
        by_prefix[pl].append((ni, bi, info))
    for pl in by_prefix:
        by_prefix[pl].sort(key=lambda x: x[0])
    prefix_lengths = sorted(by_prefix.keys(), reverse=True)
    key_arrays = {pl: [e[0] for e in by_prefix[pl]] for pl in prefix_lengths}

    ipam_lpm = {'by_prefix': dict(by_prefix),
                'prefix_lengths': prefix_lengths,
                'key_arrays': key_arrays}

    # Merge app_subnet_index
    app_idx = load_app_subnet_index(dataset_dir, verbose)
    for cidr, app_data in app_idx.items():
        if cidr in ipam_c24:
            for k, v in app_data.items():
                if not ipam_c24[cidr].get(k) and v:
                    ipam_c24[cidr][k] = v

    total = sum(len(v) for v in by_prefix.values())
    log(f'  IPAM LPM ready: {total:,} networks across {len(prefix_lengths)} prefix lengths', verbose, force=True)
    return ipam_lpm, ipam_c24


def load_app_subnet_index(dataset_dir, verbose):
    """Load app_subnet_index_v*.csv — per-/24 app metadata.
    Keyed by /24 parent CIDR. Merges app context into IPAM lookup table.
    keyed by /24 parent CIDR for app context lookup.
    """
    pattern = os.path.join(dataset_dir, 'app_subnet_index_v*.csv')
    matches = sorted(glob.glob(pattern), key=_ver_key)
    if not matches:
        log('  app_subnet_index: not found — app/APM context on source subnets disabled', verbose)
        return {}
    path = matches[-1]
    log(f'  Loading app_subnet_index: {os.path.basename(path)}', verbose, force=True)
    idx = {}
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(l for l in f if not l.startswith('#'))
        for row in reader:
            cidr = row.get('CIDR', row.get('CIDR_24', '')).strip()  # CIDR is primary key
            if not cidr:
                continue
            idx[cidr] = {
                'apps':         s(row.get('APP_COUNT', '')),
                'app_acronyms': s(row.get('APP_ACRONYMS', '')),
                'apm_ids':      s(row.get('APM_IDS', '')),
                'app_names':    s(row.get('APP_NAMES', '')),
                'prod_apps':    s(row.get('PROD_APP_COUNT', '')),
                'pci':          s(row.get('PCI_DESIGNATION', '')),
                'risk':         s(row.get('RISK_TIER', '')),
                'sox':          s(row.get('SOX_CRITICAL', '')),
                'hitrust':      s(row.get('HITRUST', '')),
                'heritage':     s(row.get('HERITAGE', '')),
                'cpc_svc':      s(row.get('CPC_SERVICES', '')),
                'app_envs':     s(row.get('APP_ENV_TYPES', '')),
                'ipam_app_id':  s(row.get('IPAM_APP_ID', '')),
                'pci_mixed':    s(row.get('APP_PCI_MIXED', '')),
                'os_dominant':  s(row.get('OS_DOMINANT', '')),
                'servers':      s(row.get('SERVER_COUNT', '')),
            }
    log(f'  app_subnet_index: {len(idx):,} /24 records loaded', verbose, force=True)
    return idx


def lookup_src_ipam(src_ip, ipam):
    """LPM lookup: find the most-specific matching network for src_ip.
    ipam: dict with 'by_prefix', 'prefix_lengths', 'key_arrays'
          OR legacy dict keyed by /24 CIDR (backwards compatible).
    """
    if not src_ip or src_ip == 'any':
        return {}
    if not ipam:  # empty list returned by load_ipam when no IPAM data found
        return {}

    # Legacy flat dict — walk /32→/8 for correct LPM
    # (replaces hardcoded /24 parent lookup; handles /26 retail blocks,
    #  /21 DC aggregates, etc.)
    if isinstance(ipam, dict) and 'by_prefix' not in ipam:
        try:
            ip_int = int(ipaddress.ip_address(src_ip))
            for pl in range(32, 7, -1):
                mask    = ((1 << 32) - 1) ^ ((1 << (32 - pl)) - 1)
                net_int = ip_int & mask
                cidr_key = (f'{(net_int>>24)&0xff}.{(net_int>>16)&0xff}.'
                            f'{(net_int>>8)&0xff}.{net_int&0xff}/{pl}')
                if cidr_key in ipam:
                    return ipam[cidr_key]
            return {}
        except Exception:
            return {}

    # New LPM format
    try:
        parts   = src_ip.split('.')
        ip_int  = (int(parts[0])<<24)|(int(parts[1])<<16)|(int(parts[2])<<8)|int(parts[3])
    except Exception:
        try:
            ip_int = int(ipaddress.ip_address(src_ip))
        except Exception:
            return {}

    import bisect
    by_prefix     = ipam.get('by_prefix', {})
    prefix_lengths = ipam.get('prefix_lengths', [])
    key_arrays    = ipam.get('key_arrays', {})

    for pl in prefix_lengths:
        group = by_prefix.get(pl)
        if not group:
            continue
        keys = key_arrays.get(pl, [e[0] for e in group])
        idx  = bisect.bisect_right(keys, ip_int) - 1
        if idx >= 0:
            net_int, bcast_int, info = group[idx]
            if net_int <= ip_int <= bcast_int:
                return info
    return {}



def load_ent(dataset_dir, verbose, ent_master_path=None):
    """
    Load enterprise host records for per-IP enrichment.

    Supports two source formats:
      1. ent_host_master.csv  — new unified master (preferred, --ent-master)
      2. ent-ipdataset-*.csv  — legacy format (auto-discovered in dataset_dir)

    Returns IP-keyed dict with hostname, app, OS, BU, CSNA, APM IDs, heritage,
    PARSED_* fields from parse_hostname, and data source flags.
    """
    # ── Try parse_hostname module (optional — enriches every hostname) ────────
    _parse_hostname = None
    try:
        import importlib.util, sys as _sys
        _spec = importlib.util.spec_from_file_location(
            'parse_hostname',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'parse_hostname.py'))
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        _parse_hostname = _mod.parse_hostname
        log('  parse_hostname: loaded', verbose)
    except Exception as e:
        log(f'  parse_hostname: not available ({e}) — site/env from hostname disabled', verbose)

    def _enrich_hostname(hostname, fqdn=''):
        """Call parse_hostname if available, else return empty dict."""
        if not _parse_hostname or not hostname:
            return {}
        try:
            return _parse_hostname(hostname, fqdn)
        except Exception:
            return {}

    ent = {}

    # ── Mode 1: ent_host_master.csv (new unified schema) ─────────────────────
    if ent_master_path and os.path.isfile(ent_master_path):
        log(f'  Loading ENT master: {os.path.basename(ent_master_path)}', verbose, force=True)
        enc = 'utf-8'
        try:
            open(ent_master_path, encoding='utf-8').read(1024)
        except UnicodeDecodeError:
            enc = 'latin-1'
        with open(ent_master_path, newline='', encoding=enc, errors='replace') as f:
            reader = csv.DictReader(l for l in f if not l.startswith('#'))
            for row in reader:
                ip_str = s(row.get('IP_ADDRESS', '') or row.get('IP', ''))
                if not ip_str or ip_str in ('nan', 'None', ''):
                    continue
                hostname = s(row.get('SERVER_NAME', ''))
                fqdn     = s(row.get('FQDN', ''))
                parsed   = _enrich_hostname(hostname, fqdn)
                ent[ip_str] = {
                    'hostname':    hostname,
                    'fqdn':        fqdn,
                    'app':         s(row.get('APP_NAMES',       '') or row.get('APPLICATION',''))[:100],
                    'app_acronym': s(row.get('APP_ACRONYMS',    '') or row.get('PRIMARY_ACRONYM','')),
                    'os':          s(row.get('OS_GROUP',        '') or row.get('OS_NORMALIZED','')),
                    'os_detail':   s(row.get('OS_VERSION',      '')),
                    'location':    s(get_canonical_location(row) or row.get('SERVER_SITE','')),
                    'env':         s(row.get('PRIMARY_ENV',     '') or row.get('APP_ENVIRONMENTS','')),
                    'pci_ent':     s(row.get('PCI',             '') or row.get('PCI_DESIGNATION','')),
                    'risk_ent':    s(row.get('RISK_TIER',       '')),
                    'csna_path':   s(row.get('CSNA_HOSTGROUP_PATH', '')),
                    'apm_ids':     s(row.get('APM_IDS',         '') or row.get('PRIMARY_APM_ID','')),
                    'bu':          s(row.get('BUSINESS_UNIT',   '') or row.get('ITPM_BUSINESS_UNIT','')),
                    'heritage':    s(row.get('HERITAGE',        '')),
                    'server_class':s(row.get('SERVER_CLASS',    '')),
                    'is_virtual':  s(row.get('IS_VIRTUAL',      '')),
                    'op_status':   s(row.get('OPERATIONAL_STATUS','')),
                    'active_status':s(row.get('ACTIVE_STATUS',  '')),
                    'in_snow':     s(row.get('IN_SNOW',         '')),
                    'in_qualys':   s(row.get('IN_QUALYS',       '')),
                    'in_wiz':      s(row.get('IN_WIZ',          '')),
                    'data_sources':s(row.get('DATA_SOURCES',    '')),
                    'secondary_ip':s(row.get('SECONDARY_IP', '')),
                    'ip':          s(row.get('IP',           '')),
                    'routing_dom': s(row.get('ROUTING_DOMAIN',  '')),
                    'facility':    s(row.get('FACILITY_TYPE',   '')),
                    'fw_policy':   s(row.get('FW_POLICY',       '')),
                    'cidr_24':     s(row.get('CIDR_24',         '')),  # legacy field — kept for backward compat
                    # parse_hostname fields
                    'parsed_site_code': parsed.get('PARSED_SITE_CODE', ''),
                    'parsed_dc_name':   parsed.get('PARSED_DC_NAME',   ''),
                    'parsed_site_name': parsed.get('PARSED_SITE_NAME', ''),
                    'parsed_env':       parsed.get('PARSED_ENV',       ''),
                    'parsed_os_hint':   parsed.get('PARSED_OS_HINT',   ''),
                    'parsed_heritage':  parsed.get('PARSED_HERITAGE',  ''),
                    'parsed_scheme':    parsed.get('PARSED_SCHEME',    ''),
                    'parsed_confidence':parsed.get('PARSED_CONFIDENCE',''),
                }
        log(f'  ENT host records (master): {len(ent):,}', verbose, force=True)

    # ── Mode 2: legacy ent-ipdataset-*.csv ────────────────────────────────────
    if not ent:
        pattern = os.path.join(dataset_dir, 'ent-ipdataset-*.csv')
        matches = sorted(glob.glob(pattern), key=_ver_key)
        if not matches:
            log(f'  WARNING: No ENT host file found — hostname lookup disabled', force=True)
            return {}
        for path in matches:
            log(f'  Loading ENT (legacy): {os.path.basename(path)}', verbose, force=True)
            with open(path, newline='', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(l for l in f if not l.startswith('#'))
                for row in reader:
                    ip_str = s(row.get('IP', ''))
                    if not ip_str or ip_str.startswith('#'):
                        continue
                    hostname = s(row.get('SERVER_NAME', ''))
                    parsed   = _enrich_hostname(hostname, s(row.get('FQDN', '')))
                    ent[ip_str] = {
                        'hostname':    hostname,
                        'fqdn':        s(row.get('FQDN', '')),
                        'app':         s(row.get('APPLICATION', ''))[:100],
                        'app_acronym': '',
                        'os':          s(row.get('OS_NORMALIZED', '') or row.get('OS', '')),
                        'os_detail':   '',
                        'location':    s(get_canonical_location(row)),
                        'env':         s(row.get('ENVIRONMENT', '')),
                        'pci_ent':     s(row.get('PCI', '')),
                        'risk_ent':    s(row.get('RISK_TIER', '')),
                        'csna_path':   s(row.get('CSNA_HOSTGROUP_PATH', '')),
                        'apm_ids':     s(row.get('APM_IDS', '')),
                        'bu':          s(row.get('BU', '')),
                        'heritage':    s(row.get('HERITAGE', '')),
                        'server_class': '',
                        'in_snow': '', 'in_qualys': '', 'in_wiz': '',
                        'data_sources': '',
                        'parsed_site_code': parsed.get('PARSED_SITE_CODE', ''),
                        'parsed_dc_name':   parsed.get('PARSED_DC_NAME',   ''),
                        'parsed_site_name': parsed.get('PARSED_SITE_NAME', ''),
                        'parsed_env':       parsed.get('PARSED_ENV',       ''),
                        'parsed_os_hint':   parsed.get('PARSED_OS_HINT',   ''),
                        'parsed_heritage':  parsed.get('PARSED_HERITAGE',  ''),
                        'parsed_scheme':    parsed.get('PARSED_SCHEME',    ''),
                        'parsed_confidence':parsed.get('PARSED_CONFIDENCE',''),
                    }
        log(f'  ENT host records (legacy): {len(ent):,}', verbose, force=True)

    # Build secondary IP index — maps SECONDARY_IP and IP field to same record
    # Doubles ENT match rate for hosts with multiple IPs/VIPs
    secondary_index = {}
    for ip, rec in list(ent.items()):
        sec = rec.get('secondary_ip', '').strip()
        alt = rec.get('ip', '').strip()
        if sec and sec not in ent and sec not in ('', 'N/A', '-'):
            secondary_index[sec] = rec
        if alt and alt not in ent and alt != ip:
            secondary_index[alt] = rec
    ent.update(secondary_index)
    if secondary_index:
        log(f'  ENT secondary IPs added: {len(secondary_index):,} additional mappings', verbose, force=True)
    return ent


# ── Well-known supplemental IP table (fills gaps in ip_dataset registry) ──────
# IPs/CIDRs that appear heavily in CVS traffic but aren't in any registered dataset.
WELL_KNOWN_SUPPLEMENT = [
    # Cisco Umbrella DNS
    ('208.67.222.0/24', 'Cisco Umbrella', 'DNS-Security', 'global', 'SAAS', 'DNS-SEC',  'Cisco Umbrella DNS Resolver'),
    ('208.67.220.0/24', 'Cisco Umbrella', 'DNS-Security', 'global', 'SAAS', 'DNS-SEC',  'Cisco Umbrella DNS Resolver'),
    ('208.67.222.222/32','Cisco Umbrella','DNS-Security', 'global', 'SAAS', 'DNS-SEC',  'Cisco Umbrella Primary DNS'),
    ('208.67.220.220/32','Cisco Umbrella','DNS-Security', 'global', 'SAAS', 'DNS-SEC',  'Cisco Umbrella Secondary DNS'),
    # Cloudflare
    ('104.16.0.0/12', 'Cloudflare',    'CDN',          'global', 'IAAS', 'CDN',       'Cloudflare CDN / 1.1.1.1 DNS'),
    ('172.64.0.0/13', 'Cloudflare',    'CDN',          'global', 'IAAS', 'CDN',       'Cloudflare Network'),
    ('162.158.0.0/15','Cloudflare',    'CDN',          'global', 'IAAS', 'CDN',       'Cloudflare Network'),
    ('1.1.1.1/32',    'Cloudflare',    'DNS',          'global', 'IAAS', 'DNS',       'Cloudflare Public DNS'),
    # Cisco DNScrypt / Umbrella
    ('67.215.64.0/18','Cisco Umbrella','DNS-Security', 'global', 'SAAS', 'DNS-SEC',   'Cisco Umbrella'),
    # Google Workspace / Meet
    ('142.250.0.0/15','Google',        'Google-Workspace','us',  'IAAS', 'CLOUD-INFRA','Google Workspace / Meet / Drive'),
    ('172.253.0.0/16','Google',        'Google-Workspace','us',  'IAAS', 'CLOUD-INFRA','Google Frontend Network'),
    ('192.178.0.0/15','Google',        'Google-Workspace','us',  'IAAS', 'CLOUD-INFRA','Google Network'),
    # Apple
    ('17.0.0.0/8',    'Apple',         'Apple-Services','global','SAAS', 'CDN',       'Apple Push Notification / iCloud'),
    # Akamai
    ('23.0.0.0/8',    'Akamai',        'CDN',          'global', 'IAAS', 'CDN',       'Akamai CDN'),
    # Zscaler (confirmed from traffic: src=Zscaler app hitting 209.177.x)
    ('136.226.0.0/16', 'Zscaler',       'Proxy',        'global', 'SAAS', 'PROXY',     'Zscaler Cloud Proxy'),
    ('209.177.0.0/16', 'Zscaler',       'Proxy',        'global', 'SAAS', 'PROXY',     'Zscaler Traffic Forwarding'),
    # Dynatrace SaaS monitoring (136.22.x.x confirmed from DYNATRACE-CVS app)
    ('136.22.0.0/16',  'Dynatrace',     'APM-SaaS',     'global', 'SAAS', 'MONITORING','Dynatrace SaaS Monitoring'),
    # Meta / Facebook
    ('157.240.0.0/16', 'Meta',          'Facebook',     'global', 'SAAS', 'SOCIAL',    'Meta/Facebook Services'),
    ('157.240.11.0/24','Meta',          'Facebook',     'global', 'SAAS', 'SOCIAL',    'Meta/Facebook Services'),
    ('57.144.0.0/14',  'Meta',          'Facebook',     'global', 'SAAS', 'SOCIAL',    'Meta/Facebook CDN'),
    # Microsoft 365 / Teams / Intune
    ('150.171.0.0/16', 'Microsoft',     'M365-Teams',   'global', 'SAAS', 'PRODUCTIVITY','Microsoft 365 / Teams / Intune'),
    ('150.171.22.0/24','Microsoft',     'M365-Teams',   'global', 'SAAS', 'PRODUCTIVITY','Microsoft M365 Traffic'),
    # Meta/Facebook additional ranges
    ('31.13.64.0/18',  'Meta',          'Facebook',     'global', 'SAAS', 'SOCIAL',    'Meta/Facebook Services'),
    ('185.60.216.0/22','Meta',          'Facebook',     'global', 'SAAS', 'SOCIAL',    'Meta/Facebook Services'),
    ('66.220.144.0/20','Meta',          'Facebook',     'global', 'SAAS', 'SOCIAL',    'Meta/Facebook CDN'),
    # Fastly additional ranges
    ('160.79.104.0/22','Fastly',        'CDN',          'global', 'IAAS', 'CDN',       'Fastly CDN'),
    # Cloudflare additional ranges
    ('141.193.212.0/22','Cloudflare',   'CDN',          'global', 'IAAS', 'CDN',       'Cloudflare Network'),
    # Limelight / Edgio CDN
    ('204.99.16.0/20', 'Limelight/Edgio','CDN',         'global', 'IAAS', 'CDN',       'Limelight/Edgio CDN'),
    # Automattic / WordPress.com
    ('192.0.72.0/22',  'Automattic',    'WordPress',    'global', 'SAAS', 'HOSTING',   'Automattic/WordPress.com Hosting'),
    # Shopify
    ('199.60.103.0/24','Shopify',       'eCommerce',    'global', 'SAAS', 'ECOMMERCE', 'Shopify eCommerce'),
    # AT&T (12.x.x.x) — corporate internet/MPLS
    ('12.0.0.0/8',     'AT&T',          'ISP-Transit',  'us',     'IAAS', 'TRANSIT',   'AT&T IP Services / corporate internet'),
    # Edgecast / Verizon Media CDN
    ('185.146.172.0/22','Edgecast/Verizon','CDN',       'global', 'IAAS', 'CDN',       'Edgecast/Verizon Media CDN'),
    # Russian ISPs / RuNet (common in corporate environments with CW offshore)
    ('77.37.64.0/18',  'Enforta/RuNet', 'ISP-Transit',  'ru',     'IAAS', 'TRANSIT',   'Enforta Russian ISP'),
]

def _build_supplement():
    supp = []
    for cidr, provider, service, region, ds_class, svc_type, desc in WELL_KNOWN_SUPPLEMENT:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            supp.append((net, provider, service, region, ds_class, svc_type, desc))
        except Exception:
            pass
    supp.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return supp

_SUPPLEMENT = _build_supplement()


# ── GeoIP loader ──────────────────────────────────────────────────────────────

def build_cpc_index(dataset_dir, verbose):
    """Load CPC-CORE-SERVICES — maps service CIDRs to named enterprise services."""
    import bisect as _bisect
    from collections import defaultdict as _dd
    pattern = os.path.join(dataset_dir, 'ent-ipdataset-CPC-CORE-SERVICES*.csv')
    matches = sorted(glob.glob(pattern), key=_ver_key)
    if not matches:
        log('  CPC-CORE-SERVICES: not found — CPC policy matching disabled', verbose)
        return {}
    path = matches[-1]
    log(f'  Loading CPC-CORE-SERVICES: {os.path.basename(path)}', verbose, force=True)
    raw = []
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        for row in csv.DictReader(l for l in f if not l.startswith('#')):
            cidr = s(row.get('IP_NETWORK', '')).strip()
            if not cidr or ':' in cidr: continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                raw.append((net.prefixlen, int(net.network_address),
                            int(net.broadcast_address), {
                    'cpc_service':  s(row.get('SERVICE', '')),
                    'cpc_provider': s(row.get('PROVIDER', '')),
                    'cpc_heritage': s(row.get('HERITAGE', '')),
                    'cpc_ports':    s(row.get('PORTS', '')),
                    'cpc_desc':     s(row.get('DESCRIPTION', '')),
                    'cpc_cidr':     cidr,
                }))
            except Exception: pass
    from collections import defaultdict as _dd2
    by_prefix = _dd2(list)
    for pl, ni, bi, info in raw:
        by_prefix[pl].append((ni, bi, info))
    for pl in by_prefix:
        by_prefix[pl].sort(key=lambda x: x[0])
    prefix_lengths = sorted(by_prefix.keys(), reverse=True)
    key_arrays = {pl: [e[0] for e in by_prefix[pl]] for pl in prefix_lengths}
    total = sum(len(v) for v in by_prefix.values())
    log(f'  CPC-CORE-SERVICES: {total:,} service CIDRs', verbose, force=True)
    return {'by_prefix': dict(by_prefix), 'prefix_lengths': prefix_lengths,
            'key_arrays': key_arrays}


def cpc_lookup(ip_str, cpc_idx):
    """LPM lookup against CPC-CORE-SERVICES index."""
    if not ip_str or not cpc_idx: return {}
    by_prefix      = cpc_idx.get('by_prefix', {})
    prefix_lengths  = cpc_idx.get('prefix_lengths', [])
    key_arrays     = cpc_idx.get('key_arrays', {})
    try:
        parts  = ip_str.split('.')
        ip_int = (int(parts[0])<<24)|(int(parts[1])<<16)|(int(parts[2])<<8)|int(parts[3])
    except Exception:
        try: ip_int = int(ipaddress.ip_address(ip_str))
        except Exception: return {}
    for pl in prefix_lengths:
        group = by_prefix.get(pl)
        if not group: continue
        keys = key_arrays.get(pl, [e[0] for e in group])
        idx  = bisect.bisect_right(keys, ip_int) - 1
        if idx >= 0:
            ni, bi, info = group[idx]
            if ni <= ip_int <= bi: return info
    return {}


def load_app_taxonomy(dataset_dir, verbose):
    """Load fw_app_taxonomy.csv — App-ID to action/category/risk mapping.
    Built from PA App-ID names seen in logs + enterprise app knowledge base.
    Keyed by APP_ID (lowercase). Falls back gracefully if file not present.
    """
    path = os.path.join(dataset_dir, 'fw_app_taxonomy.csv')
    if not os.path.isfile(path):
        log('  fw_app_taxonomy: not found — using built-in App-ID rules only', verbose)
        return {}
    taxonomy = {}
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        for row in csv.DictReader(l for l in f if not l.startswith('#')):
            app_id = s(row.get('APP_ID', '')).lower()
            if app_id:
                taxonomy[app_id] = {
                    'category':    s(row.get('CATEGORY', '')),
                    'action':      s(row.get('ACTION', '')),
                    'risk':        s(row.get('RISK', '')),
                    'description': s(row.get('DESCRIPTION', '')),
                    'notes':       s(row.get('NOTES', '')),
                }
    log(f'  fw_app_taxonomy: {len(taxonomy):,} App-ID entries loaded', verbose, force=True)
    return taxonomy




def load_ipam_tags(dataset_dir, verbose):
    """Load ipam_tags_summary.csv — IPAM Location Tags for FW enrichment.

    Provides IPAM_LOC_TAG, ENV_CLASS, DISPLACEMENT_TYPE per source IP.
    Built by generate_ipam_tags.py v2.0.
    Tag format: [APM_ID]-[HERITAGE]-[ENV_CLASS]-[LOC_CODE]
    """
    import glob as _g
    for pattern in ['ipam_tags_summary_v*.csv', 'ipam_tags_summary.csv',
                    'ipam_tags_valid_v*.csv',   'ipam_tags_valid.csv']:
        matches = sorted(_g.glob(os.path.join(dataset_dir, pattern)), key=_ver_key)
        if matches:
            break
    else:
        log('  ipam_tags: not found — IPAM tag enrichment disabled', verbose)
        return {}

    path = matches[-1]
    log(f'  Loading IPAM tags: {os.path.basename(path)}', verbose, force=True)
    tags = {}
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as fh:
            reader = csv.DictReader(l for l in fh if not l.startswith('#'))
            count = 0
            for row in reader:
                ip = row.get('IP_ADDRESS', '').strip()
                if ip:
                    tags[ip] = {
                        'ipam_tag':    row.get('IPAM_LOC_TAG', '').strip(),
                        'env_class':   row.get('ENV_CLASS', '').strip(),
                        'loc_code':    row.get('LOC_CODE', '').strip(),
                        'heritage':    row.get('HERITAGE', '').strip(),
                        'apm_id':      row.get('APM_ID', '').strip(),
                        'app_acronym': row.get('APP_ACRONYM', '').strip(),
                        'disp_type':   row.get('DISPLACEMENT_TYPE', '').strip(),
                        'disp_note':   row.get('DISPLACEMENT_NOTE', '').strip(),
                        'pci':         row.get('PCI', '').strip(),
                        'risk_tier':   row.get('RISK_TIER', '').strip(),
                        'sox':         row.get('SOX_CRITICAL', '').strip(),
                        'phi':         row.get('ARA_PHI', '').strip(),
                        'pii':         row.get('ARA_PII', '').strip(),
                    }
                    count += 1
        log(f'  ipam_tags: {count:,} records loaded', verbose, force=True)
    except Exception as e:
        log(f'  WARNING: could not load ipam_tags: {e}', verbose)
        return {}
    return tags



def load_vpn_partners(dataset_dir, verbose):
    """Load vpn_protected_subnets.csv — S2S VPN partner remote subnets.

    Provides partner identification for destination IPs matching partner
    subnets so traffic to partners shows as PARTNER-<name> not UNKNOWN.
    Returns LPM table: [(net_int, bcast_int, partner_name, gateway_site)]
    """
    import glob as _g, ipaddress as _ip, bisect as _b
    from collections import defaultdict as _dd

    for pat in ['vpn_protected_subnets*.csv', 'ent-ipdataset-S2S-VPN-PARTNERS*.csv']:
        matches = sorted(_g.glob(os.path.join(dataset_dir, pat)), key=_ver_key)
        if matches: break
    else:
        log('  vpn_partners: not found — partner subnet enrichment disabled', verbose)
        return None

    path = matches[-1]
    log(f'  Loading VPN partner subnets: {os.path.basename(path)}', verbose, force=True)
    entries = []
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as fh:
            count = 0
            for row in csv.DictReader(l for l in fh if not l.startswith('#')):
                cidr = (row.get('IP_NETWORK') or row.get('REMOTE_SUBNET') or
                        row.get('CIDR','') or row.get('remote_subnet','')).strip()
                name = (row.get('PARTNER_NAME') or row.get('partner_name') or
                        row.get('PEER_NAME','')).strip()
                gw   = (row.get('gateway_site') or row.get('GATEWAY_SITE','') or
                        row.get('GATEWAY','')).strip()
                # Only index REMOTE subnets for destination enrichment
                direction = row.get('direction','').strip().upper()
                if direction == 'LOCAL': continue
                if not cidr: continue
                try:
                    net = _ip.ip_network(cidr, strict=False)
                    entries.append((int(net.network_address),
                                    int(net.broadcast_address),
                                    name, gw))
                    count += 1
                except Exception:
                    continue
        entries.sort(key=lambda x: x[0])
        log(f'  vpn_partners: {count:,} partner subnets loaded', verbose, force=True)
    except Exception as e:
        log(f'  WARNING: could not load vpn_partners: {e}', verbose)
        return None
    return entries


def lookup_vpn_partner(ip_str, vpn_entries):
    """Return (partner_name, gateway_site) if IP matches a VPN partner subnet."""
    if not vpn_entries: return None, None
    import ipaddress as _ip, bisect as _b
    try:
        ip_int = int(_ip.ip_address(ip_str.split('/')[0].strip()))
    except Exception:
        return None, None
    keys = [e[0] for e in vpn_entries]
    idx  = _b.bisect_right(keys, ip_int) - 1
    if idx >= 0 and vpn_entries[idx][0] <= ip_int <= vpn_entries[idx][1]:
        return vpn_entries[idx][2], vpn_entries[idx][3]
    return None, None

def load_geoip(dataset_dir, verbose):
    """Load GeoIP lookup engine from geo_ip.py if available and files present."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'geo_ip',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'geo_ip.py'))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        geo = mod.GeoIPLookup(dataset_dir, load_us_geo=True)
        if geo.is_loaded():
            st = geo.stats()
            log(f'  GeoIP loaded: {st["networks"]:,} country CIDRs, '
                f'{st["asn"]:,} ASN records', verbose, force=True)
            return geo
        else:
            log('  GeoIP: DB files not found in dataset_dir — country/ASN enrichment disabled', verbose)
            return None
    except Exception as e:
        log(f'  GeoIP: not available ({e})', verbose)
        return None


# ── IP dataset loader ─────────────────────────────────────────────────────────

def load_ip_datasets(ip_dataset_dir, verbose):
    """
    Load all ip_dataset_*.csv files.
    Returns a list of (network, provider, service, region, ds_class, svc_type,
                       svc_label, description, nbg) tuples sorted longest-prefix first.
    """
    pattern = os.path.join(ip_dataset_dir, 'ip_dataset_*.csv')
    files   = sorted(glob.glob(pattern), key=_ver_key)
    if not files:
        log(f'  WARNING: No ip_dataset_*.csv found in {ip_dataset_dir} — dest enrichment disabled', force=True)
        return []

    records = []
    seen    = {}   # net_str → best candidate tuple (quality-aware)
    for fpath in files:
        try:
            with open(fpath, newline='', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(l for l in f if not l.startswith('#'))
                for row in reader:
                    net_str = s(row.get('IP_NETWORK', ''))
                    if not net_str or ':' in net_str:
                        continue
                    try:
                        net = ipaddress.ip_network(net_str, strict=False)
                    except ValueError:
                        continue
                    provider = s(row.get('PROVIDER', ''))
                    service  = s(row.get('SERVICE',  ''))
                    region   = s(row.get('REGION',   ''))
                    nbg      = s(row.get('NETWORK_BORDER_GROUP', ''))
                    ds_class = s(row.get('IP_DATASET_CLASS',   'UNKNOWN'))
                    svc_type = s(row.get('SERVICE_TYPE_CODE',  ''))
                    svc_label= s(row.get('SERVICE_TYPE_LABEL', ''))
                    desc     = s(row.get('DESCRIPTION',        ''))

                    # Infer Google service from region/NBG when service is blank
                    if provider == 'Google' and not service:
                        if nbg and nbg not in ('', '-'):
                            service = nbg
                        elif region:
                            if 'us-' in region or region in ('us','google-global'):
                                service = 'Google-US'
                            elif 'europe' in region or 'eu' in region:
                                service = 'Google-EU'
                            elif 'asia' in region:
                                service = 'Google-APAC'
                            else:
                                service = f'Google-{region}'

                    candidate = (net, provider, service, region, ds_class,
                                 svc_type, svc_label, desc, nbg)

                    # Quality-aware dedup: keep best record per CIDR
                    # Priority: IAAS/SAAS/CLOUD > OTHER/CARRIER > UNKNOWN
                    # Within same class: named service > generic
                    CLASS_RANK = {'IAAS':0,'SAAS':0,'CLOUD':0,'ENTERPRISE':1,
                                  'OTHER':2,'CARRIER':2,'UNKNOWN':3}
                    existing = seen.get(net_str)
                    if existing is None:
                        seen[net_str] = candidate
                    else:
                        ex_rank  = CLASS_RANK.get(existing[4], 3)
                        new_rank = CLASS_RANK.get(ds_class, 3)
                        # New is better class, OR same class but has a named service
                        if new_rank < ex_rank or (
                            new_rank == ex_rank and service and not existing[2]):
                            seen[net_str] = candidate
        except Exception as e:
            log(f'  WARNING: Could not read {fpath}: {e}', verbose)

    records = list(seen.values())
    records.sort(key=lambda x: x[0].prefixlen, reverse=True)
    log(f'  IP datasets: {len(records):,} CIDR records from {len(files)} files', verbose, force=True)
    if len(records) > MAX_LPM_ROWS:
        log(f'  WARNING: ip_dataset LPM table has {len(records):,} records '
            f'(>{MAX_LPM_ROWS:,} MAX_LPM_ROWS threshold). '
            f'Dest enrichment lookups may be slow on large log files. '
            f'Consider splitting or pruning ip_dataset files.', verbose, force=True)
    return records


def classify_ip_space(ip_obj):
    """Classify an IP address by RFC address space.
    Returns (space_class, rfc, description, is_internet_routable, is_bogon_for_internet)
    """
    PRIVATE_RANGES = [
        (ipaddress.ip_network('10.0.0.0/8'),        'RFC1918',  'Private network',           False, True),
        (ipaddress.ip_network('172.16.0.0/12'),      'RFC1918',  'Private network',           False, True),
        (ipaddress.ip_network('192.168.0.0/16'),     'RFC1918',  'Private network',           False, True),
        (ipaddress.ip_network('100.64.0.0/10'),      'RFC6598',  'CGNAT shared address space',False, True),
        (ipaddress.ip_network('127.0.0.0/8'),        'RFC5735',  'Loopback',                  False, True),
        (ipaddress.ip_network('169.254.0.0/16'),     'RFC3927',  'Link-local',                False, True),
        (ipaddress.ip_network('0.0.0.0/8'),          'RFC1122',  'This network',              False, True),
        (ipaddress.ip_network('240.0.0.0/4'),        'RFC1112',  'Reserved',                  False, True),
        (ipaddress.ip_network('224.0.0.0/4'),        'RFC5771',  'Multicast',                 False, True),
        (ipaddress.ip_network('198.18.0.0/15'),      'RFC2544',  'Benchmarking',              False, True),
        (ipaddress.ip_network('192.0.2.0/24'),       'RFC5737',  'Documentation TEST-NET-1',  False, True),
        (ipaddress.ip_network('198.51.100.0/24'),    'RFC5737',  'Documentation TEST-NET-2',  False, True),
        (ipaddress.ip_network('203.0.113.0/24'),     'RFC5737',  'Documentation TEST-NET-3',  False, True),
        (ipaddress.ip_network('192.0.0.0/24'),       'RFC6890',  'IETF Protocol Assignments', False, True),
    ]
    for net, rfc, desc, routable, bogon in PRIVATE_RANGES:
        if ip_obj in net:
            return (rfc, rfc, desc, routable, bogon)
    return ('PUBLIC', 'IANA', 'Internet-routable public address', True, False)


def lookup_dest(dest_ip, ip_dataset_records, geoip=None, src_zone='', dst_zone='', cpc_idx=None):
    """
    Enriched destination lookup — geo_ip runs on EVERY IP, no blanks.

    Resolution chain (all layers always applied):
      0. RFC space classification — bogon/private in outside zone = CRITICAL
      1. GeoIP — ASN, org, country, city, state  (always)
      2. ip_dataset LPM — provider/service label  (adds to geo result)
      3. Supplement table — well-known providers not in ip_dataset
      4. ASN org as provider fallback if ip_dataset has no match

    Result always has: country, asn, org, city — never 'Unknown' for public IPs.
    """
    result = {
        'provider':     '', 'service': '', 'region': '', 'nbg': '',
        'ds_class':     'EXTERNAL', 'svc_type': '', 'svc_label': '', 'description': '',
        'country_code': '', 'country_name': '', 'is_high_risk': 'N',
        'risk_reason':  '', 'asn': '', 'as_name': '', 'city': '',
        'us_state':     '', 'asn_display': '',
        'ip_space':     'PUBLIC', 'ip_rfc': '', 'ip_space_desc': '',
        'is_bogon':     False,
        'cpc_match':    'N', 'cpc_service': '', 'cpc_heritage': '',
        'cpc_ports':    '', 'cpc_desc': '',
    }

    try:
        ip = ipaddress.ip_address(dest_ip)
    except ValueError:
        result['provider'] = 'Invalid IP'
        return result

    # ── Step 0: RFC space classification ─────────────────────────────────────
    space, rfc, space_desc, routable, is_bogon = classify_ip_space(ip)
    result['ip_space']      = space
    result['ip_rfc']        = rfc
    result['ip_space_desc'] = space_desc
    result['is_bogon']      = is_bogon

    outside_zones = {'outside', 'untrust', 'external', 'internet', 'dmz', 'egress'}
    is_outside = dst_zone.lower() in outside_zones or 'outside' in dst_zone.lower() or 'untrust' in dst_zone.lower()

    if is_bogon and is_outside:
        result['provider']    = f'⚠ RFC VIOLATION — {rfc}'
        result['description'] = f'{space_desc} ({rfc}) destined for internet-facing zone — should never be routed externally'
        result['ds_class']    = 'BOGON'
        result['is_high_risk'] = 'Y'
        result['risk_reason']  = f'Private/reserved address space ({rfc}) in outside zone — route leak, NAT failure, or spoofed packet'
        return result

    if is_bogon:
        # RFC1918 to RFC1918 — internal only, enrich via IPAM not geo
        result['provider']    = f'{rfc} — {space_desc}'
        result['ds_class']    = 'INTERNAL'
        result['description'] = space_desc
        return result

    # ── Step 1: GeoIP — runs on EVERY public IP ───────────────────────────────
    if geoip is not None:
        geo = geoip.lookup(dest_ip)
        if geo:
            asn = geo.get('asn', '')
            org = geo.get('as_name', '')
            result.update({
                'country_code': geo.get('country_code', ''),
                'country_name': geo.get('country_name', ''),
                'is_high_risk': geo.get('is_high_risk', 'N'),
                'risk_reason':  geo.get('risk_reason',  ''),
                'asn':          asn,
                'as_name':      org,
                'city':         geo.get('city',     ''),
                'us_state':     geo.get('us_state', ''),
                'asn_display':  f'{asn} — {org}'.strip(' —') if asn or org else '',
            })
            # Use ASN org as provider baseline — overridden by ip_dataset if matched
            if org:
                result['provider'] = org
                result['description'] = f'{org} ({asn}) — {geo.get("country_code","")} {geo.get("city","")}'.strip()

    # ── Step 2: ip_dataset LPM — adds provider/service label ─────────────────
    for net, provider, service, region, ds_class, svc_type, svc_label, desc, nbg in ip_dataset_records:
        if ip in net:
            # Quality check: if ip_dataset class is OTHER/CARRIER and geo ASN org
            # disagrees with the dataset provider, geo wins — carrier datasets have
            # stale/wrong attribution for cloud provider ranges (e.g. Azure in AWS space)
            geo_org = result.get('as_name', '')
            geo_asn = result.get('asn', '')
            if ds_class in ('OTHER', 'CARRIER', 'UNKNOWN') and geo_org:
                # Check for obvious org mismatch (Microsoft vs Amazon etc.)
                CLOUD_KEYWORDS = {
                    'microsoft': 'Microsoft Azure',
                    'amazon':    'Amazon Web Services',
                    'google':    'Google',
                    'cloudflare':'Cloudflare',
                    'akamai':    'Akamai',
                    'fastly':    'Fastly',
                }
                geo_org_lower = geo_org.lower()
                prov_lower    = (provider or '').lower()
                geo_canonical = next((v for k,v in CLOUD_KEYWORDS.items()
                                     if k in geo_org_lower), None)
                prov_matches  = any(k in prov_lower for k in CLOUD_KEYWORDS)
                # If geo identifies a major cloud and provider is different — use geo
                if geo_canonical and geo_canonical.split()[0].lower() not in prov_lower:
                    result.update({
                        'provider':    geo_canonical,
                        'service':     service or f'{geo_canonical} ({geo_asn})',
                        'region':      region or result.get('us_state',''),
                        'nbg':         nbg,
                        'ds_class':    'IAAS',
                        'svc_type':    svc_type,
                        'svc_label':   svc_label or geo_canonical,
                        'description': f'{geo_canonical} — {geo_org} ({geo_asn}) [geo-corrected from: {provider}]',
                    })
                    break
            # Standard ip_dataset match
            result.update({
                'provider':    provider or result['provider'],
                'service':     service,
                'region':      region or result.get('us_state','') or result.get('country_code',''),
                'nbg':         nbg,
                'ds_class':    ds_class,
                'svc_type':    svc_type,
                'svc_label':   svc_label,
                'description': desc or result['description'],
            })
            break

    # ── Step 3: Supplement table — fills gaps for known providers ────────────
    if result['ds_class'] == 'EXTERNAL':
        for net, provider, service, region, ds_class, svc_type, desc in _SUPPLEMENT:
            if ip in net:
                result.update({
                    'provider':  provider,
                    'service':   service,
                    'region':    region,
                    'ds_class':  ds_class,
                    'svc_type':  svc_type,
                    'description': desc or result['description'],
                })
                break

    # ── Final fallback: ensure provider is never blank ────────────────────────
    if not result['provider']:
        cc = result.get('country_code','')
        result['provider'] = f'Unknown ({cc})' if cc else 'Unknown — no ASN data'

    return result


# ── Log loader ────────────────────────────────────────────────────────────────
# ── Log loader ────────────────────────────────────────────────────────────────

def load_log(paths, min_pkts, verbose):
    """Load one or more Splunk CSV log files.

    Handles two schemas automatically:
      FULL schema:  packets_out + packets_in columns present.
                    min_pkts filter applied — only established sessions kept.
      FLOW schema:  No packet count columns (pre-aggregated TCP-FIN flows).
                    src_port column may be present. Every row treated as
                    an established session; min_pkts filter skipped.

    Returns (established_sessions, funnel).
    """
    est_rows = []
    funnel = {
        'total': 0, 'syn_only': 0, 'syn_synack': 0,
        'handshake': 0, 'data_minimal': 0, 'established': 0,
        'tcp_fin': 0, 'tcp_rst': 0, 'aged_out': 0,
        'pkts_out_total': 0, 'pkts_in_total': 0,
        'top_ports': defaultdict(int), 'top_apps': defaultdict(int),
        'dest_zones': set(), 'src_zones': set(),
        'devices': set(), 'log_files': [],
        'min_pkts': min_pkts,
        'schema': 'unknown',
    }

    for path in paths:
        funnel['log_files'].append(os.path.basename(path))
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(l for l in f if not l.startswith("#"))
            fieldnames = reader.fieldnames or []
            # Detect schema from column headers
            has_pkt_cols  = 'packets_out' in fieldnames or 'packets_in' in fieldnames
            has_src_port  = 'src_port' in fieldnames
            # Zscaler EDL logs use 'src' instead of 'src_ip'
            src_col       = 'src_ip' if 'src_ip' in fieldnames else 'src'
            schema        = 'full' if has_pkt_cols else 'flow'
            funnel['schema'] = schema
            log(f'  Schema: {schema.upper()} (pkt_cols={has_pkt_cols} src_port={has_src_port} src_col={src_col})',
                verbose, force=True)

            for row in reader:
                try:
                    pout = int(row.get('packets_out', 0) or 0)
                    pin  = int(row.get('packets_in',  0) or 0)
                except (ValueError, TypeError):
                    pout = pin = 0

                end   = s(row.get('session_end_reason', ''))
                app   = s(row.get('app', '') or row.get('rule', ''))
                port  = int(row.get('dest_port', 0) or 0)
                sport = int(row.get('src_port',  0) or 0)
                dz    = s(row.get('dest_zone', ''))
                sz    = s(row.get('src_zone',  ''))
                dvc   = s(row.get('dvc', ''))

                # Flow schema: every row is a completed TCP-FIN session
                # Assign a nominal packet count so funnel renders correctly
                if schema == 'flow':
                    total_pkts = min_pkts + 1   # signal: established
                    pout = pout or 1
                    pin  = pin  or 1
                else:
                    total_pkts = pout + pin

                funnel['total']          += 1
                funnel['pkts_out_total'] += pout
                funnel['pkts_in_total']  += pin
                funnel['top_ports'][port] += 1
                if app:  funnel['top_apps'][app] += 1
                if dz:   funnel['dest_zones'].add(dz)
                if sz:   funnel['src_zones'].add(sz)
                if dvc:  funnel['devices'].add(dvc)

                # Lifecycle stage
                if schema == 'flow':
                    # All flow records are established sessions (TCP-FIN confirmed)
                    funnel['established'] += 1
                elif pout == 1 and pin == 0:
                    funnel['syn_only'] += 1
                elif pout == 1 and pin == 1:
                    funnel['syn_synack'] += 1
                elif 2 <= total_pkts <= 3:
                    funnel['handshake'] += 1
                elif 4 <= total_pkts <= min_pkts:
                    funnel['data_minimal'] += 1
                else:
                    funnel['established'] += 1

                # Close reason
                if end == 'tcp-fin':
                    funnel['tcp_fin'] += 1
                elif 'rst' in end:
                    funnel['tcp_rst'] += 1
                elif end == 'aged-out':
                    funnel['aged_out'] += 1

                # Include row if it passes the threshold (flow schema: always passes)
                is_established = (schema == 'flow') or (total_pkts >= min_pkts)
                if is_established:
                    # Traffic tier — classify session by packet volume
                    # Helps distinguish PA inspection probes from real data flows
                    tp = total_pkts if total_pkts > 0 else pout + pin
                    if tp <= 5:
                        traffic_tier = 'PROBE'       # TCP handshake only / PA app probe
                    elif tp <= 20:
                        traffic_tier = 'LIGHT'       # minimal data exchange
                    elif tp <= 100:
                        traffic_tier = 'NORMAL'      # normal interactive session
                    elif tp <= 1000:
                        traffic_tier = 'ACTIVE'      # sustained data transfer
                    else:
                        traffic_tier = 'BULK'        # high-volume transfer

                    est_rows.append({
                        'src_ip':       s(row.get(src_col, '') or row.get('src_ip', '') or row.get('src', '')),
                        'src_port':     sport,
                        'src_zone':     sz,
                        'src_hostname': s(row.get('src_host', '') or row.get('src_hostname', '') or row.get('hostname', '')),
                        'dest_ip':      s(row.get('dest_translated_ip', '') or row.get('dest_ip', '')),
                        'dest_zone':    dz,
                        'dest_port':    port,
                        'pkts_out':     pout,
                        'pkts_in':      pin,
                        'total_pkts':   total_pkts,
                        'traffic_tier': traffic_tier,
                        'dvc':          dvc,
                        'end_reason':   end,
                        'flags':        s(row.get('flags', '')),
                        'app':          app,
                    })

    funnel['dest_zones'] = sorted(funnel['dest_zones'])
    funnel['src_zones']  = sorted(funnel['src_zones'])
    funnel['devices']    = sorted(funnel['devices'])
    funnel['top_ports']  = dict(sorted(funnel['top_ports'].items(),  key=lambda x: -x[1])[:10])
    funnel['top_apps']   = dict(sorted(funnel['top_apps'].items(),   key=lambda x: -x[1])[:8])

    log(f'  Schema detected:              {funnel["schema"].upper()}', verbose, force=True)
    log(f'  Total rows in log:            {funnel["total"]:,}', verbose, force=True)
    log(f'  Established sessions:         {len(est_rows):,}', verbose, force=True)
    return est_rows, funnel


# ── Aggregation ───────────────────────────────────────────────────────────────

# ── Hostname translator (inline — no external dependency) ────────────────────
# Self-contained 5-tier hostname→location resolver that mirrors the logic in
# hostname_translate.py. Used as a fallback enrichment pass inside aggregate()
# when a src_ip has a hostname (from the Splunk log or ENT dataset) but no
# matching ENT record, or when the IPAM lookup returned an empty blob.

import re as _ht_re

# Tier 1 — prefix registry: longest-prefix match, keyed by lowercase prefix.
# Add entries here or extend via the external hostname_prefix_registry.csv.
# Format: prefix → (canonical_location, heritage, routing_domain, net_type, env)
_HT_PREFIX_REGISTRY = {
    # AI/GPU cluster — Las Vegas Switch Colo (confirmed from IPAM: 10.20.34.0/24)
    'aigpu':        ('Las Vegas NV - Switch Colo',      'CVS',   'COLO',         'COLO',      ''),
    # Zscaler appliances — PA Zone (site derived from zone suffix)
    'paz1zsc':      ('Scottsdale AZ - Shea DC',         'CVS',   'Internal-PBM', 'DataCenter', 'PROD'),
    'paz2zsc':      ('Scottsdale AZ - Shea DC',         'CVS',   'Internal-PBM', 'DataCenter', 'PROD'),
    # SCOM gateways — monitored site, not subnet home (override in caller)
    'mdnpscomgtw':  ('Scottsdale AZ - Shea DC',         'CVS',   'Internal-PBM', 'DataCenter', 'PROD'),
    # IBM RxConnect
    'ibmrxc':       ('Cloud - AWS US-East-1',           'CVS',   'Cloud-AWS',    'Cloud',     ''),
    'ibmrxconsp':   ('Cloud - AWS US-East-1',           'CVS',   'Cloud-AWS',    'Cloud',     ''),
    'ibmrxcpe':     ('Cloud - AWS US-East-1',           'CVS',   'Cloud-AWS',    'Cloud',     ''),
    # GKE node pools
    'us-east4':     ('Cloud - GCP US-East4',            'CVS',   'Cloud-GCP',    'Cloud',     'PROD'),
    'us-central1':  ('Cloud - GCP US-Central1',         'CVS',   'Cloud-GCP',    'Cloud',     'PROD'),
    # Aetna Windsor
    'wvms':         ('Windsor CT - Aetna WDC',          'AETNA', 'Internal-HCB', 'DataCenter', ''),
    'wvmt':         ('Windsor CT - Aetna WDC',          'AETNA', 'Internal-HCB', 'DataCenter', ''),
    'winp':         ('Windsor CT - Aetna WDC',          'AETNA', 'Internal-HCB', 'DataCenter', ''),
    'wint':         ('Windsor CT - Aetna WDC',          'AETNA', 'Internal-HCB', 'DataCenter', ''),
    # Aetna Middletown
    'mdnp':         ('Middletown CT - Aetna MDC',       'AETNA', 'Internal-HCB', 'DataCenter', ''),
    'mpxp':         ('Phoenix AZ - Aetna DC',           'AETNA', 'Internal-HCB', 'DataCenter', ''),
    'pdch':         ('Phoenix AZ - Aetna DC',           'AETNA', 'Internal-HCB', 'DataCenter', ''),
    # CVS Shea DC
    'rca':          ('Scottsdale AZ - Shea DC',         'CVS',   'Internal-PBM', 'DataCenter', ''),
    'rsh':          ('Scottsdale AZ - Shea DC',         'CVS',   'Internal-PBM', 'DataCenter', ''),
    # CVS RI-One
    'rri':          ('Providence RI - RI-One',          'CVS',   'Internal-PBM', 'DataCenter', ''),
    'rin':          ('Providence RI - RI-One',          'CVS',   'Internal-PBM', 'DataCenter', ''),
    # CVS RI-2100
    'r21':          ('Cumberland RI - 2100 Highland',   'CVS',   'Internal-PBM', 'DataCenter', ''),
    # Las Vegas Switch
    'lvs':          ('Las Vegas NV - Switch Colo',      'CVS',   'COLO',         'COLO',      ''),
    'lvc':          ('Las Vegas NV - Switch Colo',      'CVS',   'COLO',         'COLO',      ''),
    # Atlanta Switch
    'atls':         ('Atlanta GA - Switch COLO',        'CVS',   'COLO',         'COLO',      ''),
    # Retail store pattern (rXXXX = store number)
}

# Tier 2 — compiled regex patterns (checked in order, first match wins)
_HT_PATTERNS = [
    # GKE nodes
    (_ht_re.compile(r'^us-east4-.*-gke$'),      'Cloud - GCP US-East4',         'CVS',   'Cloud-GCP',    'Cloud',      'PROD'),
    (_ht_re.compile(r'^us-central1-.*-gke$'),   'Cloud - GCP US-Central1',      'CVS',   'Cloud-GCP',    'Cloud',      'PROD'),
    # Azure cloud hosts
    (_ht_re.compile(r'^xacl'),                  'Cloud - Azure East US 2',       'AETNA', 'Cloud-Azure',  'Cloud',      ''),
    (_ht_re.compile(r'^xaw1'),                  'Cloud - Azure East US 2',       'AETNA', 'Cloud-Azure',  'Cloud',      ''),
    (_ht_re.compile(r'^eaw1'),                  'Cloud - Azure East US 2',       'AETNA', 'Cloud-Azure',  'Cloud',      ''),
    (_ht_re.compile(r'^mer-az'),                'Cloud - Azure East US 2',       'AETNA', 'Cloud-Azure',  'Cloud',      ''),
    # EC2 internal
    (_ht_re.compile(r'^ip-10-\d+-\d+-\d+$'),   'Cloud - AWS US-East-1',         'CVS',   'Cloud-AWS',    'Cloud',      ''),
    # IBM Tivoli/TPMS
    (_ht_re.compile(r'^ibmtpms'),               'Scottsdale AZ - Shea DC',       'CVS',   'Internal-PBM', 'DataCenter', 'PROD'),
    # Aetna Hartford prefix
    (_ht_re.compile(r'^hvmt'),                  'Hartford CT - 151 Farmington',  'AETNA', 'Internal-HCB', 'DataCenter', ''),
    # Qumu / enterprise app (Omnicare stores context)
    (_ht_re.compile(r'^qumu'),                  'Scottsdale AZ - Shea DC',       'CVS',   'Internal-PBM', 'DataCenter', ''),
]

# Tier 3 — CVS 3-char site codes (first token of hostname, lowercase)
_HT_CVS3 = {
    'rca': ('Scottsdale AZ - Shea DC',          'CVS',   'Internal-PBM', 'DataCenter'),
    'rsh': ('Scottsdale AZ - Shea DC',          'CVS',   'Internal-PBM', 'DataCenter'),
    'rri': ('Providence RI - RI-One',           'CVS',   'Internal-PBM', 'DataCenter'),
    'rin': ('Providence RI - RI-One',           'CVS',   'Internal-PBM', 'DataCenter'),
    'rdc': ('Richardson TX - Caremark',         'CVS',   'Internal-PBM', 'DataCenter'),
    'rgc': ('Richardson TX - Caremark',         'CVS',   'Internal-PBM', 'DataCenter'),
    'woe': ('Woonsocket RI - Corporate',        'CVS',   'Internal-PBM', 'Corporate'),
    'wone':('Woonsocket RI - Corporate',        'CVS',   'Internal-PBM', 'Corporate'),
    'lvs': ('Las Vegas NV - Switch Colo',       'CVS',   'COLO',         'COLO'),
    'atl': ('Atlanta GA - Switch COLO',         'CVS',   'COLO',         'COLO'),
}

# Tier 4 — Aetna legacy: [e|p] + 3-char airport code
_HT_AETNA_AIRPORTS = {
    'atl': 'Atlanta GA - Aetna DC',
    'mdc': 'Middletown CT - Aetna MDC',
    'mdz': 'Middletown CT - Aetna MDC',
    'wdc': 'Windsor CT - Aetna WDC',
    'phx': 'Phoenix AZ - Aetna DC',
    'hfd': 'Hartford CT - 151 Farmington',
    'bwi': 'Baltimore MD - Aetna',
}

# Tier 5 — FQDN domain suffix
_HT_DOMAINS = {
    'cvty.com':         ('',                            'CVS',   'Internal-PBM', 'Corporate'),
    'wdcaetna.com':     ('Windsor CT - Aetna WDC',     'AETNA', 'Internal-HCB', 'DataCenter'),
    'aetna.com':        ('Middletown CT - Aetna MDC',  'AETNA', 'Internal-HCB', 'DataCenter'),
    'caremark.com':     ('Scottsdale AZ - Shea DC',    'CVS',   'Internal-PBM', 'DataCenter'),
    'cvshealth.com':    ('',                            'CVS',   'Internal-PBM', 'Corporate'),
    'cvs.com':          ('',                            'CVS',   'Internal-PBM', 'Corporate'),
}

# Also load external prefix registry if present alongside the script
def _load_external_ht_registry(script_dir):
    """Load hostname_prefix_registry.csv if present — extends _HT_PREFIX_REGISTRY."""
    import csv as _csv
    reg_path = os.path.join(script_dir, 'hostname_prefix_registry.csv')
    if not os.path.exists(reg_path):
        return
    try:
        with open(reg_path, newline='', encoding='utf-8') as f:
            for row in _csv.DictReader(r for r in f if not r.startswith('#')):
                prefix = (row.get('PREFIX','') or '').strip().lower()
                if not prefix: continue
                _HT_PREFIX_REGISTRY[prefix] = (
                    row.get('CANONICAL_LOCATION','').strip(),
                    row.get('HERITAGE','').strip(),
                    row.get('ROUTING_DOMAIN','').strip(),
                    row.get('NET_TYPE','').strip(),
                    row.get('ENV','').strip(),
                )
    except Exception:
        pass

def translate_hostname(hostname):
    """Translate a CVS/Aetna hostname to location context.

    Returns dict with keys: location, heritage, routing_domain, net_type, env,
    site_code, tier.  Returns {} if no match found.
    """
    if not hostname:
        return {}
    hn = hostname.strip().lower().split('.')[0]   # strip domain, lowercase
    fqdn_lower = hostname.strip().lower()

    # Tier 1 — prefix registry (longest-prefix-first match)
    for length in range(min(len(hn), 20), 0, -1):
        prefix = hn[:length]
        if prefix in _HT_PREFIX_REGISTRY:
            loc, her, rd, nt, env = _HT_PREFIX_REGISTRY[prefix]
            # Infer env from hostname if not in registry
            if not env:
                if 'prd' in hn or 'prod' in hn:  env = 'PROD'
                elif 'dev' in hn:                  env = 'DEV'
                elif 'tst' in hn or 'test' in hn:  env = 'TEST'
                elif 'stg' in hn or 'stage' in hn: env = 'STG'
            return {'location': loc, 'heritage': her, 'routing_domain': rd,
                    'net_type': nt, 'env': env, 'tier': '1-prefix-registry'}

    # Tier 2 — compiled regex patterns
    for pattern, loc, her, rd, nt, env in _HT_PATTERNS:
        if pattern.search(hn):
            if not env:
                if 'prd' in hn or 'prod' in hn: env = 'PROD'
                elif 'dev' in hn:                env = 'DEV'
            return {'location': loc, 'heritage': her, 'routing_domain': rd,
                    'net_type': nt, 'env': env, 'tier': '2-pattern'}

    # Tier 3 — CVS 3-char site code (first token before digit or separator)
    site3 = _ht_re.match(r'^([a-z]{3})', hn)
    if site3:
        code = site3.group(1)
        if code in _HT_CVS3:
            loc, her, rd, nt = _HT_CVS3[code]
            env = 'PROD' if any(x in hn for x in ('prd','prod','1p','2p','3p')) else \
                  'DEV'  if 'dev' in hn else ''
            return {'location': loc, 'heritage': her, 'routing_domain': rd,
                    'net_type': nt, 'env': env, 'tier': '3-cvs3'}

    # Tier 4 — Aetna legacy [e|p] + 3-char airport
    m4 = _ht_re.match(r'^[ep]([a-z]{3})', hn)
    if m4 and m4.group(1) in _HT_AETNA_AIRPORTS:
        loc = _HT_AETNA_AIRPORTS[m4.group(1)]
        env = 'PROD' if hn[0] == 'p' else 'DEV'
        return {'location': loc, 'heritage': 'AETNA', 'routing_domain': 'Internal-HCB',
                'net_type': 'DataCenter', 'env': env, 'tier': '4-aetna-legacy'}

    # Tier 5 — FQDN domain suffix
    for domain, (loc, her, rd, nt) in _HT_DOMAINS.items():
        if fqdn_lower.endswith('.' + domain) or fqdn_lower == domain:
            return {'location': loc, 'heritage': her, 'routing_domain': rd,
                    'net_type': nt, 'env': '', 'tier': '5-fqdn-domain'}

    return {}   # no match


def aggregate(sessions, ipam, ent, ip_dataset_records, geoip, verbose, app_taxonomy=None, cpc_idx=None,
              ipam_tags=None,
              vpn_partners=None):
    # ipam is now the LPM dict from load_ipam
    """
    Build rule candidates and all ancillary data for the report.

    Rule key: (src_/24, dest_ip, dest_port)  →  aggregated stats
    """
    log('  Aggregating rule candidates...', verbose)

    # Cache dest lookups
    dest_cache = {}
    src_cache  = {}
    hn_cache   = {}   # hostname → translate_hostname() result

    # Rule candidates: key = (src_ip, dest_ip, dest_port) — explicit source IPs
    rules = defaultdict(lambda: {
        'src_cidrs':    set(),
        'src_ips':      set(),
        'dest_ips':     set(),
        'apps':         set(),
        'end_reasons':  set(),
        'pkts_out':     0,
        'pkts_in':      0,
        'count':        0,
        'devices':      set(),
        'traffic_tiers': {},   # tier → count
    })

    # Per-src-/24 aggregation for the source panel
    src24_data = defaultdict(lambda: {
        'src_ips':   set(),
        'dest_ips':  set(),
        'ports':     set(),
        'apps':      set(),
        'count':     0,
        'ipam':      {},
        'ip_hosts':  {},
    })

    # Per-dest-IP aggregation
    dest_data = defaultdict(lambda: {
        'src_ips':  set(),
        'ports':    set(),
        'apps':     set(),
        'count':    0,
        'enriched': {},
    })

    rfc_violations = []   # (src_ip, src_zone, dst_ip, dst_zone, port, app, pkts_out, pkts_in, rfc, desc, count)
    rfc_seen = {}         # key → count

    _total   = len(sessions)
    _report  = max(1, _total // 20)   # report every 5%
    _t0      = __import__('time').time()
    _last_t  = _t0

    for _i, sn in enumerate(sessions):
        # Progress every 5% or every 30 seconds
        if _i % _report == 0 or _i == _total - 1:
            _now  = __import__('time').time()
            _pct  = 100 * _i / _total if _total else 100
            _ela  = _now - _t0
            _rate = _i / _ela if _ela > 0 else 0
            _rem  = (_total - _i) / _rate if _rate > 0 else 0
            _rstr = f'{int(_rem//60)}m{int(_rem%60):02d}s' if _rem > 60 else f'{int(_rem)}s'
            import sys
            print(f'\r  Processing: {_i:>10,} / {_total:,}  ({_pct:.0f}%)  '
                  f'{_rate:,.0f} rows/s  ETA {_rstr}     ', end='', flush=True)
        if _i == _total - 1:
            print()  # newline after final progress

        src_ip   = sn['src_ip']
        dest_ip  = sn['dest_ip']
        port     = sn['dest_port']

        # Source subnet grouping key — use actual best-matching CIDR from IPAM
        # (replaces hardcoded /24 parent; /26 retail stores, /21 DC blocks now
        #  group and display at their actual allocation boundary)
        if src_ip not in src_cache:
            src_cache[src_ip] = lookup_src_ipam(src_ip, ipam)
        ipam_info = src_cache[src_ip]

        # ── Hostname translator fallback — fills IPAM gaps ───────────────────
        # When a source IP has no IPAM entry (empty blob), try to infer location
        # from the hostname. Hostname comes from: (a) the Splunk log field
        # src_host/src_hostname, or (b) will be set from ENT later in this loop.
        # We cache translate_hostname() results per hostname to avoid re-running.
        _sn_hn = sn.get('src_hostname', '')
        if not ipam_info and _sn_hn:
            if _sn_hn not in hn_cache:
                hn_cache[_sn_hn] = translate_hostname(_sn_hn)
            ht = hn_cache[_sn_hn]
            if ht:
                # Build a synthetic IPAM-compatible info dict from the translation
                # Mark it so the UI and loc_breakdown know it is inferred.
                try:
                    ip_obj = ipaddress.ip_address(src_ip)
                    synth_cidr = f'{ip_obj.packed[0]}.{ip_obj.packed[1]}.{ip_obj.packed[2]}.0/24'
                except Exception:
                    synth_cidr = '0.0.0.0/24'
                ipam_info = {
                    'cidr':          synth_cidr,
                    'location':      ht.get('location', ''),
                    'site':          ht.get('location', ''),
                    'facility':      ht.get('net_type', ''),
                    'net_type':      ht.get('net_type', ''),
                    'routing_dom':   ht.get('routing_domain', ''),
                    'heritage':      ht.get('heritage', ''),
                    'env':           ht.get('env', ''),
                    'ht_inferred':   True,   # flag: location derived from hostname
                    'ht_tier':       ht.get('tier', ''),
                    'ht_hostname':   _sn_hn,
                }
                # Store in src_cache so subsequent sessions from the same IP reuse it
                src_cache[src_ip] = ipam_info

        # ── IPAM Location Tag enrichment ──────────────────────────────────────
        _tag = (ipam_tags or {}).get(src_ip, {})
        if _tag:
            ipam_info['ipam_tag']    = _tag.get('ipam_tag', '')
            ipam_info['disp_type']   = _tag.get('disp_type', '')
            ipam_info['disp_note']   = _tag.get('disp_note', '')
            ipam_info['tag_apm_id']  = _tag.get('apm_id', '')
            ipam_info['tag_acronym'] = _tag.get('app_acronym', '')
            if not ipam_info.get('env_class'):
                ipam_info['env_class'] = _tag.get('env_class', '')
            if _tag.get('pci') == 'Yes':
                ipam_info['pci'] = ipam_info.get('pci') or 'Yes'
            if _tag.get('phi') == 'Yes':
                ipam_info['phi'] = 'Yes'
            if _tag.get('pii') == 'Yes':
                ipam_info['pii'] = 'Yes'
            if _tag.get('sox') == 'Yes':
                ipam_info['sox'] = 'Yes'

        try:
            ip = ipaddress.ip_address(src_ip)
            _fallback24 = (f'{ip.packed[0]}.{ip.packed[1]}.{ip.packed[2]}.0/24')
        except Exception:
            _fallback24 = '0.0.0.0/24'
        src24 = ipam_info.get('cidr', '') or _fallback24

        if dest_ip not in dest_cache:
            dest_cache[dest_ip] = lookup_dest(dest_ip, ip_dataset_records, geoip,
                                                    src_zone=sn.get('src_zone',''),
                                                    dst_zone=sn.get('dest_zone',''),
                                                    cpc_idx=cpc_idx)
        dest_info = dest_cache[dest_ip]
        # VPN partner subnet lookup
        if not dest_info.get('provider'):
            _vpn_name, _vpn_gw = lookup_vpn_partner(dest_ip, vpn_partners)
            if _vpn_name:
                dest_info['provider']      = f'PARTNER-{_vpn_name}'
                dest_info['service']       = 'S2S-VPN'
                dest_info['ds_class']      = 'PARTNER'
                dest_info['vpn_gateway']   = _vpn_gw
                dest_info['is_internal']   = True

        # RFC violation detection — private/bogon dst in outside zone
        if dest_info.get('is_bogon') and dest_info.get('ds_class') == 'BOGON':
            _rfc_key = (src_ip, dest_ip, port)
            if _rfc_key not in rfc_seen:
                rfc_seen[_rfc_key] = 0
                rfc_violations.append({
                    'src_ip':   src_ip,
                    'src_zone': sn.get('src_zone', ''),
                    'dst_ip':   dest_ip,
                    'dst_zone': sn.get('dest_zone', ''),
                    'port':     port,
                    'app':      sn.get('app', ''),
                    'pkts_out': sn.get('pkts_out', 0),
                    'pkts_in':  sn.get('pkts_in', 0),
                    'tier':     sn.get('traffic_tier', ''),
                    'rfc':      dest_info.get('ip_rfc', ''),
                    'desc':     dest_info.get('ip_space_desc', ''),
                    'count':    0,
                })
            rfc_seen[_rfc_key] += 1
        for v in rfc_violations:
            if (v['src_ip'],v['dst_ip'],v['port']) in rfc_seen:
                v['count'] = rfc_seen.get((v['src_ip'],v['dst_ip'],v['port']), 1)

        # Rule key — keyed by explicit src IP for precision
        rkey = (src_ip, dest_ip, port)
        r = rules[rkey]
        r['src_cidrs'].add(src24)
        r['src_ips'].add(src_ip)
        r['dest_ips'].add(dest_ip)
        r['apps'].add(sn['app'])
        r['end_reasons'].add(sn['end_reason'])
        r['pkts_out'] += sn['pkts_out']
        r['pkts_in']  += sn['pkts_in']
        r['count']    += 1
        r['devices'].add(sn['dvc'])
        tier = sn.get('traffic_tier', 'LIGHT')
        r['traffic_tiers'][tier] = r['traffic_tiers'].get(tier, 0) + 1
        r['ipam']       = ipam_info
        r['dest_enriched'] = dest_info

        # Src /24 panel — keyed by /24, but track individual IPs with host info
        sd = src24_data[src24]
        sd['src_ips'].add(src_ip)
        sd['dest_ips'].add(dest_ip)
        sd['ports'].add(port)
        sd['apps'].add(sn['app'])
        sd['count'] += 1
        if not sd['ipam']:
            sd['ipam'] = ipam_info
        # Per-IP host record (from ENT dataset)
        if src_ip not in sd['ip_hosts']:
            host_rec = ent.get(src_ip, {})
            # ── Hostname translator fallback for ENT misses ──────────────────
            # If ENT has no record for this IP but we have a hostname
            # (either from the Splunk log field or from an existing ent lookup
            # on a different session for the same IP), run the translator and
            # synthesise a lightweight host record so location/env/heritage
            # appear in the UI rather than showing blanks.
            if not host_rec:
                _hn_src = sn.get('src_hostname', '')
                if not _hn_src and ipam_info.get('ht_hostname'):
                    _hn_src = ipam_info['ht_hostname']
                if _hn_src:
                    if _hn_src not in hn_cache:
                        hn_cache[_hn_src] = translate_hostname(_hn_src)
                    ht = hn_cache.get(_hn_src, {})
                    if ht:
                        host_rec = {
                            'hostname':         _hn_src,
                            'fqdn':             _hn_src,
                            'location':         ht.get('location', ''),
                            'parsed_site_name': ht.get('location', ''),
                            'parsed_env':       ht.get('env', ''),
                            'parsed_heritage':  ht.get('heritage', ''),
                            'heritage':         ht.get('heritage', ''),
                            'env':              ht.get('env', ''),
                            'ht_inferred':      True,
                            'ht_tier':          ht.get('tier', ''),
                        }
            sd['ip_hosts'][src_ip] = host_rec

        # Dest panel
        dd = dest_data[dest_ip]
        dd['src_ips'].add(src_ip)
        dd['ports'].add(port)
        dd['apps'].add(sn['app'])
        dd['count'] += 1
        if not dd['enriched']:
            dd['enriched'] = dest_info

    # Build rule list with action
    rule_list = []
    for (src_ip_key, dest_ip, port), r in rules.items():
        port_risk  = PORT_RISK.get(port)
        dest_class = r.get('dest_enriched', {}).get('ds_class', 'UNKNOWN')
        end_reason = list(r['end_reasons'])[0] if r['end_reasons'] else ''
        app        = list(r['apps'])[0] if r['apps'] else ''
        dominant_tier  = max(r.get('traffic_tiers', {'LIGHT':1}).items(), key=lambda x: x[1])[0]
        action, reason = derive_action(port_risk, dest_class, end_reason, app,
                                       r.get('dest_enriched', {}), dominant_tier, app_taxonomy)

        risk_level = port_risk[1] if port_risk else 'MEDIUM'
        svc_name   = port_risk[0] if port_risk else f'Port-{port}'

        # Resolve hostname for the explicit source IP
        host_rec  = ent.get(src_ip_key, {})
        # Hostname translator fallback: if ENT misses, try to resolve from
        # any hostname carried by the rule's IPAM info (set during session loop)
        if not host_rec:
            _hn_try = r.get('ipam', {}).get('ht_hostname', '')
            if _hn_try:
                if _hn_try not in hn_cache:
                    hn_cache[_hn_try] = translate_hostname(_hn_try)
                ht = hn_cache.get(_hn_try, {})
                if ht:
                    host_rec = {
                        'hostname':         _hn_try,
                        'fqdn':             _hn_try,
                        'location':         ht.get('location', ''),
                        'parsed_site_name': ht.get('location', ''),
                        'parsed_env':       ht.get('env', ''),
                        'parsed_heritage':  ht.get('heritage', ''),
                        'heritage':         ht.get('heritage', ''),
                        'env':              ht.get('env', ''),
                        'ht_inferred':      True,
                        'ht_tier':          ht.get('tier', ''),
                    }
        src24_key = list(r['src_cidrs'])[0] if r['src_cidrs'] else '0.0.0.0/24'
        best_site = (host_rec.get('parsed_site_name') or host_rec.get('location') or r.get('ipam', {}).get('location', ''))
        best_env  = (host_rec.get('parsed_env') or host_rec.get('env') or r.get('ipam', {}).get('env', ''))
        best_os   = (host_rec.get('os') or host_rec.get('parsed_os_hint') or r.get('ipam', {}).get('os', ''))
        # ht_inferred: True if location was derived from hostname translation
        # rather than from IPAM or ENT records directly.
        ht_inferred = bool(host_rec.get('ht_inferred') or r.get('ipam', {}).get('ht_inferred'))
        ht_tier     = host_rec.get('ht_tier','') or r.get('ipam',{}).get('ht_tier','')
        rule_list.append({
            'src_ip':           src_ip_key,
            'src24':            src24_key,
            'hostname':         host_rec.get('hostname', ''),
            'fqdn':             host_rec.get('fqdn', ''),
            'ht_inferred':      ht_inferred,
            'ht_tier':          ht_tier,
            'src_os':           best_os,
            'src_os_detail':    host_rec.get('os_detail', ''),
            'src_app':          (host_rec.get('app', '') or '')[:100],
            'src_app_acronym':  host_rec.get('app_acronym', ''),
            'src_csna':         host_rec.get('csna_path', ''),
            'src_env':          best_env,
            'src_bu':           host_rec.get('bu', ''),
            'src_heritage':     host_rec.get('parsed_heritage') or host_rec.get('heritage', ''),
            'src_apm_ids':      host_rec.get('apm_ids', ''),
            'src_server_class': host_rec.get('server_class', ''),
            'src_in_snow':      host_rec.get('in_snow', ''),
            'src_in_qualys':    host_rec.get('in_qualys', ''),
            'src_in_wiz':       host_rec.get('in_wiz', ''),
            'src_data_sources': host_rec.get('data_sources', ''),
            'src_site_name':    best_site,
            'src_dc_name':      host_rec.get('parsed_dc_name', ''),
            'src_site_code':    host_rec.get('parsed_site_code', ''),
            'dest_ip':          dest_ip,
            'dest_port':        port,
            'action':           action,
            'risk':             risk_level,
            'svc':              svc_name,
            'reason':           reason,
            'port_note':        port_risk[2] if port_risk else 'Unclassified port — identify before allowing.',
            'count':            r['count'],
            'pkts_out':         r['pkts_out'],
            'pkts_in':          r['pkts_in'],
            'total_pkts':       r['pkts_out'] + r['pkts_in'],
            'apps':             sorted(a for a in r['apps'] if a),
            'end_reasons':      sorted(r['end_reasons']),
            'devices':          sorted(r['devices']),
            'ipam':             r.get('ipam', {}),
            'dest':             r.get('dest_enriched', {}),
            'dest_country':     r.get('dest_enriched', {}).get('country_code', ''),
            'dest_country_name':r.get('dest_enriched', {}).get('country_name', ''),
            'dest_high_risk':   r.get('dest_enriched', {}).get('is_high_risk', 'N'),
            'dest_risk_reason': r.get('dest_enriched', {}).get('risk_reason', ''),
            'dest_asn_display': r.get('dest_enriched', {}).get('asn_display', ''),
            'dest_city':        r.get('dest_enriched', {}).get('city', ''),
            'dest_us_state':    r.get('dest_enriched', {}).get('us_state', ''),
            'dest_asn':         r.get('dest_enriched', {}).get('asn', ''),
            'dest_as_name':     r.get('dest_enriched', {}).get('as_name', ''),
            'dest_description': r.get('dest_enriched', {}).get('description', ''),
            'dest_is_bogon':    r.get('dest_enriched', {}).get('is_bogon', False),
            'dest_ip_space':    r.get('dest_enriched', {}).get('ip_space', ''),
            'dest_ip_rfc':      r.get('dest_enriched', {}).get('ip_rfc', ''),
            'dest_cpc_match':   r.get('dest_enriched', {}).get('cpc_match', 'N'),
            'dest_cpc_service': r.get('dest_enriched', {}).get('cpc_service', ''),
            'dest_cpc_heritage':r.get('dest_enriched', {}).get('cpc_heritage', ''),
            'traffic_tiers':    r.get('traffic_tiers', {}),
            'dominant_tier':    max(r.get('traffic_tiers', {'LIGHT':1}).items(), key=lambda x: x[1])[0],
            'pkts_avg':         round((r['pkts_out'] + r['pkts_in']) / max(r['count'], 1)),
        })

    # Sort rules: BLOCK first, then by count desc
    rule_list.sort(key=lambda x: (RISK_ORDER.get(x['risk'], 99), -x['count']))

    # ── Build optimized policy recommendations (/32 App/Server-Intent model) ───
    # Target model: individual /32 source host objects grouped by application
    # intent, pointing to destination service objects (provider + svc_type).
    # Each proposed rule = (src_app × src_env × src_site × dest_provider ×
    #                       dest_svc_type × PA_app_id × action)
    # This aligns with a PA App-ID + address-object ruleset rather than
    # subnet ACLs.
    from collections import defaultdict as _dd2

    def _src_obj_name(r):
        """PA address object name for a /32 source host."""
        app = (r.get('src_app_acronym') or r.get('src_app') or '').upper()
        app = app.replace(' ', '-').replace('/', '-')[:15]
        ip  = r.get('src_ip', '')
        hn  = r.get('hostname', '')
        if app and app not in ('UNKNOWN', 'UNK'):
            return f"HOST-{app}-{ip}"
        if hn:
            short = hn.split('.')[0].upper()[:20]
            return f"HOST-{short}-{ip}"
        # No app, no hostname — use subnet CIDR prefix so the object name
        # indicates which block it belongs to (e.g. HOST-10-180-64_18-10.180.64.12)
        src24 = r.get('src24', '')
        cidr_part = src24.replace('.', '-').replace('/', '_')[:18] if src24 else 'UNK'
        return f"HOST-{cidr_part}-{ip}"

    def _src_group_name(r):
        """PA address group name for all hosts sharing app × env × site.

        Naming priority:
          App  — IPAM app_names (human-readable) > src_app_acronym > src_app
                 Falls back to CIDR when no app identity at all.
          Site — Abbreviated from location, not net_type, so COLO rules say
                 LV-SWITCH or ATL-SWITCH rather than the generic 'COLO'.
        """
        raw_app   = (r.get('src_app_acronym') or r.get('src_app') or '').strip()
        env       = (r.get('src_env') or '').strip()
        ipam      = r.get('ipam') or {}

        # Prefer the human-readable app name from IPAM over the raw acronym
        # e.g. "Convo AI" → CONVOAI, "Domain Control" → DOMAINCTRL
        ipam_app_names = ipam.get('app_names', '') or ''
        if ipam_app_names:
            # Take the first app name, strip spaces/special chars
            first_name = ipam_app_names.split('|')[0].strip()
            app_token  = _ht_re.sub(r'[^A-Za-z0-9]', '', first_name).upper()[:12]
        elif raw_app and raw_app.upper() not in ('UNKNOWN', 'UNK', ''):
            app_token = raw_app.upper().replace(' ', '-').replace('/', '-')[:12]
        else:
            app_token = ''

        # Site abbreviation: use the full location string for specificity,
        # not just the net_type.  "Las Vegas NV - Switch Colo" → LV-SWITCH
        # "Scottsdale AZ - Shea DC" → SHEA-DC
        site_full = (r.get('src_site_name') or r.get('src_dc_name') or '')
        if not site_full:
            site_full = (ipam.get('location') or ipam.get('site') or '').strip()

        def _abbrev_site(s):
            if not s: return ''
            # Take the last segment after " - "
            seg = s.split(' - ')[-1].strip()
            # City abbreviations for COLO sites so we get LV not SWITCH
            CITY_MAP = {
                'las vegas': 'LV', 'atlanta': 'ATL', 'scottsdale': 'SHEA',
                'phoenix': 'PHX', 'middletown': 'MDC', 'windsor': 'WDC',
                'providence': 'RI1', 'cumberland': 'RI2', 'richardson': 'DAL',
                'woonsocket': 'WOO', 'sparks': 'TRE', 'woodbridge': 'WBR',
                'carlstadt': 'CAR',
            }
            city = s.split(' - ')[0].split(',')[0].strip().lower()
            # Strip trailing 2-char state code (e.g. "Las Vegas NV" → "las vegas")
            city = _ht_re.sub(r'\s+[a-z]{2}$', '', city).strip()
            city_abbr = CITY_MAP.get(city, '')
            # For COLO sites, prepend city so LV-SWITCH, ATL-SWITCH
            if 'colo' in seg.lower() or 'switch' in seg.lower():
                seg_clean = seg.replace('Switch', '').replace('Colo', '').replace('COLO','').strip()
                seg_clean = seg_clean or 'COLO'
                return (city_abbr + '-SWITCH' if city_abbr else
                        seg.replace(' ', '-').upper()[:12])
            return seg.replace(' ', '-').upper()[:12]

        site_abbr = _abbrev_site(site_full)

        env_part = ('-' + env.upper()[:4]) if env and env.upper() not in ('UNK','UNKNOWN','') else ''

        if app_token:
            return f"AG-SRC-{app_token}{env_part}-{site_abbr}" if site_abbr else f"AG-SRC-{app_token}{env_part}"
        else:
            # No app identity — name by subnet CIDR
            src24     = r.get('src24', '')
            cidr_part = src24.replace('.', '-').replace('/', '_') if src24 else 'UNREGISTERED'
            return f"AG-SRC-{cidr_part}-{site_abbr}" if site_abbr else f"AG-SRC-{cidr_part}"

    def _dst_obj_name(d, port):
        """PA address object name for a destination provider+service."""
        prov = (d.get('provider') or 'UNKNOWN').upper()
        prov = prov.replace(' ', '-').replace(',', '').replace('⚠', '').strip('-')[:20]
        svc  = (d.get('svc_type') or '').upper().replace(' ', '-')[:12]
        return f"DST-{prov}-{svc}" if svc else f"DST-{prov}-{port}"

    def _rule_name(r, d):
        """Proposed PA security rule name."""
        app  = (r.get('src_app_acronym') or r.get('src_app') or 'UNK').upper().replace(' ', '-')[:12]
        prov = (d.get('provider') or 'UNK').split()[0].upper()[:10]
        svc  = (d.get('svc_type') or '').upper()[:8]
        port = r.get('dest_port', '')
        pa   = (r.get('apps') or ['any'])[0].upper().replace('-', '')[:10]
        act  = r.get('action', 'ALLOW')
        dest_part = f"{prov}-{svc}" if svc else f"{prov}-{port}"
        return f"{act}-{app}-TO-{dest_part}-{pa}"

    policy_groups = {}   # key → rule dict

    for r in rule_list:
        if r.get('action') not in ('ALLOW', 'REVIEW'):
            continue
        ip = r.get('src_ip', '')
        if not ip:
            continue   # collapsed rules handled below

        d      = r.get('dest_enriched') or r.get('dest') or {}
        pa_app = (r.get('apps') or ['unknown'])[0]
        app    = r.get('src_app_acronym') or r.get('src_app') or 'UNKNOWN'
        env    = r.get('src_env') or 'UNK'
        site   = r.get('src_site_name') or r.get('src_dc_name') or 'UNK'
        prov   = d.get('provider', 'Unknown')
        svc_t  = d.get('svc_type', '')
        port   = str(r.get('dest_port', ''))

        key = (app, env, site, prov, svc_t or port, pa_app, r.get('action', ''))
        if key not in policy_groups:
            policy_groups[key] = {
                'rule_name':   _rule_name(r, d),
                'action':      r.get('action', ''),
                'pa_app':      pa_app,
                'src_app':     app,
                'src_env':     env,
                'src_site':    site,
                'src_group':   _src_group_name(r),
                'src_hosts':   {},    # ip → {obj_name, hostname, app, env, site}
                'dest_obj':    _dst_obj_name(d, port),
                'dest_provider': prov,
                'dest_svc_type': svc_t,
                'dest_svc_label': d.get('svc_label', ''),
                'dest_ips':    set(),
                'ports':       set(),
                'sessions':    0,
                'cpc_service': '',
            }
        pg = policy_groups[key]
        pg['src_hosts'][ip] = {
            'obj':      _src_obj_name(r),
            'hostname': r.get('hostname', ''),
            'app':      app,
            'env':      env,
            'site':     site,
        }
        pg['dest_ips'].add(r.get('dest_ip', ''))
        pg['ports'].add(port)
        pg['sessions'] += r.get('count', 0)
        if not pg['cpc_service']:
            pg['cpc_service'] = r.get('dest_cpc_service', '')

    # Serialize — convert sets to sorted lists, hosts dict to list
    policy_recs = []
    for key, pg in sorted(policy_groups.items(), key=lambda x: -x[1]['sessions']):
        hosts = sorted(pg['src_hosts'].values(), key=lambda h: h.get('obj', ''))
        policy_recs.append({
            'rule_name':     pg['rule_name'],
            'action':        pg['action'],
            'pa_app':        pg['pa_app'],
            'src_app':       pg['src_app'],
            'src_env':       pg['src_env'],
            'src_site':      pg['src_site'],
            'src_group':     pg['src_group'],
            'src_hosts':     hosts,
            'dest_obj':      pg['dest_obj'],
            'dest_provider': pg['dest_provider'],
            'dest_svc_type': pg['dest_svc_type'],
            'dest_svc_label':pg['dest_svc_label'],
            'dest_ips':      sorted(pg['dest_ips'])[:30],
            'ports':         sorted(pg['ports'], key=lambda x: int(x) if x.isdigit() else 0),
            'sessions':      pg['sessions'],
            'cpc_service':   pg['cpc_service'],
        })

    # ── Policy consolidation ─────────────────────────────────────────────────
    # Three passes to collapse the fine-grained initial grouping into the
    # minimal set of operationally meaningful rules.
    #
    # Pass 1 — strip RFC-violation rules from ALLOW/REVIEW policy entirely.
    #   These are handled exclusively by the BLOCK grouper below. Leaving them
    #   in the ALLOW/REVIEW list produces dozens of spurious single-port rules.
    policy_recs = [p for p in policy_recs
                   if '⚠ RFC VIOLATION' not in p.get('dest_provider', '')
                   and 'RFC VIOLATION' not in p.get('dest_obj', '')]

    # Pass 2 — same src_group × dest_provider × dest_svc_type × pa_app × action
    #   → union ports.  The original key split on port, so e.g. STUN to Akamai
    #   on ports 3478, 3479, 3480 became three rules; now it becomes one.
    def _consolidate_ports(recs):
        merged = {}
        order  = []
        for p in recs:
            key = (p['src_group'], p['dest_provider'], p.get('dest_svc_type',''),
                   p['pa_app'], p['action'])
            if key not in merged:
                merged[key] = dict(p)
                merged[key]['ports']      = list(p.get('ports') or [])
                merged[key]['dest_ips']   = set(p.get('dest_ips') or [])
                merged[key]['src_hosts']  = {h['obj']: h for h in (p.get('src_hosts') or [])}
                order.append(key)
            else:
                c = merged[key]
                for port in (p.get('ports') or []):
                    if port not in c['ports']: c['ports'].append(port)
                c['dest_ips'].update(p.get('dest_ips') or [])
                for h in (p.get('src_hosts') or []):
                    c['src_hosts'].setdefault(h['obj'], h)
                c['sessions'] += p.get('sessions', 0)
        out = []
        for key in order:
            c = merged[key]
            c['dest_ips']  = sorted(c['dest_ips'])[:30]
            c['src_hosts'] = sorted(c['src_hosts'].values(), key=lambda h: h.get('obj',''))
            c['ports']     = sorted(c['ports'], key=lambda x: int(x) if str(x).isdigit() else 0)
            out.append(c)
        return out

    # Pass 3 — same src_group × pa_app × action, media/NAT-traversal apps
    #   (stun, rtcp, ms-teams-audio-video, quic-base, google-base, zoom) fan
    #   out to many dest providers per UDP hole-punching.  Collapse them into
    #   one rule per pa_app per src_group, with a generic dest object and all
    #   providers listed as context.
    MEDIA_APPS_SET = {'stun','rtcp','ms-teams-audio-video','quic-base',
                      'google-base','zoom','insufficient-data','unknown-udp'}

    def _consolidate_media(recs):
        media, other = [], []
        for p in recs:
            if p.get('pa_app','').lower() in MEDIA_APPS_SET:
                media.append(p)
            else:
                other.append(p)
        merged = {}
        order  = []
        for p in media:
            key = (p['src_group'], p['pa_app'], p['action'])
            if key not in merged:
                merged[key] = dict(p)
                merged[key]['ports']          = list(p.get('ports') or [])
                merged[key]['dest_ips']       = set(p.get('dest_ips') or [])
                merged[key]['src_hosts']      = {h['obj']: h for h in (p.get('src_hosts') or [])}
                merged[key]['_providers']     = {p.get('dest_provider','')}
                merged[key]['_svc_types']     = {p.get('dest_svc_type','')}
                order.append(key)
            else:
                c = merged[key]
                for port in (p.get('ports') or []):
                    if port not in c['ports']: c['ports'].append(port)
                c['dest_ips'].update(p.get('dest_ips') or [])
                for h in (p.get('src_hosts') or []):
                    c['src_hosts'].setdefault(h['obj'], h)
                c['sessions'] += p.get('sessions', 0)
                c['_providers'].add(p.get('dest_provider',''))
                c['_svc_types'].add(p.get('dest_svc_type',''))
        out = list(other)
        for key in order:
            c = merged[key]
            c['dest_ips']  = sorted(c['dest_ips'])[:30]
            c['src_hosts'] = sorted(c['src_hosts'].values(), key=lambda h: h.get('obj',''))
            # Rename dest object to reflect the PA app-id rather than a single provider
            pa   = c['pa_app'].upper().replace('-','')[:12]
            site = c['src_site'].split(' - ')[-1].replace(' ','-').upper()[:10]
            c['dest_obj']      = f"DST-ANY-{pa}"
            c['dest_provider'] = ', '.join(sorted(p for p in c['_providers'] if p))[:60]
            c['dest_svc_type'] = 'MEDIA-NAT'
            c['dest_svc_label']= f"Media/NAT traversal — {c['pa_app']} (any provider)"
            c['rule_name']     = f"{c['action']}-{c['src_app'].upper()[:10]}-{pa}-MEDIA"
            c['ports']         = sorted(set(c['ports']), key=lambda x: int(x) if str(x).isdigit() else 0)
            # Convert internal work sets to serialisable lists
            c['_providers'] = sorted(p for p in c['_providers'] if p)
            c['_svc_types'] = sorted(s for s in c['_svc_types'] if s)
            out.append(c)
        return out

    # Pass 4 — same src_group × dest_obj × action → union pa_apps
    #   e.g. VBS → Hetzner has google-base/ssl/http-proxy as three rules; one rule,
    #   application = any (or list them).
    def _consolidate_apps(recs):
        merged = {}
        order  = []
        for p in recs:
            key = (p['src_group'], p['dest_obj'], p['action'])
            if key not in merged:
                merged[key] = dict(p)
                merged[key]['_pa_apps']  = [p.get('pa_app','')]
                merged[key]['ports']     = list(p.get('ports') or [])
                merged[key]['dest_ips']  = set(p.get('dest_ips') or [])
                merged[key]['src_hosts'] = {h['obj']: h for h in (p.get('src_hosts') or [])}
                order.append(key)
            else:
                c = merged[key]
                app = p.get('pa_app','')
                if app and app not in c['_pa_apps']: c['_pa_apps'].append(app)
                for port in (p.get('ports') or []):
                    if port not in c['ports']: c['ports'].append(port)
                c['dest_ips'].update(p.get('dest_ips') or [])
                for h in (p.get('src_hosts') or []):
                    c['src_hosts'].setdefault(h['obj'], h)
                c['sessions'] += p.get('sessions', 0)
        out = []
        for key in order:
            c = merged[key]
            c['dest_ips']  = sorted(c['dest_ips'])[:30]
            c['src_hosts'] = sorted(c['src_hosts'].values(), key=lambda h: h.get('obj',''))
            c['ports']     = sorted(set(c['ports']), key=lambda x: int(x) if str(x).isdigit() else 0)
            # If multiple apps, set pa_app to the most specific non-generic one
            apps = [a for a in c['_pa_apps'] if a not in ('any','unknown','')]
            c['pa_app'] = apps[0] if len(apps) == 1 else ('any' if not apps else apps[0])
            c['_pa_apps_all'] = sorted(c['_pa_apps'])  # preserved for display
            out.append(c)
        return out

    # Apply passes
    pre  = len(policy_recs)
    policy_recs = _consolidate_ports(policy_recs)
    policy_recs = _consolidate_media(policy_recs)
    policy_recs = _consolidate_apps(policy_recs)
    # Final sort: sessions desc
    policy_recs.sort(key=lambda x: -x.get('sessions', 0))
    log(f'  Policy consolidation: {pre} → {len(policy_recs)} rules '
        f'({pre - len(policy_recs)} merged)', verbose, force=True)

    # ── RFC violation BLOCK rules ─────────────────────────────────────────────
    # RFC violations (private/bogon IPs in outside zone) require explicit BLOCK
    # rules — they represent route leaks, NAT failures, or split-brain DNS.
    # Group by (source site × RFC class) so one BLOCK rule covers all affected
    # hosts from the same site hitting the same RFC address space.
    rfc_block_groups = {}
    # PA apps that produce RFC-address traffic as a normal side-effect of
    # WebRTC/Teams ICE candidate probing — NOT route leaks, NOT policy-worthy.
    # STUN/RTCP/Teams hitting 192.168.x.x is a remote peer's local candidate
    # leaking through ICE; the call falls back to TURN relay automatically.
    # Generating BLOCK rules for this would drop legitimate media sessions.
    WEBRTC_ICE_APPS = {'stun', 'rtcp', 'ms-teams-audio-video', 'zoom',
                       'google-base', 'quic-base', 'unknown-udp'}
    for r in rule_list:
        # Identify bogon-destined rules from the rule list (dest_is_bogon or
        # provider starts with ⚠ RFC VIOLATION)
        is_bogon = r.get('dest_is_bogon') or '⚠ RFC VIOLATION' in str(r.get('dest_asn_display',''))
        if not is_bogon:
            continue
        # Skip WebRTC ICE probe traffic — 192.168.x.x / 100.64.x.x as STUN/RTCP
        # destinations is expected NAT traversal, not a route leak
        pa_apps = [a.lower() for a in (r.get('apps') or [])]
        if any(a in WEBRTC_ICE_APPS for a in pa_apps):
            continue
        ipam_blob = r.get('ipam') or {}
        site  = (ipam_blob.get('location') or ipam_blob.get('site') or
                 r.get('src_site_name') or r.get('src_dc_name') or 'Unknown')
        rfc_c = r.get('dest_ip_rfc') or 'RFC-PRIVATE'
        key   = (site, rfc_c)
        if key not in rfc_block_groups:
            site_token = site.split(' - ')[-1].replace(' ','-').upper()[:12]
            # Clean, implementable PA address object names per RFC class
            # Each maps to the full address range — not per-IP, not per-port
            RFC_DEST_OBJECTS = {
                'RFC1918': 'RFC-1918-Private_INT-Violation',   # 10/8, 172.16/12, 192.168/16
                'RFC6598': 'RFC-6598-CGNAT-Violation',         # 100.64/10
                'RFC5737': 'RFC-5737-Documentation-Violation', # 192.0.2/24 etc
                'RFC3927': 'RFC-3927-LinkLocal-Violation',     # 169.254/16
            }
            dest_obj  = RFC_DEST_OBJECTS.get(rfc_c, f'RFC-{rfc_c}-Violation')
            # Corresponding PA address object definitions (what to create on the firewall)
            RFC_RANGES = {
                'RFC1918': '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
                'RFC6598': '100.64.0.0/10',
                'RFC5737': '192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24',
                'RFC3927': '169.254.0.0/16',
            }
            addr_ranges = RFC_RANGES.get(rfc_c, 'See RFC')
            rfc_block_groups[key] = {
                'rule_name':   f'BLOCK-{site_token}-TO-{rfc_c.replace(" ","")}',
                'action':      'BLOCK',
                'pa_app':      'any',
                'src_app':     'Multiple',
                'src_env':     '',
                'src_site':    site,
                'src_group':   f'AG-SRC-{site_token}-ALL',
                'src_hosts':   [],
                'dest_obj':    dest_obj,
                'dest_provider': rfc_c,
                'dest_svc_type': 'RFC-BOGON',
                'dest_svc_label': f'{rfc_c} — {addr_ranges}',
                'addr_ranges': addr_ranges,
                'dest_ips':    [],
                'dest_ips_set':set(),
                'ports':       [],
                'ports_ctr':   {},
                'sessions':    0,
                'cpc_service': '',
                'src_ips_set': set(),
                'is_rfc_block':True,
                'rfc_class':   rfc_c,
            }
        grp = rfc_block_groups[key]
        grp['sessions'] += r.get('count', 0)
        src_ip = r.get('src_ip','')
        if src_ip:
            grp['src_ips_set'].add(src_ip)
            grp['src_hosts'].append({
                'obj':      f"HOST-{src_ip}",
                'hostname': r.get('hostname',''),
                'app':      r.get('src_app_acronym') or r.get('src_app',''),
                'env':      r.get('src_env',''),
                'site':     site,
            })
        dst = r.get('dest_ip','')
        if dst: grp['dest_ips_set'].add(dst)
        port = str(r.get('dest_port',''))
        if port: grp['ports_ctr'][port] = grp['ports_ctr'].get(port,0) + r.get('count',1)

    # Serialise RFC BLOCK groups — prepend to policy_recs (BLOCK before ALLOW)
    rfc_policy = []
    for (site, rfc_c), grp in sorted(rfc_block_groups.items(), key=lambda x: -x[1]['sessions']):
        grp['dest_ips'] = sorted(grp['dest_ips_set'])[:30]
        grp['ports']    = sorted(grp['ports_ctr'], key=lambda x: -grp['ports_ctr'].get(x,0))[:10]
        # Deduplicate src_hosts by IP
        seen_ips = set()
        deduped_hosts = []
        for h in grp['src_hosts']:
            if h['obj'] not in seen_ips:
                seen_ips.add(h['obj'])
                deduped_hosts.append(h)
        grp['src_hosts'] = deduped_hosts
        rfc_policy.append({k: v for k, v in grp.items()
                           if k not in ('src_ips_set','dest_ips_set','ports_ctr')})

    # RFC BLOCK rules go at the front — highest priority
    policy_recs = rfc_policy + policy_recs

    log(f'  Rule candidates: {len(rule_list):,}', verbose, force=True)
    log(f'  Intent-based policy rules: {len(policy_recs):,} '
        f'(incl. {len(rfc_policy)} RFC BLOCK rules)', verbose, force=True)

    # Hostname translation stats
    n_ht = sum(1 for r in rule_list if r.get('ht_inferred'))
    if n_ht:
        tiers = {}
        for r in rule_list:
            if r.get('ht_inferred') and r.get('ht_tier'):
                tiers[r['ht_tier']] = tiers.get(r['ht_tier'], 0) + 1
        log(f'  Hostname-translated rules: {n_ht:,} ({100*n_ht//max(len(rule_list),1)}%)', verbose, force=True)
        for tier, cnt in sorted(tiers.items()):
            log(f'    {tier}: {cnt:,}', verbose, force=True)

    # App-ID coverage report
    all_apps = set()
    for r in rule_list:
        all_apps.update(r.get('apps', []))
    if app_taxonomy and all_apps:
        uncovered = [a for a in all_apps if a.lower() not in app_taxonomy]
        if uncovered:
            log(f'  App-IDs not in taxonomy ({len(uncovered)}): ' +
                ', '.join(sorted(uncovered)[:10]), verbose, force=True)

    # Finalise src24 and dest panels
    src24_list = []
    for cidr, sd in sorted(src24_data.items(), key=lambda x: -x[1]['count']):
        ipam_info = sd['ipam']
        # Build per-IP host list sorted by IP
        ip_list = []
        for ip_str in sorted(sd['src_ips']):
            hr = sd['ip_hosts'].get(ip_str, {})
            best_site_ip = (hr.get('parsed_site_name') or hr.get('location') or ipam_info.get('location',''))
            best_env_ip  = (hr.get('parsed_env') or hr.get('env', ''))
            ip_list.append({
                'ip':          ip_str,
                'hostname':    hr.get('hostname', ''),
                'fqdn':        hr.get('fqdn', ''),
                'os':          hr.get('os', '') or hr.get('parsed_os_hint',''),
                'os_detail':   hr.get('os_detail', ''),
                'app':         (hr.get('app', '') or '')[:100],
                'app_acronym': hr.get('app_acronym', ''),
                'location':    best_site_ip,
                'env':         best_env_ip,
                'pci_ent':     hr.get('pci_ent', ''),
                'risk_ent':    hr.get('risk_ent', ''),
                'csna_path':   hr.get('csna_path', ''),
                'apm_ids':     hr.get('apm_ids', ''),
                'bu':          hr.get('bu', ''),
                'heritage':    hr.get('parsed_heritage') or hr.get('heritage',''),
                'in_snow':     hr.get('in_snow', ''),
                'in_qualys':   hr.get('in_qualys', ''),
                'in_wiz':      hr.get('in_wiz', ''),
                'data_sources':hr.get('data_sources', ''),
                'site_code':   hr.get('parsed_site_code', ''),
                'dc_name':     hr.get('parsed_dc_name', ''),
                'server_class':hr.get('server_class', ''),
            })
        src24_list.append({
            'cidr':     cidr,
            'count':    sd['count'],
            'src_n':    len(sd['src_ips']),
            'dest_n':   len(sd['dest_ips']),
            'ports':    sorted(sd['ports']),
            'apps':     sorted(a for a in sd['apps'] if a),
            'unregistered': not bool(ipam_info),   # True = subnet has no IPAM entry
            'site':     ipam_info.get('site', ''),
            'location': ipam_info.get('location', ''),
            'site_class':ipam_info.get('site_class',''),
            'facility': ipam_info.get('facility', ''),
            'net_type': ipam_info.get('net_type',  ''),
            'owner':    ipam_info.get('owner',     ''),
            'bu':       ipam_info.get('bu',        ''),
            'pci':      ipam_info.get('pci',       ''),
            'risk':     ipam_info.get('risk',      ''),
            'os':       ipam_info.get('os',        ''),
            'apps_ipam':    ipam_info.get('app_acronyms', ''),
            'apm_ids':      ipam_info.get('apm_ids',   ''),
            'app_names':    ipam_info.get('app_names',  ''),
            'prod_apps':    ipam_info.get('prod_apps',  ''),
            'app_envs':     ipam_info.get('app_envs',   ''),
            'pci_mixed':    ipam_info.get('pci_mixed',  ''),
            'ipam_app_id':  ipam_info.get('ipam_app_id',''),
            'compliance':   ipam_info.get('compliance',''),
            'routing':      ipam_info.get('routing_dom',''),
            'cpc_svc':      ipam_info.get('cpc_svc',  ''),
            'sox':          ipam_info.get('sox',       ''),
            'hitrust':      ipam_info.get('hitrust',   ''),
            'ip_hosts': ip_list,
        })

    dest_list = []
    for ip, dd in sorted(dest_data.items(), key=lambda x: -x[1]['count']):
        en = dd['enriched']
        dest_list.append({
            'ip':           ip,
            'count':        dd['count'],
            'src_n':        len(dd['src_ips']),
            'ports':        sorted(dd['ports']),
            'apps':         sorted(a for a in dd['apps'] if a),
            'provider':     en.get('provider',     'Unknown'),
            'service':      en.get('service',      ''),
            'region':       en.get('region',       ''),
            'nbg':          en.get('nbg',          ''),
            'ds_class':     en.get('ds_class',     'UNKNOWN'),
            'svc_type':     en.get('svc_type',     ''),
            'svc_label':    en.get('svc_label',    ''),
            'description':  en.get('description',  ''),
            'country_code': en.get('country_code', ''),
            'country_name': en.get('country_name', ''),
            'is_high_risk': en.get('is_high_risk', 'N'),
            'risk_reason':  en.get('risk_reason',  ''),
            'asn':          en.get('asn',          ''),
            'as_name':      en.get('as_name',      ''),
            'asn_display':  en.get('asn_display',  ''),
            'city':         en.get('city',         ''),
        })

    # Port risk summary
    port_summary = []
    port_counts  = defaultdict(int)
    for sn in sessions:
        port_counts[sn['dest_port']] += 1
    for port, cnt in sorted(port_counts.items(), key=lambda x: -x[1]):
        pr = PORT_RISK.get(port)
        port_summary.append({
            'port':   port,
            'count':  cnt,
            'svc':    pr[0] if pr else f'Port-{port}',
            'risk':   pr[1] if pr else 'MEDIUM',
            'note':   pr[2] if pr else 'Unclassified port — identify application before creating rule.',
        })

    return rule_list, src24_list, dest_list, port_summary, rfc_violations, policy_recs


# ── Stats ─────────────────────────────────────────────────────────────────────

def build_loc_breakdown(rule_list):
    """Build the Source Locations tab dataset — rules grouped by location type
    → site → subnet. Uses the actual IPAM field names from the CCD dataset:
      net_type    (CVS-DC, Corporate, Specialty, CVS-CallCenter, COLO, Cloud-Azure, DR, ...)
      routing_dom (Internal-PBM, Internal-HCB, COLO, Cloud-Azure, ...)
      facility    (DataCenter, Corporate, Call-Center, Mail-Order, COLO, Specialty, Cloud, ...)
      heritage    (CVS, AETNA, OMNICARE, CAREMARK, SWITCH, ...)
      location    (Canonical location string from IPAM)
    """
    from collections import defaultdict

    # Map net_type → display type (primary key — always present in the blob)
    NET_TYPE_MAP = {
        'CVS-DC':           'CVS-DC',
        'AETNA-DC':         'AETNA-DC',
        'DR':               'CVS-DC',          # disaster-recovery = DC-class
        'COLO':             'COLO',
        'Corporate':        'Corporate',
        'Specialty':        'Specialty',
        'CarePlus':         'Specialty',
        'Coram':            'Specialty',
        'CVS-CallCenter':   'Call-Center',
        'AETNA-CallCenter': 'Call-Center',
        'Mail-Order':       'Mail-Order',
        'Cloud-Azure':      'Cloud',
        'Cloud-AWS':        'Cloud',
        'Cloud-GCP':        'Cloud',
        'Retail':           'Retail',
        'Distribution':     'Corporate',
    }
    # Facility values used as fallback when net_type is absent or unmapped
    FACILITY_MAP = {
        'DataCenter':  None,   # resolved via routing_dom / heritage below
        'Datacenter':  None,
        'COLO':        'COLO',
        'Corporate':   'Corporate',
        'Call-Center': 'Call-Center',
        'Mail-Order':  'Mail-Order',
        'Specialty':   'Specialty',
        'Coram':       'Specialty',
        'Omnicare':    'Specialty',
        'CarePlus':    'Specialty',
        'Cloud':       'Cloud',
    }

    def get_loc_type(ipam_blob):
        if not ipam_blob:
            return 'Unknown'
        net_type    = (ipam_blob.get('net_type','')    or '').strip()
        routing_dom = (ipam_blob.get('routing_dom','') or '').strip()
        facility    = (ipam_blob.get('facility','')    or '').strip()
        heritage    = (ipam_blob.get('heritage','')    or '').strip().upper()
        location    = (ipam_blob.get('location','')    or '').strip()

        # 1. net_type is the most reliable — use it first
        if net_type in NET_TYPE_MAP:
            return NET_TYPE_MAP[net_type]

        # 2. For DataCenter facility, use routing_dom / heritage to split CVS vs Aetna
        if facility in ('DataCenter', 'Datacenter'):
            if routing_dom == 'Internal-HCB' or 'AETNA' in heritage:
                return 'AETNA-DC'
            return 'CVS-DC'

        # 3. Cloud routing domains
        if routing_dom.startswith('Cloud-'):
            return 'Cloud'

        # 4. COLO routing domain
        if routing_dom == 'COLO':
            return 'COLO'

        # 5. Facility fallback
        if facility in FACILITY_MAP:
            result = FACILITY_MAP[facility]
            if result:
                return result

        # 6. Location-string hints
        loc_lower = location.lower()
        if any(x in loc_lower for x in ('shea dc', 'shea', 'ri one', 'ri-one', '2100 highland',
                                          'mdc', 'middletown', 'windsor', 'datacenter')):
            if routing_dom == 'Internal-HCB' or 'AETNA' in heritage:
                return 'AETNA-DC'
            return 'CVS-DC'
        if 'switch' in loc_lower or 'colo' in loc_lower:
            return 'COLO'
        if 'retail' in loc_lower:
            return 'Retail'
        if 'cloud' in loc_lower or 'azure' in loc_lower or 'aws' in loc_lower:
            return 'Cloud'

        return 'Unknown'

    # Aggregate: type → site → per-subnet stats
    type_data = defaultdict(lambda: defaultdict(lambda: {
        'rules': 0, 'sessions': 0, 'src_ips': set(),
        'review': 0, 'pci_rules': 0,
        'hosts_with_name': 0, 'hosts_total': 0, 'cidr': '',
    }))

    for r in rule_list:
        ipam  = r.get('ipam') or {}
        cidr  = r.get('src24') or ''

        # Empty IPAM blob = subnet not registered in all_IP_networks.
        # Also check for the explicit unregistered sentinel (used when this
        # function is called after compaction with lookup-table blobs).
        # These are treated as their own type ('Unregistered') and each
        # gets its own site entry keyed by CIDR so they're individually
        # visible in the Source Locations tab — not collapsed into one
        # anonymous 'Unknown' bucket.
        if not ipam or ipam.get('unregistered'):
            ltype = 'Unregistered'
            site  = cidr or 'Unknown CIDR'
        elif ipam.get('ht_inferred'):
            # Location inferred from hostname translation — treat like registered
            # but flag the type so the UI can distinguish it from ground-truth data.
            ltype = get_loc_type(ipam) or 'HT-Inferred'
            site  = (ipam.get('location') or '').strip() or 'Unknown (HT)'
        else:
            ltype = get_loc_type(ipam)
            site  = (ipam.get('location') or ipam.get('site') or '').strip() or 'Unknown'

        pci   = str(ipam.get('pci') or '').upper()
        is_pci = 'PCI' in pci and 'NON' not in pci

        sd = type_data[ltype][site]
        sd['rules']    += 1
        sd['sessions'] += r.get('count', 0)
        src = r.get('src_ip') or ''
        if src: sd['src_ips'].add(src)
        if r.get('action') == 'REVIEW': sd['review'] += 1
        if is_pci: sd['pci_rules'] += 1
        sd['cidr'] = sd['cidr'] or cidr

        # Per-host tracking for hostname coverage %
        if r.get('hostname'):
            sd['hosts_with_name'] += 1
        if r.get('src_ip'):
            sd['hosts_total'] += 1

        # Include collapsed hosts
        for h in (r.get('collapsed_hosts') or []):
            ip = h.get('ip', '')
            if ip: sd['src_ips'].add(ip)
            if h.get('hostname'): sd['hosts_with_name'] += 1
            if ip: sd['hosts_total'] += 1

    result = []
    for ltype, sites in type_data.items():
        sites_list = []
        t_rules = t_sessions = t_src_ips = t_review = t_pci = t_hn_n = t_hn_d = 0
        for site, sd in sorted(sites.items(), key=lambda x: -x[1]['rules']):
            hn_pct = round(100 * sd['hosts_with_name'] / max(sd['hosts_total'], 1))
            sites_list.append({
                'site':     site,
                'rules':    sd['rules'],
                'sessions': sd['sessions'],
                'src_ips':  len(sd['src_ips']),
                'review':   sd['review'],
                'pci_rules':sd['pci_rules'],
                'hn_pct':   hn_pct,
                'subnets':  [{'cidr': sd['cidr']}] if sd['cidr'] else [],
            })
            t_rules    += sd['rules']
            t_sessions += sd['sessions']
            t_src_ips  += len(sd['src_ips'])
            t_review   += sd['review']
            t_pci      += sd['pci_rules']
            t_hn_n     += sd['hosts_with_name']
            t_hn_d     += sd['hosts_total']

        result.append({
            'type':       ltype,
            'sites':      len(sites_list),
            'rules':      t_rules,
            'sessions':   t_sessions,
            'src_ips':    t_src_ips,
            'review':     t_review,
            'pci_rules':  t_pci,
            'hn_pct':     round(100 * t_hn_n / max(t_hn_d, 1)),
            'sites_data': sites_list,
        })

    result.sort(key=lambda x: -x['rules'])
    return result


def compute_stats(sessions, rule_list, src24_list, dest_list, funnel=None):
    action_counts = defaultdict(int)
    risk_counts   = defaultdict(int)
    for r in rule_list:
        action_counts[r['action']] += 1
        risk_counts[r['risk']]     += 1

    pci_src = sum(1 for s in src24_list if s['pci'] and 'PCI' in s['pci'])

    return {
        'total_sessions':   len(sessions),
        'total_rules':      len(rule_list),
        'n_block':          action_counts.get('BLOCK',   0),
        'n_review':         action_counts.get('REVIEW',  0),
        'n_monitor':        action_counts.get('MONITOR', 0),
        'n_allow':          action_counts.get('ALLOW',   0),
        'n_critical':       risk_counts.get('CRITICAL',  0),
        'n_high':           risk_counts.get('HIGH',      0),
        'n_medium':         risk_counts.get('MEDIUM',    0),
        'n_low':            risk_counts.get('LOW',       0),
        'n_src24':          len(src24_list),
        'n_dest':           len(dest_list),
        'n_pci_src':        pci_src,
        'generated_utc':    datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'script_version':   VERSION,
        'funnel_total':     funnel.get('total', 0) if funnel else len(sessions),
        'funnel_log_files': funnel.get('log_files', []) if funnel else [],
    }


# ── Key findings ──────────────────────────────────────────────────────────────

def build_findings(rule_list, src24_list, dest_list, sessions):
    findings = []

    # Count BLOCK rules by service
    block_rules = [r for r in rule_list if r['action'] == 'BLOCK']
    if block_rules:
        ports_blocked = sorted(set(r['dest_port'] for r in block_rules))
        svcs = sorted(set(r['svc'] for r in block_rules))
        findings.append({
            'level': 'crit',
            'icon':  '🚫',
            'filter': 'block',
            'title': f'{len(block_rules)} Rule(s) Recommended for BLOCK',
            'detail': f'Critical-risk traffic on ports {", ".join(str(p) for p in ports_blocked[:8])}. '
                      f'Services: {", ".join(svcs[:5])}. These sessions should be blocked at the perimeter immediately.',
        })

    # PCI source subnets initiating outbound
    pci_srcs = [s for s in src24_list if s['pci'] and 'PCI' in s['pci']]
    if pci_srcs:
        findings.append({
            'level': 'crit',
            'icon':  '💳',
            'filter': 'pci',
            'title': f'{len(pci_srcs)} PCI-Scoped Source Subnet(s) with Outbound Non-Standard Traffic',
            'detail': f'Subnets: {", ".join(s["cidr"] for s in pci_srcs[:5])}. '
                      f'PCI-DSS requires strict outbound controls. Each session from these subnets must be individually justified.',
        })

    # Unknown destinations
    unknown_dests = [d for d in dest_list if d['ds_class'] == 'UNKNOWN']
    if unknown_dests:
        total_sessions_to_unknown = sum(d['count'] for d in unknown_dests)
        findings.append({
            'level': 'high',
            'icon':  '❓',
            'filter': 'unknown',
            'title': f'{len(unknown_dests)} Destination IPs Not in Any Known Provider Dataset',
            'detail': f'{total_sessions_to_unknown:,} sessions to {len(unknown_dests)} IPs with no AWS, Azure, GCP or CrowdStrike match. '
                      f'These destinations require manual investigation before firewall rules can be created.',
        })

    # High-volume single destination
    if dest_list:
        top_dest = dest_list[0]
        if top_dest['count'] > 50:
            findings.append({
                'level': 'high',
                'icon':  '📡',
                'filter': 'all',
                'title': f'High-Volume Destination: {top_dest["ip"]} ({top_dest["count"]:,} sessions)',
                'detail': f'Provider: {top_dest["provider"]} | Service: {top_dest["service"] or "Unknown"} | '
                          f'Region: {top_dest["region"] or "Unknown"}. '
                          f'Ports: {", ".join(str(p) for p in top_dest["ports"][:6])}. '
                          f'Verify this is expected traffic and create a named rule.',
            })

    # RST from server — services actively refusing
    rst_rules = [r for r in rule_list if 'tcp-rst-from-server' in r['end_reasons']]
    if rst_rules:
        findings.append({
            'level': 'med',
            'icon':  '🔄',
            'filter': 'rst',
            'title': f'{len(rst_rules)} Rule(s) Where Server Actively Reset the Connection',
            'detail': f'TCP-RST-from-server means data was exchanged but the service rejected the session. '
                      f'This may indicate connection attempts to services that blocked the source. Investigate misconfiguration or scanning.',
        })

    # Aged-out with high packets
    aged_big = [r for r in rule_list if 'aged-out' in r['end_reasons'] and r['total_pkts'] > 100]
    if aged_big:
        findings.append({
            'level': 'med',
            'icon':  '⏱',
            'filter': 'aged',
            'title': f'{len(aged_big)} Long-Running Session(s) That Timed Out Without Close',
            'detail': f'Sessions with >100 packets that were aged-out rather than cleanly closed. '
                      f'These may be persistent connections to long-poll or streaming services. Adjust idle timeout policy or create stateful allow rules.',
        })

    # REVIEW rules
    review_rules = [r for r in rule_list if r['action'] == 'REVIEW']
    if review_rules:
        findings.append({
            'level': 'med',
            'icon':  '🔍',
            'filter': 'review',
            'title': f'{len(review_rules)} Rule(s) Require Security Review Before Allowing',
            'detail': f'Ports: {", ".join(sorted(set(str(r["dest_port"]) for r in review_rules))[:8])}. '
                      f'These sessions reached external destinations on sensitive ports. Each requires documented business justification.',
        })

    # Provider breakdown
    providers_seen = defaultdict(int)
    for d in dest_list:
        if d['ds_class'] != 'UNKNOWN':
            providers_seen[d['provider']] += d['count']
    if providers_seen:
        top_prov = sorted(providers_seen.items(), key=lambda x: -x[1])[:3]
        findings.append({
            'level': 'low',
            'icon':  '☁',
            'filter': 'cloud',
            'title': f'Traffic to {len(providers_seen)} Known Cloud/SaaS Provider(s)',
            'detail': 'Top: ' + ', '.join(f'{p} ({c:,} sessions)' for p, c in top_prov) + '. '
                      'These destinations are identifiable — create named application-layer rules rather than generic port allows.',
        })

    return findings


# ── HTML template ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>%%TITLE%%</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0a0f1a;color:#c8d8e8;min-height:100vh;display:flex;flex-direction:column}
/* Nav */
#nav{background:#0d1526;border-bottom:2px solid #1a2a3a;padding:0 14px;display:flex;align-items:center;gap:2px;flex-shrink:0;position:sticky;top:0;z-index:100}
#nav h1{font-size:13px;font-weight:700;color:#e8f0f8;padding:10px 14px 10px 0;border-right:1px solid #1a3a5a;margin-right:8px;white-space:nowrap}
.nb{background:none;border:none;color:#6888a8;font-size:11px;padding:10px 10px;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;white-space:nowrap;transition:all .15s}
.nb:hover{color:#c8d8e8}.nb.active{color:#4ab8f8;border-bottom-color:#4ab8f8}
/* Stats */
#statsbar{background:#08101c;border-bottom:1px solid #1a2a3a;padding:5px 14px;display:flex;gap:0;flex-shrink:0;flex-wrap:wrap}
.stat{text-align:center;padding:4px 14px;border-right:1px solid #1a2a3a}.stat:last-child{border-right:none}
.stat-val{font-size:17px;font-weight:700}.stat-lbl{font-size:9px;color:#5a7a9a;text-transform:uppercase;letter-spacing:.5px;margin-top:1px}
.sv-crit{color:#ff4444}.sv-high{color:#ff8833}.sv-med{color:#ffcc33}.sv-low{color:#44cc44}.sv-blue{color:#44aaff}.sv-wht{color:#c8d8e8}
/* Sections */
.section{padding:18px 16px;border-bottom:1px solid #0f1e2e;max-width:1400px;width:100%;display:none}
.section.active{display:block}
.section h2{font-size:13px;font-weight:700;color:#8aaacf;text-transform:uppercase;letter-spacing:.8px;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.cnt-badge{font-size:11px;color:#4ab;background:#0a1a2a;padding:1px 7px;border-radius:8px;font-weight:400;letter-spacing:0}
/* Findings */
.findings-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px}
.finding-card{background:#0d1a2e;border:1px solid #1a2a3a;border-radius:6px;padding:12px;display:flex;gap:10px;align-items:flex-start}
.finding-card.crit{border-left:3px solid #ff4444}.finding-card.high{border-left:3px solid #ff8833}
.finding-card.med{border-left:3px solid #ffcc33}.finding-card.low{border-left:3px solid #44cc44}
.finding-icon{font-size:18px;flex-shrink:0}.finding-title{font-size:12px;font-weight:600;color:#e8f0f8;margin-bottom:4px}
.finding-detail{font-size:11px;color:#6888a8;line-height:1.5}
/* Controls */
#rule-controls{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.filter-pill{font-size:11px;padding:3px 10px;border-radius:12px;border:1px solid #2a3a4a;background:none;color:#8aa8c8;cursor:pointer;transition:all .15s}
.filter-pill.active{background:#1a3a5a;border-color:#3a6a9a;color:#8ad0f8}
#rule-search{padding:4px 10px;background:#08101c;border:1px solid #1a2a3a;color:#c8d8e8;font-size:11px;border-radius:4px;outline:none;width:240px}
#rule-search::placeholder{color:#3a5a7a}
/* Rule cards */
.rules-list{display:flex;flex-direction:column;gap:8px}
.rule-card{background:#0d1a2e;border:1px solid #1a2a3a;border-radius:6px;overflow:hidden;cursor:pointer;transition:border-color .15s}
.rule-card:hover{border-color:#2a4a6a}.rule-card.expanded{border-color:#3a6a9a}
.rule-head{display:flex;flex-direction:column;padding:0}
.rh-top{display:flex;align-items:center;padding:9px 12px;gap:10px}
.rh-ids{display:flex;align-items:center;gap:0;padding:0 12px 8px;flex-wrap:wrap}
.action-badge{font-size:10px;font-weight:700;padding:3px 9px;border-radius:3px;letter-spacing:.5px;flex-shrink:0;min-width:68px;text-align:center}
.ab-BLOCK{background:#5a0a0a;color:#ff8888}.ab-REVIEW{background:#4a2a00;color:#ffaa55}
.ab-MONITOR{background:#3a3a00;color:#ffdd55}.ab-ALLOW{background:#0a3a0a;color:#55cc55}
.risk-badge{font-size:9px;padding:1px 5px;border-radius:3px;font-weight:700;flex-shrink:0}
.rb-CRITICAL{background:#4a0a0a;color:#ff6a6a}.rb-HIGH{background:#4a2a00;color:#ffaa4a}
.rb-MEDIUM{background:#3a3a00;color:#ffdd4a}.rb-LOW{background:#0a3a0a;color:#4aaa4a}
.rule-port{font-size:14px;font-weight:700;font-family:'Courier New',monospace;color:#c8d8e8;min-width:55px}
.rule-svc{font-size:11px;color:#8aa8c8;min-width:90px}
.rule-flow{font-size:10px;color:#6888a8;flex:1;font-family:'Courier New',monospace}
.rule-dest-info{font-size:10px;color:#5a9a5a;min-width:100px;text-align:right}
.rule-cnt{font-size:11px;font-family:'Courier New',monospace;color:#4a9a8a;min-width:55px;text-align:right}
.risk-bar{height:3px}
.rb-crit{background:#ff4444}.rb-high{background:#ff8833}.rb-med{background:#ffcc33}.rb-low{background:#44cc44}
/* Identity row fields */
.id-field{display:flex;flex-direction:column;padding:0 14px 0 0;border-right:1px solid #1a2a3a;margin-right:14px;min-width:0}
.id-field:last-child{border-right:none;margin-right:0}
.id-lbl{font-size:8px;color:#3a5a7a;text-transform:uppercase;letter-spacing:.6px;font-weight:700;margin-bottom:2px;white-space:nowrap}
.id-val{font-size:10px;color:#a8c8e8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px;font-family:'Courier New',monospace}
.id-val.host{color:#79c0ff;max-width:260px}
.id-val.app{color:#c8a8e8;font-family:'Segoe UI',sans-serif;max-width:200px}
.id-val.apm{color:#4a9a8a;max-width:140px}
.id-val.dest-app{color:#5a9a5a;font-family:'Segoe UI',sans-serif;max-width:180px}
.id-val.none{color:#3a5a7a;font-family:'Segoe UI',sans-serif;font-style:italic}
.id-val.bu{color:#c8a060;max-width:180px}.id-val.site{color:#60a8c8;max-width:200px}
.id-val.heritage{color:#9a70c8;max-width:120px}.id-val.env{color:#70c870;max-width:100px}
.dsrc-badge{font-size:8px;padding:1px 5px;border-radius:3px;font-weight:700;margin-right:3px}
.dsrc-snow{background:#0d2a4a;color:#60a8f8}.dsrc-ql{background:#1a2a0a;color:#70c840}
.dsrc-wiz{background:#2a0a2a;color:#c870f8}.dsrc-adl{background:#2a1a0a;color:#f8a040}
.hbadge{font-size:8px;padding:1px 5px;border-radius:3px;font-weight:700}
.hb-cvs{background:#0a2a4a;color:#4ab0f8}.hb-aetna{background:#2a1a0a;color:#f8a840}
.hb-hcb{background:#1a0a2a;color:#c880f8}
.src-host-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:4px}
.shg-field{display:flex;flex-direction:column;gap:2px}
.shg-label{font-size:8px;color:#3a5a7a;text-transform:uppercase;letter-spacing:.5px;font-weight:700}
.shg-val{font-size:10px;color:#a8c8e8;font-family:'Courier New',monospace;word-break:break-all}
/* Rule body */
.rule-body{display:none;padding:14px;border-top:1px solid #1a2a3a;background:#08101c}
.rule-body.open{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.rb-section{margin-bottom:12px}
.rb-label{font-size:9px;color:#5a7a9a;text-transform:uppercase;letter-spacing:.6px;font-weight:700;margin-bottom:8px}
.rb-rec{font-size:11px;color:#a8c8a8;margin-bottom:10px;padding:7px 10px;background:#0a1a0a;border-left:3px solid #3a7a3a;border-radius:0 3px 3px 0;line-height:1.5}
/* Rule spec */
.rule-spec{font-family:'Courier New',monospace;font-size:11px;background:#061018;border:1px solid #1a2a3a;border-radius:4px;padding:10px;margin-bottom:10px;line-height:1.8;white-space:pre}
.rs-action{font-weight:700}.rs-allow{color:#44cc44}.rs-block{color:#ff4444}.rs-review{color:#ffaa33}.rs-monitor{color:#ffdd33}
.rs-field{color:#5a9acf}.rs-val{color:#c8d8e8}.rs-comment{color:#3a5a7a}
/* Source chips */
.src-chip{background:#0d1526;border:1px solid #1a2a3a;border-radius:4px;padding:5px 8px;margin-bottom:5px;font-size:10px}
.sc-cidr{font-family:'Courier New',monospace;color:#a8c8f8;font-size:11px;font-weight:600}
.sc-meta{color:#6888a8;margin-top:2px;line-height:1.4}
.sc-compliance{font-size:9px;padding:1px 4px;border-radius:2px;margin-left:3px;font-weight:700}
.sc-pci{background:#4a1a00;color:#ff8a4a}.sc-hipaa{background:#1a004a;color:#8a8aff}.sc-sox{background:#2a1a00;color:#ffcc44}
/* Dest chips */
.dest-chip{display:flex;justify-content:space-between;padding:3px 0;font-family:'Courier New',monospace;font-size:10px;color:#a8d8a8;border-bottom:1px solid #0f1e2e}
.dc-provider{color:#6888a8;font-family:'Segoe UI',sans-serif}
/* Port table */
.port-table{width:100%;border-collapse:collapse;font-size:11px}
.port-table th{color:#5a7a9a;font-weight:600;text-align:left;padding:6px 10px;border-bottom:2px solid #1a2a3a;font-size:10px;text-transform:uppercase;letter-spacing:.4px}
.port-table td{padding:7px 10px;border-bottom:1px solid #0f1e2e;vertical-align:top}
.port-table tr:hover td{background:#0d1a2e}
.port-num{font-family:'Courier New',monospace;font-size:13px;font-weight:700}
.port-note{font-size:10px;color:#6888a8;margin-top:2px}
.port-bar-wrap{background:#0a1420;border-radius:3px;height:6px;margin-top:4px;width:120px}
.port-bar-fill{height:6px;border-radius:3px}
/* Src24 table */
.src-table{width:100%;border-collapse:collapse;font-size:10px}
.src-table th{color:#5a7a9a;font-weight:600;text-align:left;padding:5px 8px;border-bottom:2px solid #1a2a3a;font-size:9px;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
.src-table td{padding:5px 8px;border-bottom:1px solid #0f1e2e;vertical-align:middle}
.src-table tr:hover td{background:#0d1a2e;cursor:pointer}
.mono{font-family:'Courier New',monospace}
.port-pill{display:inline-block;font-size:9px;font-family:'Courier New',monospace;padding:1px 4px;border-radius:3px;margin:1px;background:#1a2a3a}
/* Dest table */
.dest-table{width:100%;border-collapse:collapse;font-size:11px}
.dest-table th{color:#5a7a9a;font-weight:600;text-align:left;padding:5px 8px;border-bottom:2px solid #1a2a3a;font-size:9px;text-transform:uppercase;letter-spacing:.4px}
.dest-table td{padding:5px 8px;border-bottom:1px solid #0f1e2e}
.dest-table tr:hover td{background:#0d1a2e}
.provider-badge{font-size:9px;padding:1px 5px;border-radius:3px;font-weight:600}
.pb-aws{background:#1a2a00;color:#88cc44}.pb-azure{background:#001a3a;color:#4488ff}
.pb-gcp{background:#001a1a;color:#44cccc}.pb-cs{background:#1a0a2a;color:#cc88ff}
.pb-isp{background:#1a1a2a;color:#88aaff}.pb-transit{background:#0a1a2a;color:#44aacc}
.pb-corp{background:#1a1a0a;color:#aaaa44}.pb-unk{background:#1a1a1a;color:#888888}

/* ── Session Lifecycle Summary Frame ── */
#funnel-frame{background:#0d1526;border:1px solid #1a2a3a;border-radius:8px;padding:16px 20px;margin-bottom:18px}
#funnel-frame h3{font-size:11px;font-weight:700;color:#8aaacf;text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px}
.funnel-desc{font-size:12px;color:#a8c8e8;line-height:1.7;margin-bottom:14px;padding:10px 14px;background:#08101c;border-radius:5px;border-left:3px solid #2a5a8a}
.funnel-desc b{color:#e8f0f8}
.funnel-stages{display:flex;align-items:stretch;gap:0;border:1px solid #1a2a3a;border-radius:6px;overflow:hidden;margin-bottom:10px}
.funnel-stage{flex:1;padding:10px 8px;text-align:center;border-right:1px solid #1a2a3a;position:relative;transition:background .15s;min-width:0}
.funnel-stage:last-child{border-right:none}
.funnel-stage:hover{background:#0f1e2e}
.fs-n{font-size:18px;font-weight:700;font-family:'Courier New',monospace;line-height:1.1}
.fs-pct{font-size:10px;color:#8b949e;margin-top:1px}
.fs-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.5px;margin-top:5px;color:#6888a8;line-height:1.3}
.fs-icon{font-size:14px;margin-bottom:3px}
.fs-arrow{font-size:16px;color:#2a3a4a;align-self:center;flex:0;padding:0 4px}
.funnel-close{display:flex;gap:10px;margin-top:8px;flex-wrap:wrap}
.fc-pill{display:flex;align-items:center;gap:5px;background:#08101c;border:1px solid #1a2a3a;border-radius:4px;padding:5px 10px;font-size:11px}
.fc-pill b{font-family:'Courier New',monospace}
.funnel-note{font-size:10px;color:#3a5a7a;margin-top:8px;font-style:italic}


/* ── Source IP grouped view ── */
.subnet-group{background:#0d1526;border:1px solid #1a2a3a;border-radius:6px;margin-bottom:8px;overflow:hidden}
.sg-header{display:flex;align-items:center;gap:10px;padding:8px 12px;cursor:pointer;transition:background .12s}
.sg-header:hover{background:#0f1e2e}
.sg-cidr{font-family:'Courier New',monospace;font-size:12px;font-weight:700;color:#a8c8f8}
.sg-site{font-size:10px;color:#6888a8;flex:1}
.sg-meta{font-size:10px;color:#4a9a8a;white-space:nowrap}
.sg-toggle{color:#3a5a7a;font-size:11px;flex-shrink:0;transition:transform .2s}
.sg-toggle.open{transform:rotate(90deg)}
.sg-ips{display:none;border-top:1px solid #1a2a3a}
.sg-ips.open{display:block}
.ip-row{display:flex;align-items:flex-start;gap:10px;padding:7px 14px;border-bottom:1px solid #0f1e2e;font-size:11px}
.ip-row:last-child{border-bottom:none}
.ip-row:hover{background:#0a1420}
.ip-addr{font-family:'Courier New',monospace;color:#79c0ff;min-width:120px;flex-shrink:0;font-size:11px;font-weight:600}
.ip-host{color:#a8c8e8;min-width:220px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ip-no-host{color:#3a5a7a;font-style:italic}
.ip-os{color:#6888a8;min-width:80px;flex-shrink:0}
.ip-app{color:#8888a8;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ip-env{font-size:9px;padding:1px 4px;border-radius:3px;background:#1a2a3a;color:#6888a8;flex-shrink:0}
.ip-csna{font-size:9px;font-family:'Courier New',monospace;color:#3a7a3a;display:block;margin-top:1px}


/* ── Log Event Modal ── */
#modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:500;align-items:center;justify-content:center}
#modal-overlay.open{display:flex}
#modal-box{background:#0d1526;border:1px solid #2a4a6a;border-radius:8px;width:92vw;max-width:1100px;max-height:88vh;display:flex;flex-direction:column;box-shadow:0 8px 40px rgba(0,0,0,.7)}
#modal-head{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid #1a2a3a;flex-shrink:0}
#modal-title{font-size:13px;font-weight:700;color:#e8f0f8;flex:1}
#modal-sub{font-size:11px;color:#6888a8}
#modal-close{background:none;border:none;color:#6888a8;font-size:18px;cursor:pointer;padding:0 4px;line-height:1}
#modal-close:hover{color:#e8f0f8}
#modal-body{overflow-y:auto;padding:12px 16px;flex:1}
#modal-body::-webkit-scrollbar{width:5px}
#modal-body::-webkit-scrollbar-thumb{background:#2a3a4a}
.log-table{width:100%;border-collapse:collapse;font-size:11px}
.log-table th{color:#5a7a9a;font-weight:600;text-align:left;padding:6px 10px;border-bottom:2px solid #1a2a3a;font-size:9px;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap;position:sticky;top:0;background:#0d1526}
.log-table td{padding:6px 10px;border-bottom:1px solid #0f1e2e;vertical-align:top}
.log-table tr:hover td{background:#0d2040}
/* Location breakdown */
.loc-type-row{background:#0d1a2e;cursor:pointer;transition:background .15s}
.loc-type-row:hover{background:#112030}
.loc-type-cell{font-size:12px;font-weight:700;padding:10px 12px;color:#e8f0f8}
.loc-site-row{background:#080f1a;display:none}
.loc-site-row.open{display:table-row}
.loc-site-cell{padding:7px 12px 7px 28px;font-size:11px;color:#8aaacf;border-bottom:1px solid #0d1a2a}
.loc-subnet-row{background:#060c14;display:none}
.loc-subnet-row.open{display:table-row}
.loc-subnet-cell{padding:5px 12px 5px 48px;font-size:10px;color:#5a7a9a;font-family:'Courier New',monospace;border-bottom:1px solid #080e18}
.loc-table{width:100%;border-collapse:collapse}
.loc-table th{color:#4a6a8a;font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:.5px;padding:7px 12px;border-bottom:2px solid #1a2a3a;white-space:nowrap;text-align:right}
.loc-table th:first-child{text-align:left}
.loc-table td{text-align:right;padding:6px 12px;border-bottom:1px solid #0a1520}
.loc-table td:first-child{text-align:left}
.hn-bar{display:inline-block;height:6px;border-radius:3px;vertical-align:middle;margin-right:4px}
.lt-badge{display:inline-block;font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;letter-spacing:.4px;margin-right:6px}
.lt-cvs-dc{background:#0a2a4a;color:#4ab8f8}.lt-aetna-dc{background:#1a1a4a;color:#8888ff}
.lt-colo{background:#1a2a1a;color:#44cc88}.lt-corporate{background:#1a1a1a;color:#8a9aaa}
.lt-mail-order{background:#2a1a0a;color:#cc8844}.lt-call-center{background:#0a2a2a;color:#44aaaa}
.lt-specialty{background:#2a0a2a;color:#cc44cc}.lt-hcb{background:#0a1a2a;color:#4488cc}
.lt-retail{background:#2a2a0a;color:#cccc44}.lt-cloud{background:#0a2a1a;color:#44cc66}
.lt-offshore{background:#2a1a1a;color:#cc6644}.lt-remote{background:#1a1a2a;color:#8844cc}
.lt-unknown{background:#1a1a1a;color:#6a7a8a}
.lt-unregistered{background:#2a1500;color:#ff8833}
.hn-good{color:#44cc88}.hn-med{color:#ffcc33}.hn-poor{color:#ff6644}
.lt-ip{font-family:'Courier New',monospace;color:#79c0ff;white-space:nowrap}
.lt-dest{font-family:'Courier New',monospace;color:#a8d8a8;white-space:nowrap}
.lt-host{color:#a8c8e8;font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lt-app-name{color:#c8a8e8;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lt-pkts{font-family:'Courier New',monospace;color:#4a9a8a;text-align:right}
.lt-end{font-size:10px;white-space:nowrap}
.lt-provider{font-size:10px;color:#5a9a5a;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lt-action{font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;white-space:nowrap}
.end-fin{color:#44cc44}.end-rst{color:#ff8833}.end-aged{color:#6888a8}
.modal-empty{color:#4a6a8a;font-size:12px;padding:20px;text-align:center}


/* ── Flow Map ── */
#flow-canvas{cursor:crosshair}
.flow-tooltip{position:fixed;background:#0d1526;border:1px solid #2a4a6a;border-radius:5px;padding:8px 12px;font-size:11px;color:#c8d8e8;pointer-events:none;z-index:300;display:none;max-width:260px;box-shadow:0 4px 16px rgba(0,0,0,.5)}

/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-thumb{background:#2a3a4a}
</style>
</head>
<body>
<div id="nav">
  <h1>🛡 PA Firewall — Rule Recommendations</h1>
  <button class="nb active" onclick="navTo('sec-findings',this)">🔍 Key Findings</button>
  <button class="nb" onclick="navTo('sec-rules',this)">📋 Rule Candidates</button>
  <button class="nb" onclick="navTo('sec-ports',this)">⚠ Port Risk</button>
  <button class="nb" onclick="navTo('sec-src',this)">🖥 Source IPs</button>
  <button class="nb" onclick="navTo('sec-loc',this)">🏢 Source Locations</button>
  <button class="nb" onclick="navTo('sec-dests',this)">📡 Destinations</button>
  <button class="nb" onclick="navTo('sec-flow',this)">🗺 Flow Map</button>
  <button class="nb" onclick="navTo('sec-rfc',this)">⛔ RFC Violations</button>
  <button class="nb" onclick="navTo('sec-policy',this)">📐 Optimized Policy</button>
</div>
<div id="statsbar">
  <div class="stat"><div class="stat-val sv-wht" id="st-sess">—</div><div class="stat-lbl">Sessions</div></div>
  <div class="stat"><div class="stat-val sv-wht" id="st-rules">—</div><div class="stat-lbl">Rule Candidates</div></div>
  <div class="stat"><div class="stat-val sv-crit" id="st-block">—</div><div class="stat-lbl">BLOCK</div></div>
  <div class="stat"><div class="stat-val sv-high" id="st-review">—</div><div class="stat-lbl">REVIEW</div></div>
  <div class="stat"><div class="stat-val sv-med" id="st-monitor">—</div><div class="stat-lbl">MONITOR</div></div>
  <div class="stat"><div class="stat-val sv-low" id="st-allow">—</div><div class="stat-lbl">ALLOW</div></div>
  <div class="stat"><div class="stat-val sv-crit" id="st-crit">—</div><div class="stat-lbl">Critical Ports</div></div>
  <div class="stat"><div class="stat-val sv-high" id="st-high">—</div><div class="stat-lbl">High Risk</div></div>
  <div class="stat"><div class="stat-val sv-blue" id="st-src24">—</div><div class="stat-lbl">Src /24s</div></div>
  <div class="stat"><div class="stat-val sv-blue" id="st-dests">—</div><div class="stat-lbl">Dest IPs</div></div>
  <div class="stat"><div class="stat-val sv-crit" id="st-rfc">—</div><div class="stat-lbl">RFC Violations</div></div>
</div>

<!-- ── Key Findings ── -->
<div class="section active" id="sec-findings">
  <h2>🔍 Key Findings</h2>
  <div id="funnel-frame">
    <h3>📊 Session Lifecycle Analysis</h3>
    <div class="funnel-desc" id="funnel-desc">Loading…</div>
    <div class="funnel-stages" id="funnel-stages"></div>
    <div class="funnel-close" id="funnel-close"></div>
    <div class="funnel-note" id="funnel-note"></div>
  </div>
  <div class="findings-grid" id="findings-grid"></div>
  <div style="margin-top:20px;padding:12px;background:#0d1a2e;border-radius:6px;border-left:3px solid #2a5a8a;font-size:11px;color:#6888a8">
    <b style="color:#8aaacf">Methodology:</b> Sessions filtered to established connections (total packets &gt; %%MIN_PKTS%%).
    Source IPs enriched from all_IP_networks (v4.0 SSOT). Destination IPs enriched via longest-prefix-match
    against AWS, Azure, Google Cloud and CrowdStrike IP datasets. Rule logic: <code style="color:#a8c8f8">
    SRC_IP (&gt;1024) → DEST_IP:DEST_PORT</code>. Firewall: <code style="color:#a8c8f8">%%DVC%%</code>.
    Generated: <code style="color:#a8c8f8">%%GENERATED%%</code>.
  </div>
</div>

<!-- ── Rule Candidates ── -->
<div class="section" id="sec-rules">
  <h2>📋 Rule Candidates <span class="cnt-badge" id="rules-cnt"></span></h2>
  <div id="rule-controls">
    <button class="filter-pill active" data-action="">All</button>
    <button class="filter-pill" data-action="BLOCK">🚫 BLOCK</button>
    <button class="filter-pill" data-action="REVIEW">🔍 REVIEW</button>
    <button class="filter-pill" data-action="MONITOR">👁 MONITOR</button>
    <button class="filter-pill" data-action="ALLOW">✅ ALLOW</button>
    <input id="rule-search" type="text" placeholder="Search port, service, IP, provider…">
  </div>
  <div class="rules-list" id="rules-list"></div>
</div>

<!-- ── Port Risk ── -->
<div class="section" id="sec-ports">
  <h2>⚠ Port Risk Analysis</h2>
  <table class="port-table">
    <thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Sessions</th><th>Volume</th><th>Assessment &amp; Recommendation</th></tr></thead>
    <tbody id="port-tbody"></tbody>
  </table>
</div>

<!-- ── Source /24s ── -->
<div class="section" id="sec-src">
  <h2>🖥 Source IPs — by Subnet <span class="cnt-badge" id="src-cnt"></span>
    <button onclick="downloadUnknownHostsCSV()"
      style="margin-left:12px;background:#0a1a2a;border:1px solid #3a6a9a;color:#8ac0ff;
             font-size:10px;padding:3px 10px;border-radius:3px;cursor:pointer;font-weight:700">
      ⬇ Unknown Hosts CSV
    </button>
  </h2>
  <div id="src-list"></div>
</div>

<!-- ── Source Locations ── -->
<div class="section" id="sec-loc">
  <h2>🏢 Source Traffic — by Location Type <span class="cnt-badge" id="loc-cnt"></span>
    <button id="btn-unreg-csv" onclick="downloadUnregisteredCSV()"
      style="display:none;margin-left:12px;background:#2a1500;border:1px solid #ff8833;color:#ff8833;
             font-size:10px;padding:3px 10px;border-radius:3px;cursor:pointer;font-weight:700">
      ⬇ Unregistered Subnets CSV
    </button>
  </h2>
  <p style="font-size:11px;color:#5a7a9a;margin-bottom:14px">Click a location type to expand sites. Click a site to expand subnets. Hostname coverage % = hosts with reverse-DNS or CMDB record.</p>
  <div id="loc-list"></div>
</div>

<!-- ── Destinations ── -->
<div class="section" id="sec-dests">
  <h2>📡 Destination IPs <span class="cnt-badge" id="dest-cnt"></span></h2>
  <table class="dest-table">
    <thead><tr>
      <th>Dest IP</th><th>Provider / Org</th><th>Service</th>
      <th>Country</th><th>City</th><th>ASN / Org</th>
      <th>Class</th><th>Sessions</th><th>Src /24s</th><th>Ports</th><th>Actions</th>
    </tr></thead>
    <tbody id="dest-tbody"></tbody>
  </table>
</div>

<script type="text/plain" id="D">%%DATA_BLOB%%</script>
<script>
'use strict';
var D=null, curAction='', curRuleSearch='';

function decomp(id){
  var el=document.getElementById(id);
  var b64=el.textContent.trim();
  var raw=atob(b64);
  var bytes=new Uint8Array(raw.length);
  for(var i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
  var ds=new DecompressionStream('gzip');
  var writer=ds.writable.getWriter();
  writer.write(bytes); writer.close();
  return new Response(ds.readable).json();
}

// ── v2.0 helpers: ipam/dest are now in lookup tables to dedupe the payload ──
function getIpam(r){
  if(!r) return {};
  if(!D||!D.ipam_by_src24) return {};
  return D.ipam_by_src24[r.src24||''] || {};
}
function getDest(r){
  if(!r) return {};
  if(!D||!D.dest_by_ip) return {};
  return D.dest_by_ip[r.dest_ip||''] || {};
}

// ── friendlyDest — human-readable "provider + service-type" label ─────────
// Combines provider, svc_type, ds_class, and service into one clear label.
// Examples:  "Akamai CDN"  "Amazon EC2"  "Azure Cloud"  "Cloudflare CDN"
//            "Amazon Network"  "Zscaler Proxy"  "Google CDN"
var _SVCTYPE_LABEL = {
  'CDN':         'CDN',
  'CLOUD-INFRA': 'Cloud',
  'US-NETWORK':  'Network',
  'ISP':         'ISP Range',
  'SOCIAL':      'Social Media',
  'PROXY':       'Proxy',
  'DEVOPS':      'DevOps',
  'EC2':         'EC2',
  'S3':          'S3',
  'CLOUDFRONT':  'CloudFront',
};
var _DSCLASS_LABEL = {
  'IAAS':     'Cloud (IaaS)',
  'SAAS':     'SaaS',
  'CLOUD':    'Cloud',
  'OTHER':    '',
  'EXTERNAL': '',
  'BOGON':    'RFC Violation',
  'INTERNAL': 'Internal',
};
function friendlyDest(destI){
  if(!destI) return 'Unknown';
  var provider  = destI.provider  || '';
  var svcType   = destI.svc_type  || '';
  var dsClass   = destI.ds_class  || '';
  var service   = destI.service   || '';
  var svcLabel  = destI.svc_label || '';

  // Bogon / RFC-violation — show the violation flag as the label
  if(dsClass === 'BOGON') return provider || 'RFC Violation';
  if(dsClass === 'INTERNAL') return provider || 'Internal';

  if(!provider || provider === 'Unknown'){
    return service || svcLabel || dsClass || 'Unknown';
  }

  // Build qualifier: svc_type human label takes priority over ds_class label
  var qualifier = _SVCTYPE_LABEL[svcType] || _DSCLASS_LABEL[dsClass] || '';

  // Specific service name — only append if it adds info beyond the qualifier
  // (skip if it's just a CIDR-range-name like "MONGO-89-192" or "Google-US")
  var svcExtra = '';
  if(service && qualifier === ''){
    // No svc_type matched — surface the service name as a fallback
    svcExtra = service;
  }

  if(qualifier) return provider + ' ' + qualifier;
  if(svcExtra)  return provider + ' (' + svcExtra + ')';
  return provider;
}
// Back-compat: old access patterns (r.ipam / r.dest) throughout the template
// now just call these helpers. After the decomp() resolves we also monkey-patch
// a getter onto each rule so legacy spots keep working without being touched.
function hydrateRules(rules){
  if(!rules) return;
  for(var i=0;i<rules.length;i++){
    var r=rules[i];
    if(!('ipam' in r)){
      Object.defineProperty(r,'ipam',{get:function(){return getIpam(this);},configurable:true});
    }
    if(!('dest' in r)){
      Object.defineProperty(r,'dest',{get:function(){return getDest(this);},configurable:true});
    }
  }
}
function debounce(fn, ms){
  var t=null;
  return function(){
    var args=arguments, ctx=this;
    if(t) clearTimeout(t);
    t=setTimeout(function(){ fn.apply(ctx, args); }, ms);
  };
}

function navTo(id,btn){
  document.querySelectorAll('.section').forEach(function(s){s.classList.remove('active');});
  document.getElementById(id).classList.add('active');
  document.querySelectorAll('.nb').forEach(function(b){b.classList.remove('active');});
  if(btn)btn.classList.add('active');
  if(id==='sec-flow')   renderFlowMap();
  if(id==='sec-rfc')    renderRfcTable();
  if(id==='sec-policy') renderPolicyTable();
  if(id==='sec-loc')    renderLocBreakdown();
}

function fmt(n){
  n=Number(n||0);
  if(n>=1e6)return (n/1e6).toFixed(1)+'M';
  if(n>=1e3)return (n/1e3).toFixed(0)+'K';
  return String(n);
}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function riskColor(r){
  return r==='CRITICAL'?'#ff4444':r==='HIGH'?'#ff8833':r==='MEDIUM'?'#ffcc33':'#44cc44';
}
function riskBarClass(r){
  return r==='CRITICAL'?'rb-crit':r==='HIGH'?'rb-high':r==='MEDIUM'?'rb-med':'rb-low';
}
function providerBadge(p,cls){
  var map={'amazon web services':'pb-aws','aws':'pb-aws','google':'pb-gcp','microsoft azure':'pb-azure','azure':'pb-azure','crowdstrike':'pb-cs'};
  var key=(p||'').toLowerCase();
  var c=map[key]||'';
  if(!c){
    if(cls==='ISP')               c='pb-isp';
    else if(cls==='TRANSIT')      c='pb-transit';
    else if(cls==='OTHER')        c='pb-corp';
    else                          c='pb-unk';
  }
  return '<span class="provider-badge '+c+'">'+esc(p||'Unknown')+'</span>';
}

function compliancePills(src){
  var out='';
  var pci=src.pci||''; var cmp=src.compliance||'';
  if(pci&&pci.indexOf('PCI')>=0) out+='<span class="sc-compliance sc-pci">PCI</span>';
  if(cmp.indexOf('HIPAA')>=0)    out+='<span class="sc-compliance sc-hipaa">HIPAA</span>';
  if(cmp.indexOf('SOX')>=0)      out+='<span class="sc-compliance sc-sox">SOX</span>';
  return out;
}

function ruleSpec(r){
  var act=r.action;
  var actClass='rs-'+act.toLowerCase();
  // v2.0 — collapsed rules have r.src_ip blanked and use r.src24 as the
  // source address (already in CIDR form, e.g. 10.180.64.0/24). Per-host
  // rules still emit /32 for precision.
  var isCollapsed = r.collapsed_n && r.collapsed_n > 1;
  var srcAddrPlain = r.src_ip || r.src24;         // for the comment lines
  var srcAddrSpec  = isCollapsed ? r.src24 : (r.src_ip + '/32');   // for source-address field
  var hostNote = r.hostname ? ' ('+r.hostname+')'
                 : (isCollapsed ? ' ('+r.collapsed_n+' hosts)' : '');
  var buNote   = r.src_bu   ? ' BU:'+r.src_bu : '';
  var siteNote = (r.src_site_name||r.src_dc_name) ? ' '+( r.src_site_name||r.src_dc_name) : '';
  var ipam2 = r.ipam||{};
  var srcZone = ipam2.fw_policy || 'Inside';
  var destProv = (r.dest&&r.dest.provider&&r.dest.provider!=='Unknown') ? '  # '+r.dest.provider+(r.dest.region?' ('+r.dest.region+')':'') : '';
  var destZone = (r.dest&&r.dest.ds_class&&r.dest.ds_class!=='UNKNOWN') ? r.dest.ds_class.toLowerCase()+'-zone' : 'outside';
  var ruleName = act+'-'+r.svc+'-'+(r.src_site_code||srcAddrPlain.replace(/[\.\/]/g,'-'))+'-to-'+r.dest_ip.replace(/\./g,'-')+'-'+r.dest_port;
  var lines=[
    '# '+r.reason,
    '# Src: '+srcAddrPlain+hostNote+(buNote?'  '+buNote:'')+siteNote,
    '# Dst: '+r.dest_ip+(r.dest&&r.dest.provider&&r.dest.provider!=='Unknown'?'  ['+r.dest.provider+(r.dest.service?' / '+r.dest.service:'')+(r.dest.region?' '+r.dest.region:'')+']':''),
    '',
    'policy-rule {',
    '  name            = "'+ruleName+'";',
    '  action          = '+act+';',
    '  source-zone     = "'+srcZone+'";',
    '  source-address  = "'+srcAddrSpec+'";',
    '  dest-zone       = "'+destZone+'";',
    '  dest-address    = "'+r.dest_ip+'/32";'+destProv,
    '  dest-port       = '+r.dest_port+';',
    '  application     = "'+(r.apps&&r.apps.length?r.apps[0]:'any')+'";',
    '  service         = "application-default";',
    '  log-start       = yes;',
    '  log-end         = yes;',
    '  log-setting     = "default";',
    '}',
  ];
  var html='<div class="rule-spec">';
  html+=lines.map(function(l,i){
    if(i===0) return '<span class="rs-comment">'+esc(l)+'</span>';
    if(l.trim().startsWith('action')) return '  <span class="rs-field">action</span>          = <span class="'+actClass+' rs-action">'+act+'</span>;';
    if(l==='policy-rule {') return '<span style="color:#4a7aaf">policy-rule</span> {';
    if(l==='}') return '}';
    if(l==='') return '';
    var m=l.match(/^(\s+)(\S+)(\s+=\s+)(.*)(;)$/);
    if(m) return m[1]+'<span class="rs-field">'+esc(m[2])+'</span>'+m[3]+'<span class="rs-val">'+esc(m[4])+'</span>'+m[5];
    return esc(l);
  }).join('\n');
  html+='</div>';
  return html;
}


function fmtN(n){
  n=Number(n||0);
  if(n>=1e6)return (n/1e6).toFixed(1)+'M';
  if(n>=1e3)return (n/1e3).toFixed(0)+'K';
  return String(n);
}

function renderFunnel(f, st){
  if(!f) return;
  var total = f.total || 1;
  var minPkts = f.min_pkts || 10;

  // Derive traffic type description from top ports and apps
  var ports = Object.keys(f.top_ports||{}).map(Number);
  var apps  = Object.keys(f.top_apps||{});
  var is80443 = ports.some(function(p){return p===80||p===443;}) && !ports.some(function(p){return p!==80&&p!==443&&p<1024;});

  var trafficDesc = '';
  if(is80443){
    var appList=apps.slice(0,3).join(', ');
    trafficDesc='HTTP and HTTPS session traffic (ports 80/443). Top applications: <b>'+esc(appList)+'</b>. ';
    trafficDesc+='Sessions aged out rather than closing with TCP-FIN — expected for UDP-based protocols (QUIC, DNS-crypt, DTLS) which do not use TCP teardown.';
  } else if(f.tcp_fin===total){
    var appList=apps.slice(0,3).join(', ');
    trafficDesc='Non-standard port sessions that all closed cleanly with <b>TCP-FIN</b>. Applications: <b>'+esc(appList)+'</b>. ';
    trafficDesc+='Every session completed its TCP teardown — this is the cleanest of the three log sets.';
  } else {
    var portList=ports.slice(0,5).join(', ');
    trafficDesc='Non-standard port traffic (excl. 80/443) on ports <b>'+esc(String(portList))+'</b>. ';
    trafficDesc+='Sessions did not close with TCP-FIN — ranging from connection attempts that were never answered to established sessions terminated by RST or aged out.';
  }

  // Build the narrative description
  var synOnly     = f.syn_only     || 0;
  var synSynAck   = f.syn_synack   || 0;
  var handshake   = f.handshake    || 0;
  var dataMin     = f.data_minimal || 0;
  var estab       = f.established  || 0;
  var pOut        = f.pkts_out_total || 0;
  var pIn         = f.pkts_in_total  || 0;
  var dvc         = (f.devices||[]).join(', ') || 'Unknown';
  var zones       = (f.dest_zones||[]).join(', ') || 'Unknown';

  var desc = '<b>Firewall:</b> '+esc(dvc)+'&ensp;|&ensp;<b>Destination zones:</b> '+esc(zones)+'<br><br>';
  desc += trafficDesc;
  desc += '<br><br>';
  desc += 'Of <b>'+fmtN(total)+'</b> total sessions logged: ';

  var parts = [];
  if(synOnly>0)   parts.push('<b>'+fmtN(synOnly)+'</b> sent only a TCP-SYN with no response ('+Math.round(100*synOnly/total)+'%)');
  if(synSynAck>0) parts.push('<b>'+fmtN(synSynAck)+'</b> received a SYN-ACK but never completed the handshake ('+Math.round(100*synSynAck/total)+'%)');
  if(handshake>0) parts.push('<b>'+fmtN(handshake)+'</b> completed the three-way handshake but exchanged no application data ('+Math.round(100*handshake/total)+'%)');
  if(dataMin>0)   parts.push('<b>'+fmtN(dataMin)+'</b> transferred minimal data — likely probes or application-layer failures ('+Math.round(100*dataMin/total)+'%)');
  if(estab>0)     parts.push('<b>'+fmtN(estab)+'</b> established with real data exchange — <b>'+fmtN(pOut)+'</b> packets out / <b>'+fmtN(pIn)+'</b> packets in ('+Math.round(100*estab/total)+'%)');
  desc += parts.join('; ') + '. ';
  desc += 'Rule recommendations are based on the <b>'+fmtN(st.total_sessions)+'</b> sessions that passed the &ge;'+minPkts+'-packet threshold.';
  document.getElementById('funnel-desc').innerHTML=desc;

  // Build stage bars
  var stages=[
    {icon:'📤', n:total,      pct:100,                        lbl:'Sessions\nLogged',          col:'#2a5a8a'},
    {icon:'🔌', n:synOnly,    pct:Math.round(100*synOnly/total),   lbl:'SYN Only\nNo Response',    col:'#6a2a2a'},
    {icon:'🤝', n:synSynAck,  pct:Math.round(100*synSynAck/total), lbl:'SYN + SYN-ACK\nHalf-Open', col:'#6a4a00'},
    {icon:'🔁', n:handshake,  pct:Math.round(100*handshake/total), lbl:'Handshake\nNo Data',        col:'#4a4a00'},
    {icon:'📦', n:dataMin,    pct:Math.round(100*dataMin/total),   lbl:'Minimal\nData',            col:'#2a4a2a'},
    {icon:'✅', n:estab,      pct:Math.round(100*estab/total),     lbl:'Established\n>'+minPkts+'pkts', col:'#1a6a1a'},
  ];
  // Remove stages with 0 count (e.g. TCP-FIN file has no SYN-only)
  stages=stages.filter(function(st){return st.n>0;});

  var html='';
  stages.forEach(function(st,i){
    if(i>0) html+='<div class="fs-arrow">→</div>';
    html+='<div class="funnel-stage">';
    html+='<div class="fs-icon">'+st.icon+'</div>';
    html+='<div class="fs-n" style="color:'+st.col+'">'+fmtN(st.n)+'</div>';
    html+='<div class="fs-pct">'+st.pct+'%</div>';
    html+='<div class="fs-lbl">'+esc(st.lbl).replace(/\n/g,'<br>')+'</div>';
    html+='</div>';
  });
  document.getElementById('funnel-stages').innerHTML=html;

  // Close reason pills
  var closeHtml='<span style="font-size:10px;color:#6888a8;align-self:center">Session close:</span>';
  if(f.tcp_fin>0)  closeHtml+='<div class="fc-pill" style="border-color:#1a4a1a"><span style="color:#44cc44">✔</span> TCP-FIN <b style="color:#44cc44">'+fmtN(f.tcp_fin)+'</b> <span style="color:#5a7a5a">('+Math.round(100*f.tcp_fin/total)+'%)</span></div>';
  if(f.tcp_rst>0)  closeHtml+='<div class="fc-pill" style="border-color:#4a2a00"><span style="color:#ff8833">↩</span> TCP-RST <b style="color:#ff8833">'+fmtN(f.tcp_rst)+'</b> <span style="color:#5a4a2a">('+Math.round(100*f.tcp_rst/total)+'%)</span></div>';
  if(f.aged_out>0) closeHtml+='<div class="fc-pill" style="border-color:#2a2a4a"><span style="color:#6888a8">⏱</span> Aged-out <b style="color:#6888a8">'+fmtN(f.aged_out)+'</b> <span style="color:#3a4a5a">('+Math.round(100*f.aged_out/total)+'%)</span></div>';
  document.getElementById('funnel-close').innerHTML=closeHtml;

  // Note
  var noteHtml='Analysis uses '+minPkts+'-packet threshold to distinguish established sessions from handshake-only or probe traffic. ';
  noteHtml+='Total packets exchanged across all sessions: <b>'+fmtN(pOut+pIn)+'</b> (out: '+fmtN(pOut)+' / in: '+fmtN(pIn)+').';
  document.getElementById('funnel-note').innerHTML=noteHtml;
}

function renderFindings(findings){
  var html='';
  findings.forEach(function(f){
    html+='<div class="finding-card '+esc(f.level)+'">';
    html+='<div class="finding-icon">'+f.icon+'</div>';
    html+='<div style="flex:1">';
    html+='<div class="finding-title">'+esc(f.title)+'</div>';
    html+='<div class="finding-detail">'+esc(f.detail)+'</div>';
    // "View Sessions" button — links to log event modal
    if(f.filter){
      var btnCol='#3a6a9a';
      if(f.level==='crit') btnCol='#6a2a2a';
      else if(f.level==='high') btnCol='#5a4a00';
      else if(f.level==='med') btnCol='#3a4a00';
      html+='<button onclick="showFindingSessions(\''+esc(f.filter)+'\',\''+esc(f.title)+'\')" '+
            'style="margin-top:8px;padding:3px 10px;background:'+btnCol+';border:1px solid '+btnCol+'88;'+
            'color:#c8d8e8;font-size:10px;border-radius:4px;cursor:pointer;white-space:nowrap"'+
            '>📋 View Sessions →</button>';
    }
    html+='</div>';
    html+='</div>';
  });
  document.getElementById('findings-grid').innerHTML=html;
}

function renderStats(st){
  document.getElementById('st-sess').textContent   =fmt(st.total_sessions);
  document.getElementById('st-rules').textContent  =fmt(st.total_rules);
  document.getElementById('st-block').textContent  =fmt(st.n_block);
  document.getElementById('st-review').textContent =fmt(st.n_review);
  document.getElementById('st-monitor').textContent=fmt(st.n_monitor);
  document.getElementById('st-allow').textContent  =fmt(st.n_allow);
  document.getElementById('st-crit').textContent   =fmt(st.n_critical);
  document.getElementById('st-high').textContent   =fmt(st.n_high);
  document.getElementById('st-src24').textContent  =fmt(st.n_src24);
  document.getElementById('st-dests').textContent  =fmt(st.n_dest);
}

// ── v2.0: action-indexed + precomputed haystack ─────────────────────────────
// curAction picks the pre-split array (BLOCK/REVIEW/MONITOR/ALLOW) instead of
// scanning all 161K rules every keystroke. rules_by_action stores indices
// into D.rules (not copies), so wire payload stays small. _hay was computed
// once on the Python side so the client never rebuilds it.
function filterRules(){
  if(!D) return [];
  var source;
  if(curAction && D.rules_by_action && D.rules_by_action[curAction]){
    var idxArr = D.rules_by_action[curAction];
    // idxArr is an array of integer indices into D.rules. Resolve once here.
    source = new Array(idxArr.length);
    for(var k=0;k<idxArr.length;k++){ source[k] = D.rules[idxArr[k]]; }
  } else {
    source = D.rules || [];
  }
  if(!curRuleSearch) return source;
  var q = curRuleSearch.toLowerCase();
  var out = [];
  for(var i=0;i<source.length;i++){
    var r = source[i];
    // Prefer precomputed _hay; fall back to legacy computation for
    // backward-compat with old reports.
    var h = r._hay;
    if(h === undefined){
      h = ((r.src_ip||r.src24||'')+' '+(r.hostname||'')+' '+(r.dest_ip||'')+' '+
           String(r.dest_port||'')+' '+(r.svc||'')+' '+(r.action||'')+' '+
           ((getDest(r).provider)||'')+' '+((r.apps||[]).join(' '))).toLowerCase();
    }
    if(h.indexOf(q) >= 0) out.push(r);
  }
  return out;
}

// ── v2.0: incremental virtualized renderer ──────────────────────────────────
// Instead of building HTML for all 161K rules on every filter change (the
// original behaviour), only the first BATCH rules are rendered. An
// IntersectionObserver on a sentinel row near the bottom appends the next
// batch when the user scrolls close. Combined with lazy bodies, this keeps
// first paint under a few hundred ms even on the MONITOR tab.
var _ruleState = {
  rules:   [],   // current filtered rule set
  shown:   0,    // how many have been mounted
  batch:   60,   // rows per chunk
  observer: null // IntersectionObserver instance
};

function renderRules(){
  _ruleState.rules = filterRules();
  _ruleState.shown = 0;
  document.getElementById('rules-cnt').textContent = _ruleState.rules.length;
  var host = document.getElementById('rules-list');
  if(!_ruleState.rules.length){
    host.innerHTML = '<div style="padding:20px;color:#4a6a8a;font-size:11px">No rules match current filter.</div>';
    if(_ruleState.observer){ _ruleState.observer.disconnect(); }
    return;
  }
  host.innerHTML = '<div id="rules-sentinel" style="height:1px"></div>';
  _renderNextBatch();
  _ensureObserver();
}

function _renderNextBatch(){
  var s = _ruleState;
  if(s.shown >= s.rules.length) return;
  var host = document.getElementById('rules-list');
  var sentinel = document.getElementById('rules-sentinel');
  var end = Math.min(s.shown + s.batch, s.rules.length);
  var frag = document.createDocumentFragment();
  var tmp = document.createElement('div');
  for(var i=s.shown; i<end; i++){
    tmp.innerHTML = buildRuleHead(s.rules[i]);
    frag.appendChild(tmp.firstChild);
  }
  host.insertBefore(frag, sentinel);
  s.shown = end;
  if(s.shown >= s.rules.length && sentinel){ sentinel.remove(); }
}

function _ensureObserver(){
  if(_ruleState.observer){ _ruleState.observer.disconnect(); }
  var sentinel = document.getElementById('rules-sentinel');
  if(!sentinel) return;
  _ruleState.observer = new IntersectionObserver(function(entries){
    if(entries[0].isIntersecting){ _renderNextBatch(); }
  }, {rootMargin: '400px 0px'});
  _ruleState.observer.observe(sentinel);
}

// One delegated click handler replaces 161K inline onclicks. Wired on init.
function _initRulesDelegation(){
  var host = document.getElementById('rules-list');
  if(!host || host._delegated) return;
  host._delegated = true;
  host.addEventListener('click', function(e){
    var card = e.target.closest('.rule-card');
    if(!card) return;
    var idx = card.getAttribute('data-idx');
    if(idx === null) return;
    toggleRule(parseInt(idx, 10));
  });
}

function buildRuleHead(r){
  var idx = r._i || 0;
  var html = '';
  var destInfo = r.dest || {};
  // v2.0 — friendlyDest() combines provider + svc_type into a clear label:
  // "Akamai CDN", "Amazon EC2", "Azure Cloud", "Google CDN", etc.
  var provStr  = friendlyDest(destInfo) || '?';
  var rc = riskColor(r.risk);
  html += '<div class="rule-card" id="rc-'+idx+'" data-idx="'+idx+'">';
  html += '<div class="rule-head">';

    // ── Top row: action | risk | port | service | flow | provider | count ──
    html+='<div class="rh-top">';
    html+='<span class="action-badge ab-'+r.action+'">'+r.action+'</span>';
    html+='<span class="risk-badge rb-'+r.risk+'">'+r.risk+'</span>';
    html+='<span class="rule-port">:'+r.dest_port+'</span>';
    html+='<span class="rule-svc">'+esc(r.svc)+'</span>';
    // App-ID badge — show PA app name prominently
    if(r.apps && r.apps.length){
      var appId = r.apps[0];
      var appIdColors = {
        'incomplete':'#cc5500','unknown-tcp':'#cc3300','unknown-udp':'#cc3300',
        'ssl':'#3a5a7a','tanium':'#1a6a3a','crowdstrike':'#1a5a4a',
        'google-base':'#1a4a8a','gmail-base':'#8a2a2a',
        'whatsapp-base':'#2a6a2a','yahoo-mail-base':'#7a3a00',
        'insufficient-data':'#5a5a2a'
      };
      var aColor = appIdColors[appId] || '#2a4a6a';
      html+='<span style="background:'+aColor+';color:#fff;font-size:9px;font-weight:700;'
           +'padding:2px 7px;border-radius:3px;margin-left:4px" title="PA App-ID">'+esc(appId)+'</span>';
      if(r.apps.length>1) html+='<span style="color:#4a6a7a;font-size:9px;margin-left:3px">+'+String(r.apps.length-1)+'</span>';
    }
    html+='<span class="rule-flow" style="font-size:11px">'+esc(r.src_ip||r.src24)+'  →  '+esc(r.dest_ip)+'</span>';
    // v2.0 — MONITOR collapsed-/24 badge
    if(r.collapsed_n && r.collapsed_n > 1){
      html+='<span style="font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;background:#1a3a5a;color:#8ac0ff;margin-left:4px;letter-spacing:.3px" title="Collapsed /24 — click card to see individual hosts">'+r.collapsed_n+' HOSTS</span>';
    }
    html+='<span class="rule-dest-info">'+providerBadge(provStr,'')+'</span>';
    html+='<span class="rule-cnt">'+fmt(r.count)+' sess</span>';
    // Traffic tier mini-badge in header
    var dtH = r.dominant_tier||'LIGHT';
    var dtColors={PROBE:'#ff8800',LIGHT:'#2a4a6a',NORMAL:'#1a5a3a',ACTIVE:'#0a6a2a',BULK:'#0a5a6a'};
    html+='<span style="font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;background:'+(dtColors[dtH]||'#2a4a6a')+';color:#fff;margin-left:4px">'+esc(dtH)+'</span>';
    html+='<span style="font-size:9px;color:#4a6a5a;margin-left:4px">avg '+fmt(r.pkts_avg||0)+'pkt</span>';
    html+='</div>';

    // ── Identity row: Src IP | Src Hostname | Src App | Src APM ID | Dest App ID ──
    var ipam=r.ipam||{};
    var destI=r.dest||{};

    // Src App: prefer ENT dataset app name, fall back to IPAM app_acronyms
    var srcAppDisp = r.src_app || (ipam.app_acronyms||'').split('|')[0].trim() || '';
    // Src APM ID: prefer ENT apm_ids, fall back to IPAM
    var srcApm = r.src_app ? (ipam.apm_ids||'').split('|')[0].trim() : (ipam.apm_ids||'').split('|')[0].trim();
    // Dest App ID — v2.0: use friendlyDest() so the identity row shows
    // "Akamai CDN", "Amazon EC2", "Azure Cloud" etc. instead of raw provider.
    var destAppDisp = friendlyDest(destI) || '';
    // If friendlyDest includes the provider, also surface a specific service
    // name when available (e.g. "Google CDN — Europe" for regional breakdown).
    var destSvcExtra = '';
    if(destI.region && destI.svc_type){
      destSvcExtra = destI.region;
    }
    var destSvcType = destI.svc_type || destI.ds_class || '';

    html+='<div class="rh-ids">';

    // Src IP + site code
    var siteCode = r.src_site_code || '';
    html+='<div class="id-field">';
    html+='<span class="id-lbl">Src IP'+(siteCode?' | '+esc(siteCode):'')+'</span>';
    html+='<span class="id-val">'+esc(r.src_ip||'—')+'</span>';
    html+='</div>';

    // Src Hostname
    html+='<div class="id-field">';
    html+='<span class="id-lbl">Src Hostname</span>';
    if(r.hostname){
      html+='<span class="id-val host" title="'+(r.fqdn||r.hostname)+'">'+esc(r.hostname)+'</span>';
      if(r.ht_inferred){
        html+='<span title="Location inferred from hostname translation ('+esc(r.ht_tier||'')+') — not from IPAM or ENT" '
             +'style="font-size:8px;font-weight:700;padding:1px 4px;border-radius:2px;'
             +'background:#1a2a00;color:#88cc44;margin-left:4px;vertical-align:middle">⟳ HT</span>';
      }
    } else if(r.collapsed_n && r.collapsed_n > 1){
      // Collapsed /24 row — summarise host count; individual hosts listed in body
      html+='<span class="id-val host" style="color:#8ac0ff" title="Click to expand for individual hosts">'
           +r.collapsed_n+' hosts in /24</span>';
    } else if(ipam.unregistered){
      // Subnet not in IPAM — flag explicitly, not silently blank
      html+='<span class="id-val none" style="color:#ff8833;font-style:normal;font-weight:600" '
           +'title="Source subnet '+esc(r.src24||'')+'  is not registered in IPAM — investigate">⚠ Unregistered subnet</span>';
    } else {
      // No ENT match — show subnet type context from IPAM
      var subnetCtx = '';
      if(ipam.net_type)   subnetCtx = ipam.net_type;
      if(ipam.infra_role && ipam.infra_role!=='Unknown') subnetCtx += (subnetCtx?' · ':'')+ipam.infra_role;
      if(ipam.store_num)  subnetCtx += ' Store#'+ipam.store_num;
      html+='<span class="id-val none" title="'+esc(subnetCtx||'not in host dataset')+'">'
           +(subnetCtx ? esc(subnetCtx.substring(0,28)) : 'not in host dataset')+'</span>';
    }
    html+='</div>';

    // Src Application + acronym — ENT match or IPAM app_subnet fallback
    html+='<div class="id-field">';
    html+='<span class="id-lbl">Src Application</span>';
    var appLabel  = r.src_app_acronym ? esc(r.src_app_acronym) : '';
    var appFull   = srcAppDisp;
    var ipamApps  = (ipam.apps_ipam||'').split('|').filter(function(a){return a.trim();});
    var ipamApmId = (ipam.apm_ids||'').split('|').filter(function(a){return a.trim();})[0]||'';
    if(appFull){
      html+='<span class="id-val app" title="'+esc(appFull)+'">'+esc(appLabel||appFull.substring(0,20))+'</span>';
    } else if(ipamApps.length){
      // Fall back to IPAM app_subnet_index — show apps in this /24
      html+='<span class="id-val" style="color:#8a70b0;font-size:10px" title="From app_subnet_index for '+esc(r.src24||'')+'">'
           +esc(ipamApps.slice(0,3).join(' · '))
           +(ipamApps.length>3?' +'+String(ipamApps.length-3):'')+'</span>';
    } else {
      html+='<span class="id-val none">unknown</span>';
    }
    html+='</div>';

    // Src BU
    html+='<div class="id-field">';
    html+='<span class="id-lbl">Business Unit</span>';
    var buDisp = r.src_bu || (ipam.bu||'');
    if(buDisp){
      html+='<span class="id-val bu" title="'+esc(buDisp)+'">'+esc(buDisp.substring(0,20))+'</span>';
    } else {
      html+='<span class="id-val none">—</span>';
    }
    html+='</div>';

    // Src Site / DC
    html+='<div class="id-field">';
    html+='<span class="id-lbl">Site / DC</span>';
    var siteDisp = r.src_site_name || r.src_dc_name || (ipam.site||ipam.location||'');
    if(siteDisp){
      html+='<span class="id-val site" title="'+esc(siteDisp)+'">'+esc(siteDisp.substring(0,22))+'</span>';
    } else {
      html+='<span class="id-val none">—</span>';
    }
    html+='</div>';

    // Dest Provider / Service
    html+='<div class="id-field">';
    html+='<span class="id-lbl">Dest Service</span>';
    if(destAppDisp && destAppDisp !== '?'){
      html+='<span class="id-val dest-app" title="'+esc(destAppDisp)+(destSvcExtra?' — '+esc(destSvcExtra):'')+'">'+esc(destAppDisp)+'</span>';
      if(destSvcExtra) html+='<span style="font-size:9px;color:#4a7a5a"> '+esc(destSvcExtra)+'</span>';
      else if(destSvcType && !destAppDisp.includes(destSvcType)) html+='<span style="font-size:9px;color:#4a7a5a"> '+esc(destSvcType)+'</span>';
    } else {
      html+='<span class="id-val none">unclassified dest</span>';
    }
    html+='</div>';

    html+='</div>'; // end rh-ids
    html+='</div>'; // end rule-head
    html+='<div class="risk-bar '+riskBarClass(r.risk)+'"></div>';
    html+='<div class="rule-body" id="rb-'+idx+'"></div>';  // body built lazily on expand
    html+='</div>'; // end rule-card
    return html;
} // end buildRuleHead

// ── buildRuleBody — constructed on first expand, cached in the DOM ──────────
function buildRuleBody(r){
    var idx = r._i || 0;
    var html = '';
    var destInfo = r.dest || {};
    var rc = riskColor(r.risk);

    // Left column
    html+='<div>';
    html+='<div class="rb-label">Recommendation</div>';
    html+='<div class="rb-rec">'+esc(r.reason)+'</div>';

    // v2.0 — Collapsed hosts list (MONITOR /24 collapse)
    if(r.collapsed_hosts && r.collapsed_hosts.length > 0){
      html+='<div class="rb-label">Hosts in /24 <span style="color:#4a9acf;font-weight:400">('+r.collapsed_hosts.length+')</span></div>';
      html+='<div style="background:#061018;border:1px solid #1a2a3a;border-radius:4px;padding:8px;margin-bottom:10px;max-height:260px;overflow-y:auto">';
      html+='<table style="width:100%;border-collapse:collapse;font-size:10px;font-family:\'Courier New\',monospace">';
      html+='<thead><tr style="color:#5a7a9a;font-size:9px;text-transform:uppercase;letter-spacing:.4px">';
      html+='<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #1a2a3a">IP</th>';
      html+='<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #1a2a3a">Hostname</th>';
      html+='<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #1a2a3a">App</th>';
      html+='<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #1a2a3a">Env</th>';
      html+='<th style="text-align:right;padding:3px 6px;border-bottom:1px solid #1a2a3a">Sess</th>';
      html+='<th style="text-align:right;padding:3px 6px;border-bottom:1px solid #1a2a3a">Pkts</th>';
      html+='</tr></thead><tbody>';
      for(var ci=0; ci<r.collapsed_hosts.length; ci++){
        var h = r.collapsed_hosts[ci];
        html+='<tr style="border-bottom:1px solid #0f1e2e">';
        html+='<td style="padding:3px 6px;color:#79c0ff">'+esc(h.ip||'—')+'</td>';
        html+='<td style="padding:3px 6px;color:#a8c8e8" title="'+esc(h.fqdn||h.hostname||'')+'">'
             +(h.hostname ? esc(h.hostname) : '<span style="color:#3a5a7a;font-style:italic">—</span>')+'</td>';
        html+='<td style="padding:3px 6px;color:#c8a8e8">'
             +(h.app ? esc(String(h.app).substring(0,22)) : '<span style="color:#3a5a7a">—</span>')+'</td>';
        html+='<td style="padding:3px 6px;color:#70c870">'+esc(h.env||'')+'</td>';
        html+='<td style="padding:3px 6px;text-align:right;color:#4a9a8a">'+fmt(h.count||0)+'</td>';
        html+='<td style="padding:3px 6px;text-align:right;color:#6a8a7a">'+fmt(h.pkts||0)+'</td>';
        html+='</tr>';
      }
      html+='</tbody></table>';
      html+='</div>';
    }

    html+='<div class="rb-label">PA Policy Rule Specification</div>';
    html+=ruleSpec(r);

    // Source host record — rich host identity card
    var ipam=r.ipam||{};
    // Heritage badge
    var heritageBadge = '';
    if(r.src_heritage==='CVS')   heritageBadge='<span class="hbadge hb-cvs">CVS</span> ';
    else if(r.src_heritage==='AETNA') heritageBadge='<span class="hbadge hb-aetna">AETNA</span> ';
    else if(r.src_heritage==='HCB')   heritageBadge='<span class="hbadge hb-hcb">HCB</span> ';
    // Data source badges
    var dsBadges='';
    if((r.src_in_snow||r.src_data_sources||'').indexOf('SNOW')>=0)   dsBadges+='<span class="dsrc-badge dsrc-snow">SNOW</span>';
    if((r.src_in_qualys||r.src_data_sources||'').indexOf('Y')===0||(r.src_data_sources||'').indexOf('Qualys')>=0) dsBadges+='<span class="dsrc-badge dsrc-ql">QUALYS</span>';
    if((r.src_in_wiz||r.src_data_sources||'').indexOf('ADL')>=0||(r.src_data_sources||'').indexOf('ADL')>=0) dsBadges+='<span class="dsrc-badge dsrc-adl">ADL</span>';
    if((r.src_in_wiz||'').indexOf('Y')===0) dsBadges+='<span class="dsrc-badge dsrc-wiz">WIZ</span>';
    html+='<div class="rb-label">Source Host — '+esc(r.src_ip||r.src24)+'</div>';
    html+='<div class="src-chip">';
    html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">';
    html+='<span class="sc-cidr" style="margin:0">'+esc(r.src_ip||r.src24)+compliancePills(ipam)+'</span>';
    html+=heritageBadge+dsBadges;
    html+='</div>';
    html+='<div class="src-host-grid">';
    // Col 1
    html+='<div>';
    if(r.hostname){
      html+='<div class="shg-field"><span class="shg-label">Hostname</span>';
      html+='<span class="shg-val" style="color:#79c0ff">'+esc(r.hostname)+'</span></div>';
    }
    if(r.fqdn && r.fqdn!==r.hostname){
      html+='<div class="shg-field"><span class="shg-label">FQDN</span>';
      html+='<span class="shg-val" style="color:#5a8acf;font-size:9px">'+esc(r.fqdn.substring(0,50))+'</span></div>';
    }
    if(r.src_os){
      html+='<div class="shg-field"><span class="shg-label">OS</span>';
      html+='<span class="shg-val">'+esc(r.src_os)+(r.src_os_detail&&r.src_os_detail!==r.src_os?' · <span style="color:#5a7a9a;font-size:9px">'+esc(r.src_os_detail.substring(0,30))+'</span>':'')+'</span></div>';
    }
    if(r.src_server_class){
      html+='<div class="shg-field"><span class="shg-label">Class</span>';
      html+='<span class="shg-val" style="color:#8a9acf">'+esc(r.src_server_class)+'</span></div>';
    }
    if(r.src_env){
      html+='<div class="shg-field"><span class="shg-label">Environment</span>';
      html+='<span class="shg-val"><span class="id-val env">'+esc(r.src_env)+'</span></span></div>';
    }
    html+='</div>';
    // Col 2
    html+='<div>';
    if(r.src_app){
      html+='<div class="shg-field"><span class="shg-label">Application</span>';
      html+='<span class="shg-val" style="color:#c8a8e8">'+esc((r.src_app_acronym||r.src_app).substring(0,30))+'</span></div>';
      if(r.src_app_acronym && r.src_app!==r.src_app_acronym){
        html+='<div class="shg-field"><span class="shg-label">Full Name</span>';
        html+='<span class="shg-val" style="color:#9a80c0;font-size:9px">'+esc(r.src_app.substring(0,50))+'</span></div>';
      }
    }
    if(r.src_apm_ids){
      html+='<div class="shg-field"><span class="shg-label">APM ID(s)</span>';
      html+='<span class="shg-val" style="color:#4a9a8a">'+esc(r.src_apm_ids.split('|').slice(0,3).join(' | '))+'</span></div>';
    }
    if(r.src_bu){
      html+='<div class="shg-field"><span class="shg-label">Business Unit</span>';
      html+='<span class="shg-val" style="color:#c8a060">'+esc(r.src_bu.substring(0,40))+'</span></div>';
    }
    if(r.src_site_name||r.src_dc_name){
      html+='<div class="shg-field"><span class="shg-label">Site / DC</span>';
      html+='<span class="shg-val" style="color:#60a8c8">'+esc(r.src_site_name||r.src_dc_name)+'</span></div>';
    }
    if(r.src_csna){
      html+='<div class="shg-field"><span class="shg-label">CSNA Hostgroup</span>';
      html+='<span class="shg-val" style="color:#7ee787;font-size:9px">'+esc(r.src_csna)+'</span></div>';
    }
    html+='</div>';
    html+='</div>'; // end grid
    html+='</div>'; // end chip

    // /24 subnet IPAM context below
    html+='<div class="rb-label">Subnet Context — '+esc(r.src24)+'</div>';
    html+='<div class="src-chip">';
    if(ipam.unregistered){
      html+='<div class="sc-meta" style="background:#2a1500;border:1px solid #ff8833;border-radius:4px;padding:8px 10px;margin-bottom:4px">'
           +'<span style="color:#ff8833;font-weight:700;font-size:12px">⚠ UNREGISTERED SUBNET</span>'
           +'<div style="color:#cc8833;font-size:10px;margin-top:4px">'+esc(r.src24)+'  is not registered in the IPAM dataset.</div>'
           +'<div style="color:#cc8833;font-size:10px;margin-top:2px">This is shadow IT, rogue infrastructure, or a gap in IPAM coverage. '
           +'Add this subnet to all_IP_networks before the next report run.</div>'
           +'</div>';
    } else if(ipam.ht_inferred){
      html+='<div class="sc-meta" style="background:#0a1a00;border:1px solid #88cc44;border-radius:4px;padding:6px 10px;margin-bottom:4px">'
           +'<span style="color:#88cc44;font-weight:700;font-size:10px">⟳ Location inferred from hostname translation</span>'
           +'<div style="color:#5a8a3a;font-size:9px;margin-top:2px">Tier: '+esc(ipam.ht_tier||'')
           +' · Hostname: '+esc(ipam.ht_hostname||r.hostname||'')+'</div>'
           +'<div style="color:#5a8a3a;font-size:9px">No IPAM record for this subnet. Location is a best-effort inference — '
           +'verify and register subnet in all_IP_networks.</div>'
           +'</div>';
    } else {
      if(ipam.site)    html+='<div class="sc-meta"><b>Site:</b> '+esc(ipam.site)+'</div>';
      if(ipam.location)html+='<div class="sc-meta"><b>Location:</b> '+esc(ipam.location)+'</div>';
      if(ipam.facility)html+='<div class="sc-meta"><b>Facility:</b> '+esc(ipam.facility)+
                             (ipam.net_type?' | Net Type: '+esc(ipam.net_type):'')+'</div>';
      if(ipam.owner)   html+='<div class="sc-meta"><b>Owner:</b> '+esc(ipam.owner)+
                             (ipam.bu?' | BU: '+esc(ipam.bu):'')+'</div>';
      if(ipam.apps_ipam||ipam.apm_ids){
        var appDisp = ipam.apps_ipam ? ipam.apps_ipam.split('|').slice(0,5).join(' · ') : '';
        html+='<div class="sc-meta"><b>Apps (IPAM):</b> <span style="color:#c8a8e8">'+esc(appDisp.substring(0,100))+'</span></div>';
      }
      if(ipam.app_names&&ipam.app_names!==ipam.apps_ipam){
        html+='<div class="sc-meta" style="font-size:9px;color:#7a6a9a">'+esc(ipam.app_names.substring(0,120))+'</div>';
      }
      if(ipam.apm_ids){
        html+='<div class="sc-meta"><b>APM IDs:</b> <span style="color:#4a9a8a;font-size:10px">'+esc(ipam.apm_ids.split('|').slice(0,5).join(' | '))+'</span></div>';
      }
      if(ipam.prod_apps){
        var prodStr = ipam.prod_apps+' prod apps';
        if(ipam.app_envs) prodStr += ' · '+ipam.app_envs;
        html+='<div class="sc-meta"><b>App Count:</b> '+esc(prodStr)+'</div>';
      }
      if(ipam.pci_mixed==='Y'){
        html+='<div class="sc-meta"><span style="color:#ff8800;font-weight:700">⚠ PCI MIXED SUBNET</span></div>';
      }
      if(ipam.sox==='Y') html+='<div class="sc-meta"><span style="color:#ff6600">SOX Critical</span></div>';
      if(ipam.hitrust==='Y') html+='<div class="sc-meta"><span style="color:#6688cc">HITRUST</span></div>';
      if(ipam.routing) html+='<div class="sc-meta"><b>Routing Domain:</b> '+esc(ipam.routing)+'</div>';
      if(ipam.cpc_svc) html+='<div class="sc-meta"><b>CPC Services:</b> '+esc(ipam.cpc_svc.substring(0,80))+'</div>';
    }
    html+='</div>';
    html+='</div>';


    // Right column
    html+='<div>';
    html+='<div class="rb-label">Destination — Identity &amp; Geography</div>';
    html+='<div class="src-chip">';
    var destHighRisk = r.dest_high_risk==='Y';
    html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">';
    html+='<span class="sc-cidr" style="margin:0;color:'+(destHighRisk?'#ff7777':(r.dest_cpc_match==='Y'?'#88ffaa':'#a8d8a8'))+'">'+esc(r.dest_ip)+'</span>';
    if(destHighRisk) html+='<span style="font-size:9px;font-weight:700;color:#ff5555;background:#3a0a0a;padding:1px 6px;border-radius:3px">⚠ HIGH-RISK COUNTRY</span>';
    if(r.dest_cpc_match==='Y') html+='<span style="font-size:9px;font-weight:700;color:#88ffaa;background:#0a2a1a;padding:1px 6px;border-radius:3px">✓ CPC: '+esc(r.dest_cpc_service)+'</span>';
    if(r.dest_is_bogon) html+='<span style="font-size:9px;font-weight:700;color:#ff4444;background:#3a0000;padding:1px 6px;border-radius:3px">⛔ '+esc(r.dest_ip_rfc)+' VIOLATION</span>';
    html+='</div>';
    html+='<div class="src-host-grid">';
    // Col 1: provider + service
    html+='<div>';
    if(destInfo.provider&&destInfo.provider!=='Unknown'){
      html+='<div class="shg-field"><span class="shg-label">Provider / Org</span>';
      html+=providerBadge(destInfo.provider,'')+'</div>';
    } else {
      html+='<div class="shg-field"><span class="shg-label">Provider / Org</span>';
      html+='<span style="color:#ff8833;font-size:10px">⚠ Unknown — investigate</span></div>';
    }
    if(destInfo.service){
      html+='<div class="shg-field"><span class="shg-label">Service</span>';
      html+='<span class="shg-val" style="color:#6ab87a">'+esc(destInfo.service)+'</span></div>';
    }
    if(destInfo.svc_label||destInfo.svc_type){
      html+='<div class="shg-field"><span class="shg-label">Service Type</span>';
      html+='<span class="shg-val" style="color:#5a9a6a">'+esc(destInfo.svc_label||destInfo.svc_type)+'</span></div>';
    }
    if(r.dest_description){
      html+='<div class="shg-field"><span class="shg-label">Description</span>';
      html+='<span class="shg-val" style="color:#4a7a5a;font-size:9px">'+esc(r.dest_description.substring(0,60))+'</span></div>';
    }
    if(destInfo.ds_class){
      html+='<div class="shg-field"><span class="shg-label">Dataset Class</span>';
      html+='<span class="shg-val" style="color:#3a7a4a">'+esc(destInfo.ds_class)+'</span></div>';
    }
    html+='</div>';
    // Col 2: geo + ASN
    html+='<div>';
    // ── Bogon/RFC violation alert ────────────────────────────────────────────
    if(r.dest_is_bogon){
      html+='<div style="background:#3a0000;border:1px solid #ff4444;border-radius:4px;padding:6px 10px;margin-bottom:6px">';
      html+='<div style="color:#ff4444;font-weight:700;font-size:11px">⛔ RFC ADDRESS SPACE VIOLATION</div>';
      html+='<div style="color:#ff8888;font-size:10px;margin-top:2px">'
           +esc(r.dest_ip_rfc||'')+' — '+esc(r.dest_ip_space||'')+' address in outside zone.</div>';
      html+='<div style="color:#ff6666;font-size:10px">Route leak / NAT failure / spoofed packet — investigate immediately.</div>';
      html+='</div>';
    }
    // ── Country + high-risk ───────────────────────────────────────────────────
    if(r.dest_country){
      html+='<div class="shg-field"><span class="shg-label">Country</span>';
      html+='<span class="shg-val" style="color:'+(destHighRisk?'#ff7777':'#c8d8e8')+'">'+esc(r.dest_country)+' — '+esc(r.dest_country_name||'')+'</span>';
      if(destHighRisk&&r.dest_risk_reason) html+='<span style="font-size:9px;color:#ff5555;display:block">'+esc(r.dest_risk_reason)+'</span>';
      html+='</div>';
    }
    // ── City / State — always show if available ───────────────────────────────
    var locParts = [r.dest_city, r.dest_us_state].filter(function(x){return x&&x.trim();});
    if(locParts.length){
      html+='<div class="shg-field"><span class="shg-label">Location</span>';
      html+='<span class="shg-val" style="color:#8aaacf">'+esc(locParts.join(', '))+'</span></div>';
    } else if(destInfo.region){
      html+='<div class="shg-field"><span class="shg-label">Region</span>';
      html+='<span class="shg-val" style="color:#8aaacf">'+esc(destInfo.region)+'</span></div>';
    }
    // ── ASN + Org — always show ───────────────────────────────────────────────
    if(r.dest_asn||r.dest_as_name){
      html+='<div class="shg-field"><span class="shg-label">ASN</span>';
      html+='<span class="shg-val" style="color:#7090b0;font-size:10px">'+esc(r.dest_asn||'')+'</span></div>';
    }
    if(r.dest_as_name){
      html+='<div class="shg-field"><span class="shg-label">Org</span>';
      html+='<span class="shg-val" style="color:#8aaacf;font-size:10px">'+esc(r.dest_as_name.substring(0,50))+'</span></div>';
    } else if(r.dest_asn_display){
      html+='<div class="shg-field"><span class="shg-label">ASN / Org</span>';
      html+='<span class="shg-val" style="color:#7090b0;font-size:10px">'+esc(r.dest_asn_display.substring(0,50))+'</span></div>';
    }
    html+='</div>';
    html+='</div>'; // end grid
    html+='<div style="margin-top:8px;padding-top:6px;border-top:1px solid #1a2a3a;display:flex;gap:12px">';
    html+='<a href="https://rdap.arin.net/registry/ip/'+esc(r.dest_ip)+'" target="_blank" style="color:#4ab;font-size:10px">ARIN RDAP →</a>';
    html+='<a href="https://www.shodan.io/host/'+esc(r.dest_ip)+'" target="_blank" style="color:#4ab;font-size:10px">Shodan →</a>';
    html+='<a href="https://bgpview.io/ip/'+esc(r.dest_ip)+'" target="_blank" style="color:#4ab;font-size:10px">BGPView →</a>';
    html+='<a href="https://www.virustotal.com/gui/ip-address/'+esc(r.dest_ip)+'" target="_blank" style="color:#c4a;font-size:10px">VirusTotal →</a>';
    html+='</div>';
    html+='</div>'; // end chip
    html+='<div class="rb-label">Session Details</div>';
    html+='<div class="sc-chip"><div class="sc-meta">';
    // Traffic tier badge
    var tierColors = {PROBE:'#ff8800',LIGHT:'#5a7a9a',NORMAL:'#4a8a6a',ACTIVE:'#3a9a4a',BULK:'#2a7a8a'};
    var tierDescs  = {
      PROBE: 'PROBE — PA app-inspection / TCP handshake only. Verify this is real traffic before creating rule.',
      LIGHT: 'LIGHT — minimal data exchange (6–20 packets)',
      NORMAL:'NORMAL — standard interactive session (21–100 packets)',
      ACTIVE:'ACTIVE — sustained data transfer (101–1,000 packets)',
      BULK:  'BULK — high-volume transfer (>1,000 packets). Verify authorised.'
    };
    var dt = r.dominant_tier || 'LIGHT';
    var tc = tierColors[dt] || '#5a7a9a';
    html+='<div style="margin-bottom:6px">';
    html+='<span style="background:'+tc+';color:#fff;font-weight:700;font-size:10px;padding:2px 8px;border-radius:3px;margin-right:6px">'+esc(dt)+'</span>';
    html+='<span style="color:'+tc+';font-size:10px">'+esc(tierDescs[dt]||'')+'</span>';
    html+='</div>';
    // Tier distribution breakdown if mixed
    if(r.traffic_tiers && Object.keys(r.traffic_tiers).length > 1){
      var tierParts = Object.entries(r.traffic_tiers).map(function(kv){
        return kv[1]+'× '+kv[0];
      }).join('  ');
      html+='<div style="font-size:9px;color:#5a7a9a;margin-bottom:4px">Tier mix: '+esc(tierParts)+'</div>';
    }
    html+='<b>Sessions:</b> '+fmt(r.count)+'  <span style="font-size:10px;color:#6a8a7a">avg '+fmt(r.pkts_avg||0)+' pkts/session</span><br>';
    html+='<b>Packets:</b> out='+fmt(r.pkts_out)+' in='+fmt(r.pkts_in)+'  total='+fmt((r.pkts_out||0)+(r.pkts_in||0))+'<br>';
    html+='<b>End reason(s):</b> '+esc((r.end_reasons||[]).join(', '))+'<br>';
    html+='<b>PA app(s):</b> '+esc((r.apps||[]).join(', '))+'<br>';
    html+='<b>Device(s):</b> '+esc((r.devices||[]).join(', '))+'<br>';
    html+='</div></div>';

    html+='<div class="rb-label">Port Assessment</div>';
    html+='<div class="rb-rec" style="border-color:'+rc+';background:#0a0a1a">'+esc(r.port_note)+'</div>';
    html+='</div>';

    return html;
}  // end buildRuleBody

// ── toggleRule — build body HTML on first expand, then just toggle class ───
function toggleRule(idx){
  var card = document.getElementById('rc-'+idx);
  var body = document.getElementById('rb-'+idx);
  if(!card || !body) return;
  if(!body._built){
    var target = null;
    var arr = _ruleState.rules;
    for(var i=0;i<arr.length;i++){ if(arr[i]._i === idx){ target = arr[i]; break; } }
    if(!target && D && D.rules){
      for(var j=0;j<D.rules.length;j++){ if(D.rules[j]._i === idx){ target = D.rules[j]; break; } }
    }
    if(target){
      body.innerHTML = buildRuleBody(target);
      body._built = true;
    }
  }
  var exp = card.classList.toggle('expanded');
  body.classList.toggle('open', exp);
}

function renderPorts(ports){
  var maxC=ports.length?ports[0].count:1;
  var html='';
  ports.forEach(function(p){
    var rc=riskColor(p.risk);
    var pct=Math.round(100*p.count/maxC);
    html+='<tr>';
    html+='<td><span class="port-num" style="color:'+rc+'">'+p.port+'</span></td>';
    html+='<td><span style="color:#a8c8e8">'+esc(p.svc)+'</span></td>';
    html+='<td><span class="risk-badge rb-'+p.risk+'">'+p.risk+'</span></td>';
    html+='<td class="mono">'+fmt(p.count)+'</td>';
    html+='<td><div class="port-bar-wrap"><div class="port-bar-fill" style="width:'+pct+'%;background:'+rc+'"></div></div></td>';
    html+='<td><span style="color:#6888a8;font-size:10px">'+esc(p.note)+'</span></td>';
    html+='</tr>';
  });
  document.getElementById('port-tbody').innerHTML=html;
}

function renderSrcIPs(src24){
  // Count total unique IPs across all subnets
  var totalIPs=0;
  src24.forEach(function(s){totalIPs+=s.src_n;});
  document.getElementById('src-cnt').textContent=totalIPs+' IPs across '+src24.length+' subnets';

  var html='';
  src24.forEach(function(s,idx){
    var portPills=s.ports.slice(0,6).map(function(p){return '<span class="port-pill">'+p+'</span>';}).join('');
    var pciTag=s.pci&&s.pci.indexOf('PCI')>=0?'<span class="sc-compliance sc-pci">PCI</span>':'';
    var siteStr = s.site || s.location || '';
    var metaStr = [s.facility, s.owner||s.bu].filter(Boolean).join(' · ');
    var hostsWithName = (s.ip_hosts||[]).filter(function(h){return h.hostname;}).length;
    var hostPct = s.src_n ? Math.round(100*hostsWithName/s.src_n) : 0;

    html += '<div class="subnet-group">';
    html += '<div class="sg-header" onclick="toggleSG('+idx+')">';
    html += '<span class="sg-cidr">'+esc(s.cidr)+'</span>';
    html += pciTag;
    if(s.unregistered){
      html += '<span class="sg-site" style="color:#ff8833;font-weight:600">⚠ Not in IPAM</span>';
    } else {
      html += '<span class="sg-site">'+esc(siteStr)+(metaStr?' &nbsp;·&nbsp; '+esc(metaStr):'')+'</span>';
    }
    html += '<span class="sg-meta">'+s.src_n+' IPs &nbsp;·&nbsp; '+s.count+' sessions';
    if(hostsWithName) html += ' &nbsp;·&nbsp; <span style="color:#3a7a3a">'+hostsWithName+' hostnames</span>';
    html += '</span>';
    html += '<span style="font-size:10px;color:#2a4a6a">'+portPills+'</span>';
    html += '<span class="sg-toggle" id="sg-arrow-'+idx+'">▶</span>';
    html += '</div>';

    // IP list — collapsed by default
    html += '<div class="sg-ips" id="sg-ips-'+idx+'">';
    // Subnet IPAM summary row
    html += '<div style="padding:6px 14px;background:#08101c;border-bottom:1px solid #1a2a3a;font-size:10px;color:#5a7a9a">';
    if(s.unregistered){
      html += '<span style="color:#ff8833;font-weight:600">Subnet '+esc(s.cidr)+' has no IPAM entry.</span>'
        +' <span style="color:#886633">Register in all_IP_networks to assign location, owner, and app context.</span>';
    } else {
      if(s.routing)   html += '<b>Routing:</b> '+esc(s.routing)+' &ensp;';
      if(s.net_type)  html += '<b>Net Type:</b> '+esc(s.net_type)+' &ensp;';
      if(s.compliance)html += '<b>Compliance:</b> '+esc(s.compliance.substring(0,40))+' &ensp;';
      if(s.apps_ipam) html += '<b>Apps (IPAM):</b> '+esc(s.apps_ipam.substring(0,60));
    }
    html += '</div>';
    // Individual IP rows
    (s.ip_hosts||[]).forEach(function(h){
      // Heritage + data source badges
      var hb='';
      if(h.heritage==='CVS')   hb='<span class="hbadge hb-cvs">CVS</span> ';
      else if(h.heritage==='AETNA') hb='<span class="hbadge hb-aetna">AETNA</span> ';
      else if(h.heritage==='HCB')   hb='<span class="hbadge hb-hcb">HCB</span> ';
      var ds='';
      if((h.in_snow||h.data_sources||'').indexOf('SNOW')>=0||h.in_snow==='Y') ds+='<span class="dsrc-badge dsrc-snow">SNOW</span>';
      if(h.in_qualys==='Y'||(h.data_sources||'').indexOf('ADL')>=0) ds+='<span class="dsrc-badge dsrc-adl">ADL</span>';
      if(h.in_wiz==='Y') ds+='<span class="dsrc-badge dsrc-wiz">WIZ</span>';
      html+='<div class="ip-row">';
      html+='<span class="ip-addr">'+esc(h.ip)+'</span>';
      if(h.hostname){
        html+='<span class="ip-host" title="'+(h.fqdn||h.hostname)+'">'+esc(h.hostname)+'</span>';
      } else {
        html+='<span class="ip-host ip-no-host">no hostname record</span>';
      }
      html+='<span class="ip-os">'+esc(h.os||'—')+'</span>';
      html+='<span class="ip-app" title="'+esc(h.app||'')+'">'+esc((h.app_acronym||h.app||'').substring(0,40)||'—')+'</span>';
      if(h.env) html+='<span class="ip-env">'+esc(h.env)+'</span>';
      if(h.bu)  html+='<span style="font-size:9px;color:#c8a060;margin-left:4px">'+esc(h.bu.substring(0,20))+'</span>';
      html+=hb+ds;
      html+='</div>';
      if(h.csna_path||h.apm_ids||h.dc_name){
        html+='<div style="padding:1px 14px 4px 134px;font-size:9px;display:flex;gap:14px">';
        if(h.csna_path) html+='<span class="ip-csna">'+esc(h.csna_path)+'</span>';
        if(h.apm_ids)   html+='<span style="color:#4a9a8a">'+esc(h.apm_ids.split('|')[0].trim())+'</span>';
        if(h.dc_name)   html+='<span style="color:#60a8c8">'+esc(h.dc_name)+'</span>';
        html+='</div>';
      }
    });
    html+='</div>';
    html+='</div>';
  });
  if(!html) html='<div style="padding:20px;color:#4a6a8a">No source data.</div>';
  document.getElementById('src-list').innerHTML=html;
}

function toggleSG(idx){
  var ips=document.getElementById('sg-ips-'+idx);
  var arr=document.getElementById('sg-arrow-'+idx);
  var open=ips.classList.toggle('open');
  arr.classList.toggle('open',open);
}

function renderDests(dests){
  document.getElementById('dest-cnt').textContent=dests.length;
  var html='';
  dests.forEach(function(d){
    var portPills=d.ports.slice(0,6).map(function(p){return '<span class="port-pill">'+p+'</span>';}).join('');
    var actions='<a href="https://rdap.arin.net/registry/ip/'+esc(d.ip)+'" target="_blank" style="color:#4ab;font-size:10px">ARIN</a> ';
    actions+='<a href="https://www.shodan.io/host/'+esc(d.ip)+'" target="_blank" style="color:#4ab;font-size:10px">Shodan</a>';
    html+='<tr>';
    // Country flag + risk indicator
    var ccDisp = d.country_code ? d.country_code : '';
    var riskFlag = (d.is_high_risk==='Y') ? ' <span style="color:#ff5555;font-size:9px;font-weight:700">⚠ HIGH-RISK</span>' : '';
    var countryDisp = ccDisp ? esc(ccDisp)+(d.country_name?' '+esc(d.country_name.substring(0,20)):'') : '—';
    var asnDisp = d.asn_display ? esc(d.asn_display.substring(0,35)) : (d.provider!=='Unknown'?esc(d.provider):'—');
    var cityDisp = d.city ? esc(d.city) : (d.region ? esc(d.region.substring(0,20)) : '—');
    var svcDisp = d.service || (d.svc_label&&d.svc_label!=='Cloud Infrastructure'?d.svc_label:'') || d.description || (d.provider!=='Unknown'?d.svc_label:'') || '—';
    var classColor = d.ds_class==='UNKNOWN'?'#ff8833':d.ds_class==='EXTERNAL'?'#aa88ff':'#44cc44';
    html+='<tr style="'+(d.is_high_risk==='Y'?'background:#1a0808':'')+'">';
    html+='<td class="mono" style="color:'+(d.is_high_risk==='Y'?'#ff7777':'#a8d8a8')+'">'+esc(d.ip)+'</td>';
    html+='<td>'+providerBadge(d.provider,'')+'</td>';
    html+='<td style="font-size:10px;color:#6888a8">'+esc(svcDisp.substring(0,30))+'</td>';
    html+='<td style="font-size:10px;color:#70a8c8">'+countryDisp+riskFlag+'</td>';
    html+='<td style="font-size:9px;color:#7090a8">'+cityDisp+'</td>';
    html+='<td style="font-size:9px;color:#507090">'+asnDisp+'</td>';
    html+='<td><span class="risk-badge" style="background:#0a1a0a;color:'+classColor+';border:1px solid '+classColor+40+'">'+esc(d.ds_class)+'</span></td>';
    html+='<td class="mono" style="color:#4a9a8a">'+fmt(d.count)+'</td>';
    html+='<td class="mono">'+fmt(d.src_n)+'</td>';
    html+='<td>'+portPills+'</td>';
    html+='<td>'+actions+'</td>';
    html+='</tr>';
  });
  document.getElementById('dest-tbody').innerHTML=html;
}

// Filter pills
document.querySelectorAll('.filter-pill').forEach(function(btn){
  btn.addEventListener('click',function(){
    document.querySelectorAll('.filter-pill').forEach(function(b){b.classList.remove('active');});
    btn.classList.add('active');
    curAction=btn.getAttribute('data-action')||'';
    renderRules();
  });
});
// v2.0 — debounced search (250ms) replaces the per-keystroke full re-render
document.getElementById('rule-search').addEventListener('input', debounce(function(){
  curRuleSearch=this.value.trim(); renderRules();
}, 250));



// ── Source Locations ──────────────────────────────────────────────────────────────────────────────
var _locRendered = false;
function renderLocBreakdown(){
  if(_locRendered) return;
  _locRendered = true;
  var loc = D.loc_breakdown || [];
  var el  = document.getElementById('loc-list');
  if(!loc.length){ el.innerHTML='<p style="color:#5a7a9a;font-size:11px">No location data available.</p>'; return; }

  var typeColors = {
    'CVS-DC':'cvs-dc','AETNA-DC':'aetna-dc','COLO':'colo','Corporate':'corporate',
    'Mail-Order':'mail-order','Call-Center':'call-center','Specialty':'specialty',
    'HCB':'hcb','Retail':'retail','Cloud':'cloud','Offshore':'offshore',
    'Remote':'remote','Unknown':'unknown','Unregistered':'unregistered'
  };

  var totalSites = loc.reduce(function(s,t){return s+t.sites;},0);
  document.getElementById('loc-cnt').textContent = loc.length+' types · '+totalSites+' sites';

  var html = '';
  loc.forEach(function(t, ti){
    var tc  = typeColors[t.type] || 'unknown';
    var tid = 'lt-'+ti;
    html += '<div style="margin-bottom:4px">'
      +'<div onclick="toggleLocType(&apos;'+tid+'&apos;)" '
      +'style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:#0d1a2e;border-radius:4px;cursor:pointer">'
      +'<span id="arr-'+tid+'" style="font-size:10px;color:#3a5a7a;display:inline-block;transition:transform .15s">▶</span>'
      +'<span class="lt-badge lt-'+tc+'">'+esc(t.type)+'</span>'
      +'<span style="font-size:11px;color:#c8d8e8;font-weight:600">'+t.sites+' site'+(t.sites!==1?'s':'')+'</span>'
      +(t.review>0?'<span style="font-size:9px;color:#ff8833;margin-left:6px">'+t.review+' REVIEW</span>':'')
      +(t.pci_rules>0?'<span style="font-size:9px;color:#ff4444;margin-left:4px">⚠ PCI</span>':'')
      +'</div>'
      +'<div id="'+tid+'" style="display:none;margin-left:16px;border-left:2px solid #1a2a3a;padding-left:12px;padding-top:4px">';

    t.sites_data.forEach(function(s, si){
      var sid = tid+'-s'+si;
      html += '<div style="margin-bottom:4px">'
        +'<div onclick="toggleLocSite(&apos;'+sid+'&apos;)" '
        +'style="display:flex;align-items:center;gap:8px;padding:6px 10px;background:#080f1a;border-radius:3px;cursor:pointer">'
        +'<span id="sarr-'+sid+'" style="font-size:9px;color:#3a5a7a;display:inline-block;transition:transform .15s">▶</span>'
        +'<span style="font-size:11px;color:#8aaacf">'+esc(s.site)+'</span>'
        +'<span style="font-size:10px;color:#3a5a7a">'+s.subnets.length+' subnet'+(s.subnets.length!==1?'s':'')+'</span>'
        +(s.review>0?'<span style="font-size:9px;color:#ff8833">'+s.review+' review</span>':'')
        +'</div>'
        +'<div id="subs-'+sid+'" style="display:none;margin-left:14px;border-left:1px solid #1a2a3a;padding:4px 0 4px 10px">';
      s.subnets.forEach(function(sub){
        html += '<div style="font-family:\'Courier New\',monospace;font-size:10px;color:#5a7a9a;padding:2px 0">'
          +esc(sub.cidr||'')+'</div>';
      });
      html += '</div></div>';
    });

    html += '</div></div>';
  });

  el.innerHTML = html;

  // Show download button if there are unregistered subnets
  var hasUnreg = (D.loc_breakdown||[]).some(function(t){ return t.type === 'Unregistered'; });
  var btn = document.getElementById('btn-unreg-csv');
  if(btn) btn.style.display = hasUnreg ? 'inline-block' : 'none';
}

function downloadUnregisteredCSV(){
  if(!D||!D.src24) return;
  var rows = [['CIDR','SRC_IP_COUNT','SESSION_COUNT','RULE_COUNT','REVIEW_RULES',
               'ALLOW_RULES','TOP_APPS','TOP_DEST_PORTS','TOP_DEST_PROVIDERS','RECOMMENDATION']];

  // Gather per-CIDR stats from rules where the IPAM lookup is unregistered
  var perCidr = {};
  (D.rules||[]).forEach(function(r){
    var ipam = r.ipam || {};
    if(ipam && !ipam.unregistered) return;  // skip registered
    var cidr = r.src24 || '';
    if(!cidr) return;
    if(!perCidr[cidr]) perCidr[cidr] = {ips:{},sess:0,rules:0,review:0,allow:0,apps:{},ports:{},provs:{}};
    var sd = perCidr[cidr];
    sd.sess  += r.count||0;
    sd.rules += 1;
    if(r.action==='REVIEW') sd.review++;
    if(r.action==='ALLOW')  sd.allow++;
    if(r.src_ip) sd.ips[r.src_ip]=1;
    (r.collapsed_hosts||[]).forEach(function(h){ if(h.ip) sd.ips[h.ip]=1; });
    (r.apps||[]).forEach(function(a){ if(a) sd.apps[a]=(sd.apps[a]||0)+(r.count||1); });
    if(r.dest_port) sd.ports[r.dest_port]=(sd.ports[r.dest_port]||0)+(r.count||1);
    var prov = getDest(r).provider||'';
    if(prov) sd.provs[prov]=(sd.provs[prov]||0)+(r.count||1);
  });

  function topN(obj, n){
    return Object.keys(obj).sort(function(a,b){return obj[b]-obj[a];}).slice(0,n).join('|');
  }

  Object.keys(perCidr).sort(function(a,b){
    return perCidr[b].sess - perCidr[a].sess;
  }).forEach(function(cidr){
    var sd = perCidr[cidr];
    rows.push([
      cidr,
      Object.keys(sd.ips).length,
      sd.sess, sd.rules, sd.review, sd.allow,
      topN(sd.apps,5), topN(sd.ports,5), topN(sd.provs,3),
      sd.review>0 ? 'URGENT — REVIEW traffic' : 'Register in all_IP_networks'
    ]);
  });

  if(rows.length <= 1){ alert('No unregistered subnets found in this report.'); return; }

  var csv = rows.map(function(r){
    return r.map(function(v){ return '"'+String(v).replace(/"/g,'""')+'"'; }).join(',');
  }).join('\r\n');

  var blob = new Blob([csv], {type:'text/csv'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'unregistered_subnets.csv';
  a.click();
  URL.revokeObjectURL(a.href);
}

function downloadUnknownHostsCSV(){
  if(!D||!D.rules) return;
  var rows = [['IP','SRC_CIDR','IPAM_LOCATION','IPAM_NET_TYPE','SUBNET_REGISTERED',
               'SESSION_COUNT','RULE_COUNT','REVIEW_RULES','ALLOW_RULES',
               'TOP_APPS','TOP_DEST_PORTS','TOP_DEST_PROVIDERS','RECOMMENDATION']];

  var perIp = {};

  function enrich(ip, r, hostSessions){
    if(!ip) return;
    if(!perIp[ip]) perIp[ip] = {src24:'',loc:'',ntype:'',unreg:false,
                                 sess:0,rules:0,review:0,allow:0,
                                 apps:{},ports:{},provs:{}};
    var sd = perIp[ip];
    var ipam = r.ipam || {};
    sd.src24 = sd.src24 || (r.src24||'');
    sd.loc   = sd.loc   || (ipam.location||ipam.site||'');
    sd.ntype = sd.ntype || (ipam.net_type||ipam.facility||'');
    if(ipam.unregistered) sd.unreg = true;
    sd.sess  += (hostSessions !== undefined ? hostSessions : (r.count||0));
    sd.rules += 1;
    if(r.action==='REVIEW') sd.review++;
    if(r.action==='ALLOW')  sd.allow++;
    (r.apps||[]).forEach(function(a){ if(a) sd.apps[a]=(sd.apps[a]||0)+(r.count||1); });
    if(r.dest_port) sd.ports[r.dest_port]=(sd.ports[r.dest_port]||0)+(r.count||1);
    var prov = getDest(r).provider||'';
    if(prov) sd.provs[prov]=(sd.provs[prov]||0)+(r.count||1);
  }

  D.rules.forEach(function(r){
    if(r.collapsed_n && r.collapsed_n > 1){
      (r.collapsed_hosts||[]).forEach(function(h){
        if(h.ip && !h.hostname) enrich(h.ip, r, h.count||0);
      });
    } else {
      if(r.src_ip && !r.hostname) enrich(r.src_ip, r);
    }
  });

  function topN(obj, n){
    return Object.keys(obj).sort(function(a,b){return obj[b]-obj[a];}).slice(0,n).join('|');
  }

  Object.keys(perIp).sort(function(a,b){
    return perIp[b].sess - perIp[a].sess;
  }).forEach(function(ip){
    var sd = perIp[ip];
    var reg = sd.unreg ? 'No' : 'Yes';
    var rec = sd.review>0 ? 'URGENT — REVIEW traffic; add to ent_host_master'
            : sd.unreg    ? 'Register subnet in IPAM then add host to ent_host_master'
            :               'Add to ent_host_master';
    rows.push([ip, sd.src24, sd.loc, sd.ntype, reg,
               sd.sess, sd.rules, sd.review, sd.allow,
               topN(sd.apps,5), topN(sd.ports,5), topN(sd.provs,3), rec]);
  });

  if(rows.length <= 1){ alert('No unknown hosts found in this report.'); return; }

  var csv = rows.map(function(r){
    return r.map(function(v){ return '"'+String(v).replace(/"/g,'""')+'"'; }).join(',');
  }).join('\r\n');

  var blob = new Blob([csv], {type:'text/csv'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'unknown_hosts.csv';
  a.click();
  URL.revokeObjectURL(a.href);
}

function toggleLocType(tid){
  var panel = document.getElementById(tid);
  var arrow = document.getElementById('arr-'+tid);
  if(!panel) return;
  var open = panel.style.display === 'none';
  panel.style.display = open ? 'block' : 'none';
  if(arrow) arrow.style.transform = open ? 'rotate(90deg)' : '';
}

function toggleLocSite(sid){
  var panel = document.getElementById('subs-'+sid);
  var arrow = document.getElementById('sarr-'+sid);
  if(!panel) return;
  var open = panel.style.display === 'none';
  panel.style.display = open ? 'block' : 'none';
  if(arrow) arrow.style.transform = open ? 'rotate(90deg)' : '';
}

// ── Flow Map ──────────────────────────────────────────────────────────────────
var flowView  = 'sankey';
var flowGroup = 'provider';
var flowNodes = [], flowEdges = [];
var selFlowNode = null;

var PROV_COLORS = {
  'Amazon Web Services': '#ff9900',
  'Google':              '#4285f4',
  'Microsoft Azure':     '#00a1f1',
  'CrowdStrike':         '#e6223b',
  'Unknown':             '#484f58',
};

var SC_COLORS = {
  'DC-OWNED':  '#1f6feb', 'DC-COLO':   '#388bfd', 'CLOUD':    '#3fb950',
  'RETAIL':    '#e3b341', 'DISTRO':    '#ffa657', 'SPECIALTY':'#ff9a6c',
  'CORPORATE': '#a5a5f5', 'VPN':       '#39d353', 'UNKNOWN':  '#484f58',
};

function setFlowView(v, btn){
  flowView=v;
  document.querySelectorAll('#flow-controls .filter-pill').forEach(function(b){
    if(['Sankey','Arc'].indexOf(b.textContent)>=0) b.classList.remove('active');
  });
  btn.classList.add('active');
  renderFlowMap();
}
function setFlowGroup(g, btn){
  flowGroup=g;
  document.querySelectorAll('[data-fg]').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  renderFlowMap();
}

function buildFlowData(){
  if(!D||!D.rules) return;
  var minSess = parseInt(document.getElementById('flow-min-sess').value)||1;
  var edgeMap = {};   // 'srcLoc|||destNode' -> {sessions,rules,dest_ips,src_sc}

  D.rules.forEach(function(r){
    var ipam = r.ipam||{};
    var dest = r.dest||{};
    // Source node: location or site or site_class
    var srcLoc = (ipam.location||'').trim() || (ipam.site||'').trim() || 'Unknown';
    var srcSC  = (ipam.site_class||'UNKNOWN').trim();
    // Dest node: depends on flowGroup
    var destNode;
    if(flowGroup==='provider'){
      destNode = dest.provider&&dest.provider!=='Unknown' ? dest.provider : 'Unknown / Unclassified';
    } else if(flowGroup==='region'){
      destNode = dest.region ? (dest.provider||'?')+' / '+dest.region : (dest.provider||'Unknown')+' / No Region';
    } else {
      destNode = r.dest_ip;
    }
    var key = srcLoc+'|||'+destNode;
    if(!edgeMap[key]) edgeMap[key]={sessions:0,rules:0,dest_ips:{},src_sc:srcSC,src_loc:srcLoc,dest_node:destNode};
    edgeMap[key].sessions   += r.count;
    edgeMap[key].rules      += 1;
    edgeMap[key].dest_ips[r.dest_ip]=1;
  });

  // Filter by minSess
  var edges=Object.values(edgeMap).filter(function(e){return e.sessions>=minSess;});

  // Build node lists
  var srcSet={}, dstSet={};
  edges.forEach(function(e){
    if(!srcSet[e.src_loc]) srcSet[e.src_loc]={label:e.src_loc,sc:e.src_sc,total:0,type:'src'};
    srcSet[e.src_loc].total+=e.sessions;
    if(!dstSet[e.dest_node]) dstSet[e.dest_node]={label:e.dest_node,total:0,type:'dst'};
    dstSet[e.dest_node].total+=e.sessions;
  });

  flowNodes = Object.values(srcSet).sort(function(a,b){return b.total-a.total;})
    .concat(Object.values(dstSet).sort(function(a,b){return b.total-a.total;}));
  flowEdges = edges.sort(function(a,b){return b.sessions-a.sessions;});
}

function renderFlowMap(){
  buildFlowData();
  if(flowView==='sankey') drawSankey();
  else drawArc();
  buildFlowLegend();
}

// ── Sankey drawing ────────────────────────────────────────────────────────────
function drawSankey(){
  var cv=document.getElementById('flow-canvas');
  var ctx=cv.getContext('2d');
  var W=Math.max(300, cv.parentElement.clientWidth-300||600);
  cv.style.width=W+'px'; // prevent CSS stretch scaling
  var srcNodes=flowNodes.filter(function(n){return n.type==='src';});
  var dstNodes=flowNodes.filter(function(n){return n.type==='dst';});
  var ROW_H=22, PAD=4;
  var H=Math.max(srcNodes.length,dstNodes.length)*ROW_H+80;
  cv.width=W; cv.height=H;
  cv.style.height=H+'px';
  ctx.clearRect(0,0,W,H);

  var COL1=4, COL2=W*0.38, COL3=W*0.62, COL4=W-4;
  var LBL_W=COL2-COL1-8, RBL_W=COL4-COL3-8;

  // Layout source nodes
  var srcY={}, srcH={};
  var totSrc=srcNodes.reduce(function(s,n){return s+n.total;},0)||1;
  var availH=H-60;
  var sy=30;
  srcNodes.forEach(function(n,i){
    var h=Math.max(ROW_H-PAD, Math.round((n.total/totSrc)*availH));
    srcY[n.label]=sy; srcH[n.label]=h; sy+=h+PAD;
  });

  // Layout dest nodes
  var dstY={}, dstH={};
  var totDst=dstNodes.reduce(function(s,n){return s+n.total;},0)||1;
  var dy=30;
  dstNodes.forEach(function(n,i){
    var h=Math.max(ROW_H-PAD, Math.round((n.total/totDst)*availH));
    dstY[n.label]=dy; dstH[n.label]=h; dy+=h+PAD;
  });

  // Draw edges (bezier curves)
  var srcOffset={}, dstOffset={};
  srcNodes.forEach(function(n){srcOffset[n.label]=0;});
  dstNodes.forEach(function(n){dstOffset[n.label]=0;});

  flowEdges.forEach(function(e){
    if(!srcY.hasOwnProperty(e.src_loc)||!dstY.hasOwnProperty(e.dest_node)) return;
    var totS=srcNodes.find(function(n){return n.label===e.src_loc;});
    var totD=dstNodes.find(function(n){return n.label===e.dest_node;});
    if(!totS||!totD) return;

    var sh=Math.max(1,Math.round(srcH[e.src_loc]*(e.sessions/totS.total)));
    var dh=Math.max(1,Math.round(dstH[e.dest_node]*(e.sessions/totD.total)));
    var x1=COL2, y1=srcY[e.src_loc]+srcOffset[e.src_loc];
    var x2=COL3, y2=dstY[e.dest_node]+dstOffset[e.dest_node];

    var prov=e.dest_node.split(' / ')[0];
    var col=PROV_COLORS[prov]||'#484f58';
    var alpha=Math.max(0.08, Math.min(0.45, e.sessions/2000));
    ctx.strokeStyle=col; ctx.lineWidth=Math.max(1,sh); ctx.globalAlpha=alpha;
    ctx.beginPath();
    ctx.moveTo(x1,y1+sh/2);
    var mx=(x1+x2)/2;
    ctx.bezierCurveTo(mx,y1+sh/2, mx,y2+dh/2, x2,y2+dh/2);
    ctx.stroke();
    ctx.globalAlpha=1;

    srcOffset[e.src_loc]+=sh;
    dstOffset[e.dest_node]+=dh;
  });

  // Draw source bars
  srcNodes.forEach(function(n){
    var col=SC_COLORS[n.sc]||'#484f58';
    var y=srcY[n.label], h=srcH[n.label];
    ctx.fillStyle=col; ctx.globalAlpha=selFlowNode===n.label?1:0.85;
    ctx.fillRect(COL1,y,COL2-COL1-4,h);
    ctx.globalAlpha=1;
    ctx.fillStyle='#e6edf3'; ctx.font='10px Segoe UI';
    ctx.textBaseline='middle'; ctx.textAlign='left';
    var lbl=n.label.length>28?n.label.substring(0,26)+'…':n.label;
    ctx.fillText(lbl, COL1+4, y+h/2);
    ctx.fillStyle='#4a9a8a'; ctx.textAlign='right';
    ctx.fillText(fmtN(n.total), COL2-8, y+h/2);
  });

  // Draw dest bars
  dstNodes.forEach(function(n){
    var prov=n.label.split(' / ')[0];
    var col=PROV_COLORS[prov]||'#484f58';
    var y=dstY[n.label], h=dstH[n.label];
    ctx.fillStyle=col; ctx.globalAlpha=selFlowNode===n.label?1:0.85;
    ctx.fillRect(COL3,y,COL4-COL3,h);
    ctx.globalAlpha=1;
    ctx.fillStyle='#e6edf3'; ctx.font='10px Segoe UI';
    ctx.textBaseline='middle'; ctx.textAlign='left';
    var lbl=n.label.length>26?n.label.substring(0,24)+'…':n.label;
    ctx.fillText(lbl, COL3+4, y+h/2);
    ctx.fillStyle='#4a9a8a'; ctx.textAlign='right'; ctx.font='9px Segoe UI';
    ctx.fillText(fmtN(n.total), COL4-2, y+h/2);
  });

  // Column labels
  ctx.fillStyle='#5a7a9a'; ctx.font='bold 10px Segoe UI'; ctx.textAlign='center'; ctx.textBaseline='top';
  ctx.fillText('SOURCE LOCATION', (COL1+COL2)/2, 6);
  ctx.fillText('DESTINATION', (COL3+COL4)/2, 6);

  // Store layout for click detection
  cv._srcY=srcY; cv._srcH=srcH; cv._dstY=dstY; cv._dstH=dstH;
  cv._colBounds={COL1,COL2,COL3,COL4};
}

// ── Arc / chord drawing ───────────────────────────────────────────────────────
function drawArc(){
  var cv=document.getElementById('flow-canvas');
  var ctx=cv.getContext('2d');
  var W=Math.max(300, cv.parentElement.clientWidth-300||600);
  var H=Math.min(W,600);
  cv.width=W; cv.height=H;
  cv.style.width=W+'px'; cv.style.height=H+'px'; // prevent CSS stretch scaling
  ctx.clearRect(0,0,W,H);

  var CX=W/2, CY=H/2, R=Math.min(W,H)/2-85;
  var NODE_R=7; // hit radius

  // All nodes arranged in a circle
  var srcNodes=flowNodes.filter(function(n){return n.type==='src';}).slice(0,24);
  var dstNodes=flowNodes.filter(function(n){return n.type==='dst';});
  var allNodes=srcNodes.concat(dstNodes);
  var total=allNodes.length||1;
  var angleStep=(2*Math.PI)/total;

  // Build position map and store on canvas for hit-testing
  var arcNodePos={}; // label -> {x,y,type,sc}
  allNodes.forEach(function(n,i){
    var a=i*angleStep - Math.PI/2;
    arcNodePos[n.label]={x:CX+R*Math.cos(a), y:CY+R*Math.sin(a), a:a, type:n.type, sc:n.sc||''};
  });
  cv._arcNodePos=arcNodePos;
  cv._srcY=null; // clear sankey layout so click handler uses arc path

  // Determine which edges involve the selected node (for highlight)
  var selEdges={};
  if(selFlowNode&&arcNodePos[selFlowNode]){
    flowEdges.forEach(function(e){
      if(e.src_loc===selFlowNode||e.dest_node===selFlowNode) selEdges[e.src_loc+'|||'+e.dest_node]=1;
    });
  }
  var hasSel=Object.keys(selEdges).length>0;

  // Draw arcs
  flowEdges.slice(0,120).forEach(function(e){
    var p1=arcNodePos[e.src_loc], p2=arcNodePos[e.dest_node];
    if(!p1||!p2) return;
    var prov=e.dest_node.split(' / ')[0];
    var col=PROV_COLORS[prov]||'#484f58';
    var key=e.src_loc+'|||'+e.dest_node;
    var isSel=selEdges[key];
    var alpha, lw;
    if(hasSel){
      alpha=isSel?Math.max(0.5,Math.min(0.9,e.sessions/1000)):0.04;
      lw=isSel?Math.max(1.5,Math.min(5,Math.log(e.sessions+1)*0.8)):0.5;
    } else {
      alpha=Math.max(0.06,Math.min(0.35,e.sessions/3000));
      lw=Math.max(0.5,Math.min(4,Math.log(e.sessions+1)*0.6));
    }
    ctx.strokeStyle=col; ctx.lineWidth=lw; ctx.globalAlpha=alpha;
    ctx.beginPath();
    ctx.moveTo(p1.x,p1.y);
    ctx.quadraticCurveTo(CX,CY,p2.x,p2.y);
    ctx.stroke();
    ctx.globalAlpha=1;
  });

  // Draw nodes
  allNodes.forEach(function(n){
    var p=arcNodePos[n.label]; if(!p) return;
    var col=n.type==='src'?(SC_COLORS[n.sc]||'#484f58'):(PROV_COLORS[n.label.split(' / ')[0]]||'#484f58');
    var isSel=(selFlowNode===n.label);
    var r=isSel?NODE_R+3:NODE_R;

    // Glow ring on selected
    if(isSel){
      ctx.strokeStyle=col; ctx.lineWidth=2; ctx.globalAlpha=0.7;
      ctx.beginPath(); ctx.arc(p.x,p.y,r+4,0,2*Math.PI); ctx.stroke();
      ctx.globalAlpha=1;
    }
    ctx.fillStyle=col;
    ctx.globalAlpha=hasSel&&!isSel&&!selEdges[n.label+'|||*']?0.35:0.92;
    ctx.beginPath(); ctx.arc(p.x,p.y,r,0,2*Math.PI); ctx.fill();
    ctx.globalAlpha=1;

    // Label
    var lbl=n.label.length>20?n.label.substring(0,18)+'…':n.label;
    var lx=CX+(R+NODE_R+8)*Math.cos(p.a), ly=CY+(R+NODE_R+8)*Math.sin(p.a);
    ctx.fillStyle=isSel?'#ffffff':(hasSel?'#4a6a8a':'#a8c8e8');
    ctx.font=(isSel?'bold ':'')+'9px Segoe UI';
    ctx.textAlign=Math.cos(p.a)>0.1?'left':Math.cos(p.a)<-0.1?'right':'center';
    ctx.textBaseline=Math.sin(p.a)>0.1?'top':Math.sin(p.a)<-0.1?'bottom':'middle';
    ctx.fillText(lbl,lx,ly);
  });
}

// ── Legend ────────────────────────────────────────────────────────────────────
function buildFlowLegend(){
  var html='<span style="color:#5a7a9a;font-weight:700;margin-right:4px">Src class:</span>';
  Object.entries(SC_COLORS).forEach(function(e){
    html+='<span style="display:inline-flex;align-items:center;gap:3px;margin-right:8px">'+
          '<span style="width:10px;height:10px;border-radius:2px;background:'+e[1]+';display:inline-block"></span>'+
          '<span>'+e[0]+'</span></span>';
  });
  html+='&ensp;<span style="color:#5a7a9a;font-weight:700;margin-right:4px">Dest:</span>';
  Object.entries(PROV_COLORS).forEach(function(e){
    html+='<span style="display:inline-flex;align-items:center;gap:3px;margin-right:8px">'+
          '<span style="width:10px;height:10px;border-radius:2px;background:'+e[1]+';display:inline-block"></span>'+
          '<span>'+e[0]+'</span></span>';
  });
  document.getElementById('flow-legend').innerHTML=html;
}

// ── Click handler — wired in DOMContentLoaded to guarantee element exists ──────
function initFlowCanvas(){
  var cv=document.getElementById('flow-canvas');
  if(!cv) return;
  // Delegated listener for "Sessions →" buttons in flow detail panel
  var fd=document.getElementById('flow-detail');
  if(fd){
    fd.addEventListener('click',function(e){
      var btn=e.target.closest('.flow-sess-btn');
      if(!btn) return;
      var srcLoc =btn.getAttribute('data-src');
      var destNode=btn.getAttribute('data-dst');
      showFlowSessions(srcLoc, destNode, srcLoc+' → '+destNode);
    });
  }

  cv.addEventListener('click',function(e){
    var rect=cv.getBoundingClientRect();
    // Scale from CSS pixels to canvas pixel space (canvas may be CSS-stretched)
    var scaleX = cv.width  / (rect.width  || cv.width);
    var scaleY = cv.height / (rect.height || cv.height);
    var mx=(e.clientX-rect.left)*scaleX, my=(e.clientY-rect.top)*scaleY;
    var hit=null, hitType=null;

    if(flowView==='chord' && cv._arcNodePos){
      // Arc mode — hit-test against stored circle node positions
      var SNAP=18; // click tolerance in px
      var best=null, bestDist=SNAP*SNAP;
      for(var lbl in cv._arcNodePos){
        var p=cv._arcNodePos[lbl];
        var dx=mx-p.x, dy=my-p.y, d2=dx*dx+dy*dy;
        if(d2<bestDist){bestDist=d2;best={lbl:lbl,type:p.type};}
      }
      if(best){hit=best.lbl; hitType=best.type;}
      selFlowNode=hit;
      if(hit) showFlowDetail(hit, hitType);
      else document.getElementById('flow-detail').innerHTML='<div style="color:#3a5a7a;font-size:11px">Click a node to see flow detail.</div>';
      drawArc();
    } else if(flowView==='sankey' && cv._srcY){
      // Sankey mode — hit-test against bar rectangles
      var b=cv._colBounds; if(!b) return;
      if(mx>=b.COL1&&mx<=b.COL2){
        for(var lbl in cv._srcY){
          if(my>=cv._srcY[lbl]&&my<=cv._srcY[lbl]+cv._srcH[lbl]){hit=lbl;hitType='src';break;}
        }
      } else if(mx>=b.COL3&&mx<=b.COL4){
        for(var lbl in cv._dstY){
          if(my>=cv._dstY[lbl]&&my<=cv._dstY[lbl]+cv._dstH[lbl]){hit=lbl;hitType='dst';break;}
        }
      }
      selFlowNode=hit;
      if(hit) showFlowDetail(hit, hitType);
      else document.getElementById('flow-detail').innerHTML='<div style="color:#3a5a7a;font-size:11px">Click a node to see flow detail.</div>';
      drawSankey();
    }
  });
}


function showFlowSessions(srcLoc, destNode, title){
  // Find the matching rules for this exact src location → dest node pair
  showSessionModal('Sessions: '+title, function(r){
    var ipam = r.ipam||{};
    var dest = r.dest||{};
    var rSrcLoc = (ipam.location||'').trim() || (ipam.site||'').trim() || 'Unknown';
    var rDest;
    if(flowGroup==='provider'){
      rDest = dest.provider&&dest.provider!=='Unknown' ? dest.provider : 'Unknown / Unclassified';
    } else if(flowGroup==='region'){
      rDest = dest.region ? (dest.provider||'?')+' / '+dest.region : (dest.provider||'Unknown')+' / No Region';
    } else {
      rDest = r.dest_ip;
    }
    return rSrcLoc===srcLoc && rDest===destNode;
  });
}

function showFlowDetail(label, type){
  var panel=document.getElementById('flow-detail');
  var edges=flowEdges.filter(function(e){
    return type==='src'?e.src_loc===label:e.dest_node===label;
  }).sort(function(a,b){return b.sessions-a.sessions;});

  if(!edges.length){
    // Node label might differ from what's in flowEdges — try a loose match
    var lbl_lc=label.toLowerCase();
    edges=flowEdges.filter(function(e){
      return type==='src'?e.src_loc.toLowerCase()===lbl_lc:e.dest_node.toLowerCase()===lbl_lc;
    });
  }
  if(!edges.length){
    panel.innerHTML='<div style="color:#4a6a8a;font-size:11px">No flow data for <b>'+esc(label)+'</b>.<br>'+
      '<span style="font-size:10px;color:#3a5a7a">This node may have been filtered by the min-sessions threshold. Try lowering the filter.</span></div>';
    return;
  }

  var total=edges.reduce(function(s,e){return s+e.sessions;},0);
  var rules =edges.reduce(function(s,e){return s+e.rules;},0);
  var allIPs={}; edges.forEach(function(e){Object.assign(allIPs,e.dest_ips);});

  var html='<div style="font-size:12px;font-weight:700;color:#e8f0f8;margin-bottom:4px">'+esc(label)+'</div>';
  html+='<div style="font-size:10px;color:#6888a8;margin-bottom:10px">';
  html+=fmtN(total)+' sessions &middot; '+rules+' rules';
  if(type==='src') html+=' &middot; '+Object.keys(allIPs).length+' dest IPs';
  html+='</div>';

  edges.forEach(function(e){
    var prov=type==='src'?e.dest_node:e.src_loc;
    var col=PROV_COLORS[prov.split(' / ')[0]]||SC_COLORS[e.src_sc]||'#484f58';
    var pct=Math.round(100*e.sessions/total);
    html+='<div style="margin-bottom:8px">';
    html+='<div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:2px">';
    html+='<span style="color:#a8c8e8;max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(prov)+'">'+esc(prov)+'</span>';
    html+='<span style="color:#4a9a8a;font-family:\'Courier New\',monospace">'+fmtN(e.sessions)+'</span>';
    html+='</div>';
    html+='<div style="height:5px;background:#1a2a3a;border-radius:3px;overflow:hidden">';
    html+='<div style="height:100%;width:'+pct+'%;background:'+col+';border-radius:3px"></div></div>';
    // Drill-down: click to open session modal filtered to this src→dest pair
    html+='<div style="display:flex;justify-content:space-between;font-size:9px;color:#3a5a7a;margin-top:2px">';
    html+='<span>'+e.rules+' rules &middot; '+Object.keys(e.dest_ips).length+' IPs</span>';
    html+='<button class="flow-sess-btn" '
         +'data-src="'+esc(e.src_loc)+'" '
         +'data-dst="'+esc(e.dest_node)+'" '
         +'style="background:#0d2040;border:1px solid #1a4a6a;color:#4a9acf;font-size:9px;'
         +'padding:1px 6px;border-radius:3px;cursor:pointer">Sessions →</button>';
    html+='</div>';
    html+='</div>';
  });

  panel.innerHTML=html;
}

// Wire flow map rendering when tab is activated
// Done via a simple post-call in navTo itself (no risky override needed)
var _flowMapReady = false;

// ── Log Event Modal ──────────────────────────────────────────────────────────
function closeModal(){
  document.getElementById('modal-overlay').classList.remove('open');
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeModal();});

function endClass(r){
  if(!r)return 'end-aged';
  if(r==='tcp-fin')return 'end-fin';
  if(r.indexOf('rst')>=0)return 'end-rst';
  return 'end-aged';
}

function showSessionModal(title, filterFn){
  if(!D||!D.rules) return;
  var matching = D.rules.filter(filterFn);
  matching.sort(function(a,b){return b.count-a.count;});

  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-sub').textContent =
    matching.length + ' rule(s) — ' + matching.reduce(function(s,r){return s+r.count;},0) + ' total sessions';

  if(!matching.length){
    document.getElementById('modal-body').innerHTML='<div class="modal-empty">No matching sessions found.</div>';
    document.getElementById('modal-overlay').classList.add('open');
    return;
  }

  var html='<table class="log-table"><thead><tr>';
  html+='<th>Action</th><th>Src IP</th><th>Src Hostname</th><th>Src Application</th>';
  html+='<th>Dest IP</th><th>:Port / Service</th><th>Dest Provider</th>';
  html+='<th>Sessions</th><th>Pkts Out</th><th>Pkts In</th><th>Close Reason</th>';
  html+='</tr></thead><tbody>';

  matching.forEach(function(r){
    var end=(r.end_reasons||[])[0]||'';
    var dest=r.dest||{};
    var ipam=r.ipam||{};
    var srcApp=r.src_app||(ipam.app_acronyms||'').split('|')[0].trim()||'';
    var provStr=dest.provider&&dest.provider!=='Unknown'
      ? dest.provider+(dest.service&&dest.service!==dest.provider?' / '+dest.service:'')
      : '— unclassified';

    html+='<tr>';
    // Action
    html+='<td><span class="lt-action ab-'+r.action+'">'+esc(r.action)+'</span></td>';
    // Src IP
    html+='<td class="lt-ip">'+esc(r.src_ip)+'</td>';
    // Src Hostname
    html+='<td class="lt-host" title="'+esc(r.hostname||'')+'">'+esc(r.hostname||'—')+'</td>';
    // Src App
    html+='<td class="lt-app-name" title="'+esc(srcApp)+'">'+esc(srcApp||'—')+'</td>';
    // Dest IP
    html+='<td class="lt-dest">'+esc(r.dest_ip)+'</td>';
    // Port / Service
    html+='<td><span style="font-family:\'Courier New\',monospace;color:#c8d8e8">:'+r.dest_port+'</span>';
    if(r.svc&&r.svc!=='Port-'+r.dest_port) html+=' <span style="font-size:10px;color:#8aa8c8">'+esc(r.svc)+'</span>';
    html+='</td>';
    // Dest Provider
    html+='<td class="lt-provider" title="'+esc(provStr)+'">'+esc(provStr)+'</td>';
    // Sessions
    html+='<td class="lt-pkts">'+fmt(r.count)+'</td>';
    // Pkts out / in
    html+='<td class="lt-pkts">'+fmt(r.pkts_out)+'</td>';
    html+='<td class="lt-pkts">'+fmt(r.pkts_in)+'</td>';
    // Close reason
    html+='<td class="lt-end"><span class="'+endClass(end)+'">'+esc(end||'aged-out')+'</span></td>';
    html+='</tr>';
  });

  html+='</tbody></table>';
  document.getElementById('modal-body').innerHTML=html;
  document.getElementById('modal-overlay').classList.add('open');
}

// Predefined filter functions for each finding type
var FINDING_FILTERS = {
  'pci':          function(r){ var p=r.ipam&&r.ipam.pci||''; return p.indexOf('PCI')>=0; },
  'unknown':      function(r){ return !r.dest||r.dest.ds_class==='UNKNOWN'||r.dest.provider==='Unknown'; },
  'unregistered': function(r){ return r.ipam&&r.ipam.unregistered===true; },
  'review':   function(r){ return r.action==='REVIEW'; },
  'block':    function(r){ return r.action==='BLOCK'; },
  'monitor':  function(r){ return r.action==='MONITOR'; },
  'allow':    function(r){ return r.action==='ALLOW'; },
  'rst':      function(r){ return (r.end_reasons||[]).some(function(e){return e.indexOf('rst')>=0;}); },
  'aged':     function(r){ return (r.end_reasons||[]).some(function(e){return e==='aged-out';}) && r.total_pkts>100; },
  'cloud':    function(r){ return r.dest&&r.dest.ds_class!=='UNKNOWN'&&r.dest.provider!=='Unknown'; },
  'all':      function(r){ return true; },
};

function showFindingSessions(filterKey, title){
  var fn = FINDING_FILTERS[filterKey] || FINDING_FILTERS['all'];
  showSessionModal(title, fn);
}

// Init
decomp('D').then(function(data){
  D=data;
  // Hydrate rules with transparent ipam/dest getters so the rest of the
  // template can keep using r.ipam / r.dest without caring about dedup.
  // (rules_by_action contains integer indices into D.rules, not rule objects,
  // so only D.rules needs hydration.)
  if(D&&D.rules) hydrateRules(D.rules);
  renderStats(D.stats);
  renderFunnel(D.funnel, D.stats);
  renderFindings(D.findings);
  _initRulesDelegation();   // v2.0 — single click listener on the rules list
  renderRules();
  renderPorts(D.ports);
  renderSrcIPs(D.src24);
  renderDests(D.dests);
  initFlowCanvas();
});

// ── RFC Violations table ───────────────────────────────────────────────────
function renderRfcTable(){
  var rfcData = D.rfc || [];
  var tbody = document.getElementById('rfc-tbody');
  var empty = document.getElementById('rfc-empty');
  if(!rfcData.length){
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  var html = '';
  rfcData.forEach(function(v){
    var tierColor = {PROBE:'#ff8800',LIGHT:'#3a6a8a',NORMAL:'#2a6a5a',ACTIVE:'#1a7a3a',BULK:'#0a6a7a'};
    var tc = tierColor[v.tier] || '#3a5a7a';
    html += '<tr style="border-bottom:1px solid #1a2a3a;background:#0d0a0a">'
          + '<td style="padding:5px 10px;color:#ff9999;font-family:monospace">'+esc(v.src_ip)+'</td>'
          + '<td style="padding:5px 10px;color:#8a9aaa">'+esc(v.src_zone)+'</td>'
          + '<td style="padding:5px 10px;color:#ff6666;font-weight:700;font-family:monospace">'+esc(v.dst_ip)+'</td>'
          + '<td style="padding:5px 10px;color:#8a9aaa">'+esc(v.dst_zone)+'</td>'
          + '<td style="padding:5px 10px;color:#c8a870">'+esc(String(v.port))+'</td>'
          + '<td style="padding:5px 10px;color:#7a9aba">'+esc(v.app||'—')+'</td>'
          + '<td style="padding:5px 10px"><span style="background:#3a0a0a;color:#ff6666;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">'+esc(v.rfc||'?')+'</span></td>'
          + '<td style="padding:5px 10px;color:#6a8a7a;font-size:10px">'+esc(v.desc||'')+'</td>'
          + '<td style="padding:5px 10px"><span style="background:'+tc+';color:#fff;font-size:9px;padding:1px 5px;border-radius:3px">'+esc(v.tier||'?')+'</span></td>'
          + '<td style="padding:5px 10px;text-align:right;color:#ff9999;font-weight:700">'+fmt(v.count)+'</td>'
          + '<td style="padding:5px 4px;text-align:right;color:#8aaa88">'+fmt(v.pkts_out)+'</td>'
          + '<td style="padding:5px 4px;text-align:right;color:#8a88aa">'+fmt(v.pkts_in)+'</td>'
          + '</tr>';
  });
  tbody.innerHTML = html;
}

// ── Optimized Policy table ─────────────────────────────────────────────────
var _policyRendered = false;
function renderPolicyTable(){
  if(_policyRendered) return;
  _policyRendered = true;
  var policy = D.policy || [];
  var host = document.getElementById('policy-host');
  if(!policy.length){
    host.innerHTML='<div style="padding:24px;text-align:center;color:#5a7a9a">No policy recommendations generated — requires ALLOW or REVIEW rules with per-host source IPs.</div>';
    return;
  }

  // Build address object inventories for the summary header
  var srcObjs = {}, dstObjs = {}, svcObjs = {}, srcGroups = {};
  policy.forEach(function(p){
    srcGroups[p.src_group] = 1;
    dstObjs[p.dest_obj]   = 1;
    var svcKey = 'SVC-' + (p.ports[0]||'any') + '-' + (p.pa_app||'any').toUpperCase().replace(/-/g,'').substr(0,10);
    svcObjs[svcKey] = 1;
    (p.src_hosts||[]).forEach(function(h){ if(h.obj) srcObjs[h.obj]=1; });
  });

  var summary = '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">';
  function stat(n,lbl,color){
    return '<div style="background:#0d1526;border:1px solid #1a2a3a;border-radius:6px;padding:10px 16px;text-align:center">'
      +'<div style="font-size:22px;font-weight:700;font-family:\'Courier New\',monospace;color:'+color+'">'+n+'</div>'
      +'<div style="font-size:9px;color:#5a7a9a;text-transform:uppercase;letter-spacing:.5px;margin-top:2px">'+lbl+'</div></div>';
  }
  summary += stat(policy.length,     'Security Rules',    '#4ab8f8');
  var blockCount = policy.filter(function(p){ return p.action==='BLOCK'; }).length;
  if(blockCount) summary += stat(blockCount, 'BLOCK Rules (RFC)', '#ff4444');
  summary += stat(Object.keys(srcObjs).length,  'Host Addr Objects', '#79c0ff');
  summary += stat(Object.keys(srcGroups).length,'Source Groups',     '#c8a8e8');
  summary += stat(Object.keys(dstObjs).length,  'Dest Svc Objects',  '#44cc88');
  summary += stat(Object.keys(svcObjs).length,  'Service Objects',   '#ffcc33');
  summary += '</div>';

  var html = '';
  policy.forEach(function(p, idx){
    var actColor = p.action==='ALLOW'  ? '#44cc44'
                 : p.action==='REVIEW' ? '#ffaa33'
                 : p.action==='BLOCK'  ? '#ff4444'
                 : '#ff6644';
    var isRfcBlock = p.is_rfc_block === true;

    // Rule card
    html += '<div style="background:#0d1a2e;border:1px solid '+(isRfcBlock?'#3a0a0a':'#1a2a3a')+';'
          + (isRfcBlock?'border-left:3px solid #ff4444;':'')
          + 'border-radius:6px;margin-bottom:8px;overflow:hidden">';

    // ── Header row ──
    html += '<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer" onclick="togglePolicy('+idx+')">';
    html += '<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;background:'+actColor+'22;color:'+actColor+';letter-spacing:.3px;flex-shrink:0">'+esc(p.action)+'</span>';
    html += '<span style="font-family:\'Courier New\',monospace;font-size:11px;font-weight:700;color:#e8f0f8;flex:1">'+esc(p.rule_name)+'</span>';
    html += '<span style="font-size:9px;padding:1px 6px;border-radius:3px;background:#1a2a1a;color:#6ac878;flex-shrink:0">'+esc(p.pa_app)+'</span>';
    if(p._pa_apps_all && p._pa_apps_all.length > 1){
      html += '<span style="font-size:8px;color:#4a6a4a;margin-left:3px">+'+String(p._pa_apps_all.length-1)+' apps</span>';
    }
    html += '<span style="font-size:10px;color:#4a9a8a;font-family:\'Courier New\',monospace;flex-shrink:0">'+fmt(p.sessions)+' sess</span>';
    html += '<span style="font-size:11px;color:#3a5a7a;flex-shrink:0" id="parr-'+idx+'">▶</span>';
    html += '</div>';

    // ── Quick-glance identity row ──
    html += '<div style="display:flex;gap:0;padding:0 14px 8px;flex-wrap:wrap;border-top:1px solid #0f1e2e">';

    // Source group
    html += '<div style="padding:5px 14px 5px 0;border-right:1px solid #1a2a3a;margin-right:14px">';
    html += '<div style="font-size:8px;color:#3a5a7a;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px">Src Group</div>';
    html += '<div style="font-size:10px;color:#c8a8e8;font-family:\'Courier New\',monospace">'+esc(p.src_group)+'</div>';
    html += '<div style="font-size:9px;color:#5a7a9a;margin-top:1px">'+esc(p.src_app)+' · '+esc(p.src_env)+' · '+esc(p.src_site.split(' - ').pop())+'</div>';
    html += '</div>';

    // Arrow
    html += '<div style="padding:5px 10px;align-self:center;color:#4a6a8a;font-size:16px">→</div>';

    // Dest object
    html += '<div style="padding:5px 14px 5px 0;border-right:1px solid #1a2a3a;margin-right:14px">';
    html += '<div style="font-size:8px;color:#3a5a7a;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px">Dest Object</div>';
    html += '<div style="font-size:10px;font-family:\'Courier New\',monospace;color:'+(isRfcBlock?'#ff6644':'#44cc88')+'">'+esc(p.dest_obj)+'</div>';
    html += '<div style="font-size:9px;color:#5a7a9a;margin-top:1px">'+esc(p.dest_provider)+(p.dest_svc_label?' · '+esc(p.dest_svc_label):'')+'</div>';
    html += '</div>';

    // Service
    html += '<div style="padding:5px 14px 5px 0;border-right:1px solid #1a2a3a;margin-right:14px">';
    html += '<div style="font-size:8px;color:#3a5a7a;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px">Service / Port</div>';
    html += '<div style="font-size:10px;color:#c8a870;font-family:\'Courier New\',monospace">'+(isRfcBlock?'any (all ports)':esc(p.ports.join(', ')))+'</div>';
    html += '<div style="font-size:9px;color:#5a7a9a;margin-top:1px">app-id: '+esc(p.pa_app)+'</div>';
    html += '</div>';

    // Host count — or RFC investigation note
    html += '<div style="padding:5px 0">';
    if(isRfcBlock){
      html += '<div style="font-size:8px;color:#ff6644;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px">Investigation Required</div>';
      html += '<div style="font-size:10px;color:#ff8833;font-weight:700">Route leak / NAT failure</div>';
      html += '<div style="font-size:9px;color:#8a5a3a;margin-top:1px">'+((p.src_hosts||[]).length)+' src hosts · '+((p.dest_ips||[]).length)+' bogon dest IPs</div>';
    } else {
      html += '<div style="font-size:8px;color:#3a5a7a;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px">Src Hosts (/32)</div>';
      html += '<div style="font-size:10px;color:#79c0ff;font-weight:700">'+((p.src_hosts||[]).length)+' host objects</div>';
      html += '<div style="font-size:9px;color:#5a7a9a;margin-top:1px">'+((p.dest_ips||[]).length)+' dest IPs</div>';
    }
    html += '</div>';

    html += '</div>'; // end identity row

    // ── Expanded body (hidden by default) ──
    html += '<div id="pbody-'+idx+'" style="display:none;border-top:1px solid '+(isRfcBlock?'#3a0a0a':'#1a2a3a')+'">';
    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:14px">';

    // Left: PA rule spec
    html += '<div>';
    if(isRfcBlock){
      html += '<div style="font-size:9px;color:#ff6644;text-transform:uppercase;letter-spacing:.6px;font-weight:700;margin-bottom:8px">⛔ RFC Violation — Explicit BLOCK Required</div>';
      html += '<div style="font-size:11px;color:#cc8833;background:#1a0a00;border:1px solid #3a1500;border-radius:4px;padding:10px;margin-bottom:10px;line-height:1.7">'
             +'Private/bogon addresses ('+esc(p.rfc_class||'RFC1918')+') detected in outside zone. '
             +'This indicates a <b>route leak</b>, <b>NAT failure</b>, or <b>misconfigured VPN split-tunnel</b>.<br><br>'
             +'<b>Investigate:</b> Which firewall or router is forwarding RFC-private traffic to the outside zone? '
             +'Check NAT rules, default routes, and VPN configurations on sources listed.<br><br>'
             +'<b>Create PA address object:</b> <span style="font-family:\'Courier New\',monospace;color:#ff8833">'
             +esc(p.dest_obj||'')+'</span>'
             +(p.addr_ranges ? '<br><span style="font-size:9px;color:#886633">Ranges: '+esc(p.addr_ranges)+'</span>' : '')
             +'</div>';
    } else {
      html += '<div style="font-size:9px;color:#5a7a9a;text-transform:uppercase;letter-spacing:.6px;font-weight:700;margin-bottom:8px">PA Policy Rule (suggested)</div>';
    }
    html += '<div style="font-family:\'Courier New\',monospace;font-size:11px;background:#06101a;border:1px solid '+(isRfcBlock?'#3a0a0a':'#1a2a3a')+';border-radius:4px;padding:10px;line-height:1.8;white-space:pre">';
    var portVal = isRfcBlock ? 'any'
               : (p.dest_svc_type === 'MEDIA-NAT') ? 'any  # UDP hole-punching — dynamic ports'
               : (p.ports && p.ports.length === 1 && p.ports[0]) ? p.ports[0]
               : 'application-default';
    var appVal  = isRfcBlock ? 'any' : esc(p.pa_app||'any');
    var appComment = (p._pa_apps_all && p._pa_apps_all.length > 1)
                   ? '  # also observed: '+esc(p._pa_apps_all.slice(1,4).join(', '))
                       +(p._pa_apps_all.length > 4 ? ' +more' : '')
                   : '';
    html += '<span style="color:#5a9acf">policy-rule</span> {\n';
    html += '  <span style="color:#5a9acf">name</span>            = <span style="color:#c8d8e8">"'+esc(p.rule_name)+'"</span>;\n';
    html += '  <span style="color:#5a9acf">action</span>          = <span style="color:'+actColor+';font-weight:700">'+esc(p.action)+'</span>;\n';
    html += '  <span style="color:#5a9acf">source-address</span>  = <span style="color:#c8a8e8">"'+esc(p.src_group)+'"</span>;  <span style="color:#3a5a7a"># '+((p.src_hosts||[]).length)+' affected hosts</span>\n';
    html += '  <span style="color:#5a9acf">dest-address</span>    = <span style="color:'+(isRfcBlock?'#ff6644':'#44cc88')+'">"'+esc(p.dest_obj)+'"</span>;  <span style="color:#3a5a7a"># '+esc(p.rfc_class||p.dest_provider).substring(0,50)+' </span>\n';
    html += '  <span style="color:#5a9acf">dest-port</span>       = <span style="color:#c8a870">'+portVal+'</span>;\n';
    html += '  <span style="color:#5a9acf">application</span>     = <span style="color:#6ac878">"'+appVal+'"</span><span style="color:#3a5a7a">'+appComment+'</span>;\n';
    html += '  <span style="color:#5a9acf">log-start</span>       = yes;\n';
    html += '  <span style="color:#5a9acf">log-end</span>         = yes;\n';
    if(isRfcBlock){
      html += '  <span style="color:#5a9acf">log-setting</span>     = <span style="color:#c8a870">"security-alert"</span>;\n';
    }
    html += '}';
    html += '</div>';
    if(p.cpc_service) html += '<div style="margin-top:8px;font-size:10px;color:#44cc88">✓ CPC covered: '+esc(p.cpc_service)+'</div>';
    html += '</div>'; // end left

    // Right: Source host objects + Dest IPs
    html += '<div>';

    // Source host objects table
    html += '<div style="font-size:9px;color:#5a7a9a;text-transform:uppercase;letter-spacing:.6px;font-weight:700;margin-bottom:6px">Source Host Objects — '+esc(p.src_group)+'</div>';
    html += '<div style="max-height:200px;overflow-y:auto;background:#06101a;border:1px solid #1a2a3a;border-radius:4px">';
    (p.src_hosts||[]).slice(0,50).forEach(function(h){
      html += '<div style="display:flex;align-items:center;gap:8px;padding:4px 8px;border-bottom:1px solid #0f1e2e;font-size:10px">';
      html += '<span style="font-family:\'Courier New\',monospace;color:#79c0ff;flex-shrink:0">'+esc(h.obj||'')+'</span>';
      if(h.hostname) html += '<span style="color:#a8c8e8;font-size:9px">'+esc(h.hostname)+'</span>';
      html += '</div>';
    });
    if((p.src_hosts||[]).length > 50){
      html += '<div style="padding:4px 8px;font-size:9px;color:#4a6a7a">+'+String((p.src_hosts.length-50))+' more host objects</div>';
    }
    html += '</div>';

    // Dest IPs (collapsed)
    html += '<div style="font-size:9px;color:#5a7a9a;text-transform:uppercase;letter-spacing:.6px;font-weight:700;margin-top:10px;margin-bottom:6px">Destination IPs — '+esc(p.dest_obj)+'</div>';
    html += '<div style="font-family:\'Courier New\',monospace;font-size:10px;color:#5a9a5a;background:#06101a;border:1px solid #1a2a3a;border-radius:4px;padding:6px 8px;max-height:120px;overflow-y:auto">';
    (p.dest_ips||[]).forEach(function(ip){ html += esc(ip)+'<br>'; });
    html += '</div>';

    html += '</div>'; // end right
    html += '</div>'; // end grid
    html += '</div>'; // end pbody

    html += '</div>'; // end card
  });

  host.innerHTML = summary + html;
}

function togglePolicy(idx){
  var body  = document.getElementById('pbody-'+idx);
  var arrow = document.getElementById('parr-'+idx);
  if(!body) return;
  var open = body.style.display === 'none';
  body.style.display = open ? 'block' : 'none';
  if(arrow) arrow.style.transform = open ? 'rotate(90deg)' : '';
}
</script>

<!-- ── Flow Map ── -->
<div class="section" id="sec-flow">
  <h2>🗺 Location → Destination Flow Map</h2>
  <div id="flow-controls" style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
    <span style="font-size:10px;color:#5a7a9a">View:</span>
    <button class="filter-pill active" onclick="setFlowView('sankey',this)">Sankey</button>
    <button class="filter-pill" onclick="setFlowView('chord',this)">Arc</button>
    <span style="font-size:10px;color:#5a7a9a;margin-left:8px">Group by:</span>
    <button class="filter-pill active" data-fg="provider" onclick="setFlowGroup('provider',this)">Provider</button>
    <button class="filter-pill" data-fg="region" onclick="setFlowGroup('region',this)">Region</button>
    <button class="filter-pill" data-fg="ip" onclick="setFlowGroup('ip',this)">Dest IP</button>
    <span style="font-size:10px;color:#5a7a9a;margin-left:8px">Min sessions:</span>
    <select id="flow-min-sess" onchange="renderFlowMap()" style="background:#0d1526;border:1px solid #1a2a3a;color:#c8d8e8;font-size:11px;padding:3px 6px;border-radius:4px">
      <option value="1">All</option>
      <option value="5">≥ 5</option>
      <option value="20" selected>≥ 20</option>
      <option value="100">≥ 100</option>
      <option value="500">≥ 500</option>
    </select>
  </div>
  <div style="display:flex;gap:12px;min-height:0">
    <div style="flex:1;min-width:0">
      <canvas id="flow-canvas" style="width:100%;border:1px solid #1a2a3a;border-radius:6px;background:#08101c;display:block"></canvas>
    </div>
    <div id="flow-detail" style="width:280px;flex-shrink:0;background:#0d1526;border:1px solid #1a2a3a;border-radius:6px;padding:12px;font-size:11px;overflow-y:auto;max-height:600px">
      <div style="color:#3a5a7a;font-size:11px">Click a source or destination node to see flow detail.</div>
    </div>
  </div>
  <div id="flow-legend" style="display:flex;gap:12px;margin-top:10px;flex-wrap:wrap;font-size:10px;color:#6888a8"></div>
</div>

<!-- ── RFC Violations ── -->
<div class="section" id="sec-rfc">
  <h2>⛔ RFC Address Space Violations</h2>
  <p style="color:#8aa0c0;font-size:12px;margin-bottom:16px">
    Sessions where the destination is RFC1918/bogon private address space but the traffic is destined for an outside/internet zone.
    These represent route leaks, NAT failures, or spoofed packets — each requires immediate investigation.
  </p>
  <div id="rfc-table-wrap">
    <table style="width:100%;border-collapse:collapse;font-size:11px">
      <thead>
        <tr style="background:#1a0a0a;color:#ff8888;text-align:left">
          <th style="padding:6px 10px">Source IP</th>
          <th style="padding:6px 10px">Src Zone</th>
          <th style="padding:6px 10px">Dest IP</th>
          <th style="padding:6px 10px">Dst Zone</th>
          <th style="padding:6px 10px">Port</th>
          <th style="padding:6px 10px">App</th>
          <th style="padding:6px 10px">RFC</th>
          <th style="padding:6px 10px">Description</th>
          <th style="padding:6px 10px">Tier</th>
          <th style="padding:6px 4px;text-align:right">Sessions</th>
          <th style="padding:6px 4px;text-align:right">Pkts Out</th>
          <th style="padding:6px 4px;text-align:right">Pkts In</th>
        </tr>
      </thead>
      <tbody id="rfc-tbody"></tbody>
    </table>
    <div id="rfc-empty" style="display:none;color:#5a7a9a;padding:24px;text-align:center;font-size:13px">
      ✅ No RFC address space violations detected in this log.
    </div>
  </div>
</div>

<!-- ── Optimized Policy ── -->
<div class="section" id="sec-policy">
  <h2>📐 App/Server Intent Policy — /32 Source-Based Rules</h2>
  <p style="color:#8aa0c0;font-size:12px;margin-bottom:12px">
    Each card = one proposed Palo Alto security rule derived from observed ALLOW/REVIEW traffic.
    Source objects are individual <b>/32 host addresses</b> grouped into address groups by application × environment × site.
    Destination objects are named by cloud provider + service type.
    Validate against intended application connectivity before implementing.
  </p>
  <div id="policy-host"></div>
</div>

<!-- ── Log Event Modal ── -->
<div id="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div id="modal-box">
    <div id="modal-head">
      <div>
        <div id="modal-title">Session Log Events</div>
        <div id="modal-sub"></div>
      </div>
      <button id="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div id="modal-body"></div>
  </div>
</div>

</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────────────────


# ── Splunk query generator ────────────────────────────────────────────────────

def check_files(dataset_dir, ip_dataset_dir, out_dir):
    """Scan for all required and optional data files and print a status report."""
    import os, glob as _glob
    _idd = ip_dataset_dir or os.path.join(dataset_dir, 'ipdatasets')

    OK   = '  ✓  '
    WARN = '  ⚠  '
    MISS = '  ✗  '
    SEP  = '─' * 72

    def find(pattern, directory):
        def _ver_key(f):
            import re as _r
            m = _r.search(r'_v(\d+)[._](\d+)', f)
            if m: return (int(m.group(1)), int(m.group(2)))
            m2 = _r.search(r'_v(\d+)', f)
            return (0, int(m2.group(1))) if m2 else (0,0)
        matches = sorted(_glob.glob(os.path.join(directory, pattern)), key=_ver_key)
        return matches

    print()
    print('=' * 72)
    print('  generate_fw_rule_report.py -- File Check')
    print('=' * 72)

    all_ok = True

    # ── Dataset dir ────────────────────────────────────────────────────────────
    print(f'\n  Dataset dir:     {os.path.abspath(dataset_dir)}')
    _idd = _idd or os.path.join(dataset_dir, 'ipdatasets')
    print(f'  IP dataset dir:  {os.path.abspath(_idd)}')
    print(f'  Output dir:      {os.path.abspath(out_dir)}')
    print()
    print(SEP)
    print('  REQUIRED FILES')
    print(SEP)

    # all_IP_networks — v4.0 single source of truth (cidr_24 abolished)
    all_ipnet = find('all_IP_networks_v*.csv', dataset_dir)
    if all_ipnet:
        f = all_ipnet[-1]
        sz = os.path.getsize(f) // 1024
        print(f'{OK}all_IP_networks  {os.path.basename(f)}  ({sz:,} KB)  [SSOT v4.0 — LPM enrichment]')
        if len(all_ipnet) > 1:
            print(f'       (using newest of {len(all_ipnet)} versions found)')
    else:
        all_ok = False
        print(f'{MISS}all_IP_networks  NOT FOUND in {dataset_dir}')
        print(f'       Expected:  all_IP_networks_v*.csv  (v3.14+)')
        print(f'       Impact:    Source IPs will have no site/location/PCI context')
        print(f'       NOTE:      cidr_24 is permanently abolished — do not substitute')

    # VPN partner subnets (optional)
    vpn_files = find('vpn_protected_subnets*.csv', dataset_dir) + \
                find('ent-ipdataset-S2S-VPN-PARTNERS*.csv', dataset_dir)
    if vpn_files:
        f = vpn_files[-1]
        sz = os.path.getsize(f) // 1024
        print(f'{OK}vpn_partners     {os.path.basename(f)}  ({sz:,} KB)  [S2S partner subnet enrichment]')
    else:
        print(f'{INFO}vpn_partners     not found — copy vpn_protected_subnets.csv to dataset_dir')

    # ENT host dataset
    ent_files = find('ent-ipdataset-*.csv', dataset_dir)
    if ent_files:
        for ef in ent_files:
            sz = os.path.getsize(ef) // 1024
            print(f'{OK}ENT host dataset {os.path.basename(ef)}  ({sz:,} KB)  [hostname/app lookup]')
    else:
        all_ok = False
        print(f'{MISS}ENT host dataset NOT FOUND in {dataset_dir}')
        print(f'       Expected:  ent-ipdataset-*.csv')
        print(f'       Impact:    No hostnames or application names on rule cards.')

    print()
    print(SEP)
    print('  OPTIONAL — IP DATASETS (destination enrichment)')
    print(SEP)

    # ip_dataset files
    ds_files = find('ip_dataset_*.csv', _idd)
    if ds_files:
        # Peek at provider names
        providers = {}
        for fp in ds_files:
            try:
                with open(fp, newline='', encoding='utf-8', errors='replace') as fh:
                    import csv as _csv
                    reader = _csv.DictReader(l for l in fh if not l.startswith("#"))
                    for row in reader:
                        if row.get('PROVIDER','').strip() and not row.get('PROVIDER','').startswith('#'):
                            providers[fp] = row.get('PROVIDER','').strip()
                            break
            except Exception:
                pass
        for fp in ds_files:
            sz = os.path.getsize(fp) // 1024
            prov = providers.get(fp, 'Unknown provider')
            print(f'{OK}ip_dataset       {os.path.basename(fp):45s}  ({sz:,} KB)  [{prov}]')
    else:
        print(f'{WARN}ip_dataset       NOT FOUND in {_idd}')
        print(f'       Expected:  ip_dataset_*.csv  (registered via ip_dataset.py)')
        print(f'       Impact:    All destinations will show as Unknown / Unclassified.')
        print(f'                  Rule actions default to REVIEW for unknown destinations.')

    # ── Enterprise/partner datasets ────────────────────────────────────────────
    ent_ds = find('ent-ipdataset-VPN-*.csv', _idd) +              find('ent-ipdataset-VPN-*.csv', dataset_dir)
    if ent_ds:
        print()
        for fp in set(ent_ds):
            sz = os.path.getsize(fp) // 1024
            print(f'{OK}ENT ip_dataset   {os.path.basename(fp):45s}  ({sz:,} KB)  [S2S-VPN partners]')

    print()
    print(SEP)
    print('  OPTIONAL — GEOIP (country / ASN / high-risk flagging)')
    print(SEP)

    # geo_ip.py — must be co-located with the report script
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    geo_py_path = os.path.join(script_dir, 'geo_ip.py')
    if not os.path.isfile(geo_py_path):
        print(f'{WARN}geo_ip.py        NOT FOUND at {geo_py_path}')
        print(f'       Impact:    No country/ASN enrichment on destination IPs.')
        print(f'                  High-risk country escalation disabled.')
        print(f'                  Rule cards will show no geo context.')
    else:
        # Try to actually load and check for data files
        try:
            import importlib.util as _ilu
            _spec = _ilu.spec_from_file_location('geo_ip', geo_py_path)
            _mod  = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            geo = _mod.GeoIPLookup(dataset_dir, load_us_geo=True)
            if geo.is_loaded():
                st = geo.stats()
                print(f'{OK}geo_ip.py        {geo_py_path}')
                print(f'       GeoIP loaded: {st["networks"]:,} country CIDRs, '
                      f'{st["asn"]:,} ASN records')
                if st.get("us_geo"):
                    print(f'       US city/state geo: {st["us_geo"]:,} records')
            else:
                print(f'{WARN}geo_ip.py        found at {geo_py_path}')
                print(f'       GeoIP data files NOT FOUND in {dataset_dir}')
                print(f'       Impact:    No country/ASN/city enrichment on destinations.')
                print(f'                  High-risk country escalation disabled.')
                print(f'       Fix:       Run build_us_geo_datasets.py or place GeoIP')
                print(f'                  CSV files in {dataset_dir}')
        except Exception as _ge:
            print(f'{WARN}geo_ip.py        found but failed to load: {_ge}')
            print(f'       Impact:    Destination geo enrichment disabled.')

    print()
    print(SEP)
    print('  OPTIONAL — ENRICHMENT MODULES')
    print(SEP)

    # fw_app_taxonomy.csv
    tax_path = os.path.join(dataset_dir, 'fw_app_taxonomy.csv')
    if os.path.isfile(tax_path):
        sz = os.path.getsize(tax_path) // 1024
        with open(tax_path, newline='', encoding='utf-8', errors='replace') as _tf:
            import csv as _csv2
            n = sum(1 for _ in _csv2.DictReader(l for l in _tf if not l.startswith('#')))
        print(f'{OK}fw_app_taxonomy  fw_app_taxonomy.csv  ({sz} KB, {n} App-ID entries)')
    else:
        print(f'{WARN}fw_app_taxonomy  NOT FOUND — built-in App-ID rules only')
        print(f'       Expected:  {tax_path}')

    # parse_hostname.py
    ph_path = os.path.join(script_dir, 'parse_hostname.py')
    if os.path.isfile(ph_path):
        print(f'{OK}parse_hostname   parse_hostname.py  [hostname → site/env enrichment]')
    else:
        print(f'{WARN}parse_hostname   NOT FOUND — site/env from hostname disabled')

    # all_IP_networks (preferred over cidr_24 — listed as bonus)
    all_ip = find('all_IP_networks_v*.csv', dataset_dir)
    if all_ip:
        f  = all_ip[-1]
        sz = os.path.getsize(f) // 1024
        print(f'{OK}all_IP_networks  {os.path.basename(f)}  ({sz:,} KB)  '
              f'[all_IP_networks v4.0 — single source of truth]')
        if len(all_ip) > 1:
            print(f'       ({len(all_ip)} versions available)')
    else:
        print(f'{WARN}all_IP_networks  loaded (single source of truth — v4.0)')
    print(SEP)
    if os.path.isdir(out_dir):
        existing = sorted(_glob.glob(os.path.join(out_dir, 'fw_report_*.html')), key=_ver_key)
        print(f'{OK}Output dir exists: {os.path.abspath(out_dir)}')
        if existing:
            print(f'       {len(existing)} existing report(s) found:')
            for rp in existing[-3:]:
                sz = os.path.getsize(rp) // 1024
                print(f'         {os.path.basename(rp)}  ({sz:,} KB)')
            if len(existing) > 3:
                print(f'         ... and {len(existing)-3} more')
        else:
            print(f'       No existing reports.')
    else:
        print(f'{OK}Output dir will be created: {os.path.abspath(out_dir)}')

    print()
    print(SEP)
    print(f'  SUMMARY: {"READY — all required files found." if all_ok else "ACTION NEEDED — see missing files above (marked with ✗)."}')
    print(SEP)
    print()

    if all_ok:
        print('  Run the report:')
        print(f'    python generate_fw_rule_report.py \\')
        print(f'        --log YOUR_LOG.csv \\')
        print(f'        --dataset-dir {dataset_dir} \\')
        print(f'        --ip-dataset-dir {_idd}')
    else:
        print('  Use ip_dataset.py to register cloud provider ranges:')
        print('    python ip_dataset.py --import azure_servicetags.json')
        print('    python ip_dataset.py --import gcp_cloud_ips.csv')
        print('    python ip_dataset.py --E VPN-PARTNER --import partner_report.html')
    print()


def print_splunk_queries():
    """Print sample Splunk SPL queries for all supported log schemas."""

    DIVIDER = '─' * 78

    print()
    print('=' * 78)
    print('  generate_fw_rule_report.py — Splunk SPL Query Reference')
    print('  Supported schemas: FULL (packet counts) | FLOW (src_port, no packets)')
    print('=' * 78)

    # ── Common header ──────────────────────────────────────────────────────────
    print("""
OVERVIEW
  Two log schemas are supported. The tool auto-detects which schema a CSV file
  uses based on column presence:

    FULL schema   packets_out + packets_in present — full session detail.
                  The --min-pkts filter (default 10) is applied to identify
                  established sessions vs SYN-only / half-open traffic.

    FLOW schema   src_port present, no packet columns — pre-aggregated
                  TCP-FIN flow records. Every row is treated as established.
                  Use this schema when Splunk has already aggregated sessions.

  Both schemas require these core fields:
    src_ip, src_zone, dest_ip, dest_zone, dest_port, dvc,
    session_end_reason, flags, app
""")

    print(DIVIDER)

    # ══════════════════════════════════════════════════════════════════════════
    # SCHEMA 1 — FULL (packets_out / packets_in)
    # ══════════════════════════════════════════════════════════════════════════
    print("""
SCHEMA 1 — FULL (packets_out + packets_in)
  Use when you need the packet-level lifecycle funnel (SYN-only, half-open,
  established) or want to tune the --min-pkts threshold.

  Required output columns:
    src_ip, src_zone, dest_ip, dest_zone, dest_port,
    packets_out, packets_in, dvc, session_end_reason, flags, app

──────────────────────────────────────────────────────────────────────────────
Query 1A — Non-standard ports, NOT TCP-FIN (scan/recon/aged-out traffic)
  Produces: NOT_80_OR_443_NOT_TCP-FIN.csv
──────────────────────────────────────────────────────────────────────────────
  index=pan_logs sourcetype=pan:traffic
      dest_port!=80 dest_port!=443
      session_end_reason!=tcp-fin
  | where src_port > 1024
  | stats
      sum(packets_out) AS packets_out
      sum(packets_in)  AS packets_in
      values(src_zone) AS src_zone
      values(dest_zone) AS dest_zone
      values(dvc)      AS dvc
      values(session_end_reason) AS session_end_reason
      values(flags)    AS flags
      values(app)      AS app
      by src_ip dest_ip dest_port
  | table src_ip src_zone dest_ip dest_zone dest_port
          packets_out packets_in dvc session_end_reason flags app

──────────────────────────────────────────────────────────────────────────────
Query 1B — Non-standard ports, WITH TCP-FIN (completed sessions only)
  Produces: NOT_80_OR_443_AND_TCP-FIN.csv
──────────────────────────────────────────────────────────────────────────────
  index=pan_logs sourcetype=pan:traffic
      dest_port!=80 dest_port!=443
      session_end_reason=tcp-fin
  | where src_port > 1024
  | stats
      sum(packets_out) AS packets_out
      sum(packets_in)  AS packets_in
      values(src_zone) AS src_zone
      values(dest_zone) AS dest_zone
      values(dvc)      AS dvc
      values(session_end_reason) AS session_end_reason
      values(flags)    AS flags
      values(app)      AS app
      by src_ip dest_ip dest_port
  | table src_ip src_zone dest_ip dest_zone dest_port
          packets_out packets_in dvc session_end_reason flags app

──────────────────────────────────────────────────────────────────────────────
Query 1C — Ports 80 and 443 only, NOT TCP-FIN (QUIC / UDP web traffic)
  Produces: 80_and_443_NOT_TCP-FIN.csv
──────────────────────────────────────────────────────────────────────────────
  index=pan_logs sourcetype=pan:traffic
      (dest_port=80 OR dest_port=443)
      session_end_reason!=tcp-fin
  | stats
      sum(packets_out) AS packets_out
      sum(packets_in)  AS packets_in
      values(src_zone) AS src_zone
      values(dest_zone) AS dest_zone
      values(dvc)      AS dvc
      values(session_end_reason) AS session_end_reason
      values(flags)    AS flags
      values(app)      AS app
      by src_ip dest_ip dest_port
  | table src_ip src_zone dest_ip dest_zone dest_port
          packets_out packets_in dvc session_end_reason flags app
""")

    print(DIVIDER)

    # ══════════════════════════════════════════════════════════════════════════
    # SCHEMA 2 — FLOW (src_port, no packet counts)
    # ══════════════════════════════════════════════════════════════════════════
    print("""
SCHEMA 2 — FLOW (src_port + session_end_reason=tcp-fin, no packet counts)
  Use for pre-aggregated, confirmed TCP-FIN sessions. Splunk deduplicates
  by (src_ip, src_port, dest_ip, dest_port) so each row = one flow.
  The tool treats every row as an established session automatically.

  Required output columns:
    src_ip, src_port, src_zone, dest_ip, dest_port, dest_zone,
    dvc, flags, app, session_end_reason
  Optional: fields (Splunk metadata — always null, safe to include)

──────────────────────────────────────────────────────────────────────────────
Query 2A — All ports, TCP-FIN only, src_port > 1023 (full day, all traffic)
  Produces: 1day_src-to-dest_tcp-fin_all_ports.csv
──────────────────────────────────────────────────────────────────────────────
  index=pan_logs sourcetype=pan:traffic
      session_end_reason=tcp-fin
  | where src_port > 1023
  | dedup src_ip src_port dest_ip dest_port
  | table src_ip src_port src_zone dest_ip dest_port dest_zone
          dvc flags fields app session_end_reason

──────────────────────────────────────────────────────────────────────────────
Query 2B — Non-standard ports only (< 1024), TCP-FIN, src_port > 1023
  Produces: 1day_src-to-dest_tcp-fin_less1024.csv
  Note: "less1024" refers to dest_port < 1024 (well-known service ports)
──────────────────────────────────────────────────────────────────────────────
  index=pan_logs sourcetype=pan:traffic
      session_end_reason=tcp-fin
  | where src_port > 1023 AND dest_port < 1024
  | dedup src_ip src_port dest_ip dest_port
  | table src_ip src_port src_zone dest_ip dest_port dest_zone
          dvc flags fields app session_end_reason

──────────────────────────────────────────────────────────────────────────────
Query 2C — High-risk port subset, TCP-FIN (targeted hunt)
  Use when you want to focus only on sensitive service ports.
──────────────────────────────────────────────────────────────────────────────
  index=pan_logs sourcetype=pan:traffic
      session_end_reason=tcp-fin
      (dest_port=25  OR dest_port=23  OR dest_port=135 OR dest_port=139 OR
       dest_port=445 OR dest_port=3389 OR dest_port=5900 OR dest_port=993 OR
       dest_port=389 OR dest_port=8089 OR dest_port=5061 OR dest_port=5228)
  | where src_port > 1023
  | dedup src_ip src_port dest_ip dest_port
  | table src_ip src_port src_zone dest_ip dest_port dest_zone
          dvc flags fields app session_end_reason
""")

    print(DIVIDER)

    # ══════════════════════════════════════════════════════════════════════════
    # Time-bounding and index guidance
    # ══════════════════════════════════════════════════════════════════════════
    print("""
TIME BOUNDING
  Add a time range to any query using the earliest/latest tokens:

  index=pan_logs sourcetype=pan:traffic earliest=-24h latest=now ...

  Or use the Splunk time picker and omit earliest/latest entirely.
  For a rolling 7-day baseline:

  index=pan_logs sourcetype=pan:traffic earliest=-7d@d latest=@d ...

FIREWALL INDEX / SOURCETYPE
  Adjust index and sourcetype to match your Splunk environment:

    PA-OS syslog (direct):   sourcetype=pan:traffic
    PA-OS via Splunk TA:     sourcetype=pan:traffic  (same)
    Cisco ASA:               sourcetype=cisco:asa  (field names differ)
    Generic syslog:          sourcetype=syslog  (requires field extractions)

  The tool uses these field names exactly as exported from Splunk.
  If your field names differ, add a rename step before the table command:

  | rename src_address AS src_ip, dst_address AS dest_ip, dst_port AS dest_port

EXPORTING FROM SPLUNK
  Run the query in Splunk Web → click Export → select CSV.
  The CSV must include a header row (Splunk exports this by default).
  File encoding must be UTF-8.

SUPPORTED DEVICE TYPES
  The tool is firewall/device agnostic — any Splunk log source that produces
  the required fields works. Tested with:
    • Palo Alto Networks PA-Series (PAZSHDC-SEC-EXTWIR-PA-01)
    • Palo Alto Panorama-pushed policy logs
  The dvc field is captured and shown in reports but not used for filtering.

RUNNING THE REPORT
  After exporting your CSV(s) from Splunk:

  # FULL schema (with packet counts) — established sessions only
  python generate_fw_rule_report.py \
      --log NOT_80_OR_443_NOT_TCP-FIN.csv \
      --dataset-dir /path/to/ipam \
      --ip-dataset-dir /path/to/ip_datasets \
      --min-pkts 10

  # FLOW schema (TCP-FIN pre-aggregated) — all rows used
  python generate_fw_rule_report.py \
      --log 1day_src-to-dest_tcp-fin_all_ports.csv \
      --dataset-dir /path/to/ipam \
      --ip-dataset-dir /path/to/ip_datasets

  # Multiple files in one report
  python generate_fw_rule_report.py \
      --log file1.csv file2.csv \
      --dataset-dir /path/to/ipam \
      --ip-dataset-dir /path/to/ip_datasets

  # Dry run — stats only, no HTML written
  python generate_fw_rule_report.py --log file.csv --dry-run -v
""")
    print('=' * 78)
    print()


def write_unknown_hosts_csv(rule_list, out_path):
    """Write a CSV of all source IPs with no enterprise hostname record.

    Covers two cases:
      1. Per-host rules (src_ip present, hostname blank)
      2. Collapsed MONITOR rules — individual hosts in collapsed_hosts
         that have no hostname

    Columns:
      IP, SRC_CIDR, IPAM_LOCATION, IPAM_NET_TYPE, SUBNET_REGISTERED,
      SESSION_COUNT, RULE_COUNT, REVIEW_RULES, ALLOW_RULES,
      TOP_APPS, TOP_DEST_PORTS, TOP_DEST_PROVIDERS, RECOMMENDATION
    """
    import csv as _csv
    from collections import defaultdict as _dd, Counter as _Ctr

    per_ip = _dd(lambda: {
        'src24': '', 'ipam_loc': '', 'ipam_type': '',
        'unreg': False,
        'sessions': 0, 'rules': 0, 'review': 0, 'allow': 0,
        'apps': _Ctr(), 'ports': _Ctr(), 'provs': _Ctr(),
    })

    def _enrich(ip, r, host_sessions=None):
        sd = per_ip[ip]
        ipam = r.get('ipam') or {}
        sd['src24']    = sd['src24']    or r.get('src24', '')
        sd['ipam_loc'] = sd['ipam_loc'] or (ipam.get('location') or ipam.get('site') or '')
        sd['ipam_type']= sd['ipam_type']or (ipam.get('net_type') or ipam.get('facility') or '')
        if ipam.get('unregistered'): sd['unreg'] = True
        count = host_sessions if host_sessions is not None else r.get('count', 0)
        sd['sessions'] += count
        sd['rules']    += 1
        if r.get('action') == 'REVIEW': sd['review'] += 1
        if r.get('action') == 'ALLOW':  sd['allow']  += 1
        for app in (r.get('apps') or []):
            if app: sd['apps'][app] += r.get('count', 1)
        sd['ports'][r.get('dest_port', 0)] += r.get('count', 1)
        dest = r.get('dest') or {}
        prov = dest.get('provider', '') or ''
        if prov: sd['provs'][prov] += r.get('count', 1)

    for r in rule_list:
        if r.get('collapsed_n', 0) > 1:
            # Collapsed rule — inspect each host in collapsed_hosts
            for h in (r.get('collapsed_hosts') or []):
                ip = h.get('ip', '')
                if not ip or h.get('hostname'):
                    continue    # skip if no IP or has a hostname
                _enrich(ip, r, host_sessions=h.get('count', 0))
        else:
            ip = r.get('src_ip', '')
            if not ip or r.get('hostname'):
                continue        # skip if no IP or hostname is known
            _enrich(ip, r)

    if not per_ip:
        return None

    rows = sorted(per_ip.items(), key=lambda x: -x[1]['sessions'])

    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = _csv.writer(f)
        w.writerow([
            'IP', 'SRC_CIDR', 'IPAM_LOCATION', 'IPAM_NET_TYPE', 'SUBNET_REGISTERED',
            'SESSION_COUNT', 'RULE_COUNT', 'REVIEW_RULES', 'ALLOW_RULES',
            'TOP_APPS', 'TOP_DEST_PORTS', 'TOP_DEST_PROVIDERS',
            'RECOMMENDATION',
        ])
        for ip, sd in rows:
            top_apps  = '|'.join(a for a, _ in sd['apps'].most_common(5))
            top_ports = '|'.join(str(p) for p, _ in sd['ports'].most_common(5))
            top_provs = '|'.join(p for p, _ in sd['provs'].most_common(3))
            registered = 'No' if sd['unreg'] else 'Yes'
            if sd['review'] > 0:
                rec = 'URGENT — REVIEW traffic; add to ent_host_master'
            elif sd['unreg']:
                rec = 'Register subnet in IPAM then add host to ent_host_master'
            else:
                rec = 'Add to ent_host_master'
            w.writerow([
                ip, sd['src24'], sd['ipam_loc'], sd['ipam_type'], registered,
                sd['sessions'], sd['rules'], sd['review'], sd['allow'],
                top_apps, top_ports, top_provs, rec,
            ])

    return len(rows)


def write_unregistered_csv(rule_list, src24_list, out_path):
    """Write a CSV of all unregistered source subnets for IPAM remediation.

    Columns:
      CIDR, SRC_IP_COUNT, SESSION_COUNT, RULE_COUNT, REVIEW_COUNT, ALLOW_COUNT,
      TOP_APPS, TOP_DEST_PORTS, TOP_DEST_PROVIDERS, RECOMMENDATION
    """
    import csv as _csv
    from collections import defaultdict as _dd, Counter as _Ctr

    # Build per-cidr stats from rule_list (unregistered = empty ipam blob)
    per_cidr = _dd(lambda: {
        'src_ips':   set(),
        'sessions':  0,
        'rules':     0,
        'review':    0,
        'allow':     0,
        'apps':      _Ctr(),
        'ports':     _Ctr(),
        'providers': _Ctr(),
    })

    for r in rule_list:
        ipam = r.get('ipam') or {}
        if ipam and not ipam.get('unregistered'):
            continue   # registered — skip
        cidr = r.get('src24', '') or ''
        if not cidr:
            continue
        sd = per_cidr[cidr]
        sd['sessions'] += r.get('count', 0)
        sd['rules']    += 1
        if r.get('action') == 'REVIEW': sd['review'] += 1
        if r.get('action') == 'ALLOW':  sd['allow']  += 1
        src = r.get('src_ip', '')
        if src: sd['src_ips'].add(src)
        for h in (r.get('collapsed_hosts') or []):
            if h.get('ip'): sd['src_ips'].add(h['ip'])
        for app in (r.get('apps') or []):
            if app: sd['apps'][app] += r.get('count', 1)
        sd['ports'][r.get('dest_port', 0)] += r.get('count', 1)
        # dest provider from dest blob (look up in rule)
        dest = r.get('dest') or {}
        prov = dest.get('provider', '') or ''
        if prov: sd['providers'][prov] += r.get('count', 1)

    if not per_cidr:
        return None   # nothing to write

    rows = sorted(per_cidr.items(), key=lambda x: -x[1]['sessions'])

    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = _csv.writer(f)
        w.writerow([
            'CIDR', 'SRC_IP_COUNT', 'SESSION_COUNT', 'RULE_COUNT',
            'REVIEW_RULES', 'ALLOW_RULES',
            'TOP_APPS', 'TOP_DEST_PORTS', 'TOP_DEST_PROVIDERS',
            'RECOMMENDATION',
        ])
        for cidr, sd in rows:
            top_apps  = '|'.join(a for a, _ in sd['apps'].most_common(5))
            top_ports = '|'.join(str(p) for p, _ in sd['ports'].most_common(5))
            top_provs = '|'.join(p for p, _ in sd['providers'].most_common(3))
            rec = 'URGENT — REVIEW traffic' if sd['review'] > 0 else 'Register in all_IP_networks'
            w.writerow([
                cidr,
                len(sd['src_ips']),
                sd['sessions'],
                sd['rules'],
                sd['review'],
                sd['allow'],
                top_apps,
                top_ports,
                top_provs,
                rec,
            ])

    return len(rows)


def next_report_num(out_dir):
    """Return the next sequential report number based on existing files in out_dir.
    Scans for fw_report_NNNNNN-*.html and returns max(N)+1, minimum 1."""
    existing = glob.glob(os.path.join(out_dir, 'fw_report_[0-9][0-9][0-9][0-9][0-9][0-9]-*.html'))
    if not existing:
        return 1
    nums = []
    for p in existing:
        base = os.path.basename(p)          # fw_report_000042-20260401.html
        try:
            nums.append(int(base.split('_')[2].split('-')[0]))
        except (IndexError, ValueError):
            pass
    return (max(nums) + 1) if nums else 1


def main():
    parser = argparse.ArgumentParser(
        description='Generate a PA firewall rule recommendation report from Splunk logs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Auto-detect log dir: FW_Log_Raw/ next to script, or cwd
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _log_dirs = ['FW_Log_Raw', 'fw_logs', 'logs', 'FW_Logs']
    _log_default = None
    for _ld in _log_dirs:
        _lp = os.path.join(_script_dir, _ld)
        if os.path.isdir(_lp) and glob.glob(os.path.join(_lp, '*.csv')):
            _log_default = [_lp]
            break
    if not _log_default:
        for _ld in _log_dirs:
            _lp = os.path.join(os.getcwd(), _ld)
            if os.path.isdir(_lp) and glob.glob(os.path.join(_lp, '*.csv')):
                _log_default = [_lp]
                break

    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('--log',            nargs='+', default=_log_default,
                        help=f'Log file(s) or directory. '
                             f'Pass a directory to stitch all CSVs into one report. '
                             f'[auto: {_log_default[0] if _log_default else "not found"}]')
    parser.add_argument('--log-dir',        default=None, metavar='DIR',
                        help='Directory of log CSVs — alias for --log DIR')
    # Auto-detect dataset-dir: prefer ipam-db/ next to this script, else cwd
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _ipam_default = (
        os.path.join(_script_dir, 'ipam-db')
        if os.path.isdir(os.path.join(_script_dir, 'ipam-db'))
        else os.path.join(os.getcwd(), 'ipam-db')
        if os.path.isdir(os.path.join(os.getcwd(), 'ipam-db'))
        else _script_dir
    )

    parser.add_argument('--dataset-dir',    default=_ipam_default,
                        help=f'IPAM directory [auto: {_ipam_default}]')
    parser.add_argument('--ip-dataset-dir', default=None,
                        help='ip_dataset_*.csv directory [auto: same as --dataset-dir]')
    parser.add_argument('--out-dir',        default='./fw-reports',
                        help='Output directory [default: ./fw-reports]')
    parser.add_argument('--ent-master',     default=None, metavar='FILE',
                        help='ent_host_master.csv [auto-discovered in dataset-dir]')
    parser.add_argument('--min-pkts',       type=int, default=10,
                        help='Minimum total packets for established session [default: 10]')
    parser.add_argument('--no-collapse-monitor', action='store_true',
                        help='Keep per-host granularity for MONITOR rules. By default, '
                             'MONITOR rules are collapsed by (src24, dest_ip, dest_port) '
                             'to reduce bloat when many hosts in the same /24 send '
                             'low-risk traffic to the same destination. Individual hosts '
                             'are preserved in an expandable list in the rule card.')
    parser.add_argument('--title',          default=None,
                        help='Report title override')
    parser.add_argument('--dry-run',        action='store_true',
                        help='Parse and analyse, print stats, write no files')
    parser.add_argument('-v', '--verbose',  action='store_true',
                        help='Verbose output')
    parser.add_argument('--splunk',         action='store_true',
                        help='Print sample Splunk SPL queries for all supported log schemas and exit')
    parser.add_argument('--check',          action='store_true',
                        help='Check that all required and optional data files can be found, print a status report, and exit without generating a report')
    args = parser.parse_args()

    # Auto-detect ip_dataset_dir if not specified
    if not args.ip_dataset_dir:
        import glob as _g
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ipdatasets'),
            os.path.join(args.dataset_dir, 'ipdatasets'),
            os.path.join(os.path.dirname(args.dataset_dir), 'ipdatasets'),
            'ipdatasets',
        ]
        for c in candidates:
            if os.path.isdir(c) and _g.glob(os.path.join(c, 'ip_dataset_*.csv')):
                args.ip_dataset_dir = c
                break

    start = datetime.now()

    # ── Early exits — do NOT need --log ──────────────────────────────────────
    log(f'generate_fw_rule_report.py v{VERSION}', force=True)

    if args.splunk:
        print_splunk_queries()
        return

    if args.check:
        check_files(args.dataset_dir, args.ip_dataset_dir, args.out_dir)
        return

    # ── --log is required for everything else ─────────────────────────────────
    # --log-dir is an alias for --log DIR
    if args.log_dir:
        args.log = [args.log_dir]

    if not args.log:
        parser.error(
            '--log is required unless --check or --splunk is specified.\n'
            '  Pass a file:       --log firewall.csv\n'
            '  Pass a directory:  --log FW_Log_Raw/   (stitches all CSVs)\n'
            '  Pass a glob:       --log "FW_Log_Raw/*.csv"'
        )

    # Expand globs in --log
    log_files = []
    for pattern in args.log:
        # If the argument is an existing directory, expand to all CSV files inside
        if os.path.isdir(pattern):
            csv_in_dir = sorted(glob.glob(os.path.join(pattern, '*.csv')),
                                key=lambda f: os.path.getmtime(f))
            if csv_in_dir:
                total_mb = sum(os.path.getsize(f) for f in csv_in_dir) / 1024 / 1024
                log(f'  Log directory: {pattern}', force=True)
                log(f'  Found {len(csv_in_dir)} CSV file(s)  ({total_mb:.0f} MB total)',
                    force=True)
                for f in csv_in_dir:
                    sz_kb = os.path.getsize(f) // 1024
                    log(f'    {os.path.basename(f)}  ({sz_kb:,} KB)', force=True)
                log_files.extend(csv_in_dir)
            else:
                sys.exit(f'ERROR: No CSV files found in directory: {pattern}')
        else:
            matches = glob.glob(pattern)
            if matches:
                log_files.extend(matches)
            elif os.path.isfile(pattern):
                log_files.append(pattern)
            else:
                sys.exit(f'ERROR: Log file not found: {pattern}')

    if not log_files:
        sys.exit('ERROR: No log files found. Check --log path(s).')

    log(f'Log files ({len(log_files)}): {[os.path.basename(f) for f in log_files]}',
        force=True)

    # ── Load ──────────────────────────────────────────────────────────────────
    ipam, ipam_c24  = load_ipam(args.dataset_dir, args.verbose)
    ent             = load_ent(args.dataset_dir, args.verbose, ent_master_path=args.ent_master)

    # Load external hostname prefix registry if present alongside this script
    _load_external_ht_registry(os.path.dirname(os.path.abspath(__file__)))
    # Resolve ip-dataset-dir: default to dataset-dir if not specified
    if not args.ip_dataset_dir:
        args.ip_dataset_dir = args.dataset_dir

    # Auto-discover ent_host_master if not specified
    if not args.ent_master:
        import glob as _glob
        _ent_candidates = sorted(
            _glob.glob(os.path.join(args.dataset_dir, 'ent_host_master_v*.csv')),
            reverse=True)
        if _ent_candidates:
            args.ent_master = _ent_candidates[0]
            log(f'  Auto-detected ent-master: {os.path.basename(args.ent_master)}',
                args.verbose, force=True)

    ip_dataset_recs = load_ip_datasets(args.ip_dataset_dir, args.verbose)
    geoip           = load_geoip(args.dataset_dir, args.verbose)
    ipam_tags       = load_ipam_tags(args.dataset_dir, args.verbose)
    vpn_partners    = load_vpn_partners(args.dataset_dir, args.verbose)
    app_taxonomy    = load_app_taxonomy(args.dataset_dir, args.verbose)
    cpc_idx         = build_cpc_index(args.dataset_dir, args.verbose)
    sessions, funnel = load_log(log_files, args.min_pkts, args.verbose)

    if not sessions:
        print('ERROR: No established sessions found (min_pkts may be too high)', file=sys.stderr)
        sys.exit(1)

    # ── Aggregate ─────────────────────────────────────────────────────────────
    rule_list, src24_list, dest_list, port_summary, rfc_violations, policy_recs = aggregate(
        sessions, ipam, ent, ip_dataset_recs, geoip, args.verbose, app_taxonomy, cpc_idx
    ,
        ipam_tags=ipam_tags,
        vpn_partners=vpn_partners
    )

    # ── v2.0: MONITOR /24 collapse (must run before stats/findings) ────────
    # By default, collapse per-host MONITOR rules into per-/24 rules. Other
    # actions keep per-host granularity. See collapse_monitor_to_src24 docstring.
    if not args.no_collapse_monitor:
        rule_list = collapse_monitor_to_src24(rule_list, verbose=args.verbose)

    stats        = compute_stats(sessions, rule_list, src24_list, dest_list, funnel)
    findings     = build_findings(rule_list, src24_list, dest_list, sessions)
    loc_breakdown= build_loc_breakdown(rule_list)

    # ── Stats output ──────────────────────────────────────────────────────────
    print('', file=sys.stderr)
    print('=== RULE RECOMMENDATION STATS ===', file=sys.stderr)
    print(f'  Established sessions:  {stats["total_sessions"]:,}', file=sys.stderr)
    print(f'  Rule candidates:       {stats["total_rules"]:,}', file=sys.stderr)
    print(f'  BLOCK:                 {stats["n_block"]}', file=sys.stderr)
    print(f'  REVIEW:                {stats["n_review"]}', file=sys.stderr)
    print(f'  MONITOR:               {stats["n_monitor"]}'
          + ('  (per-/24 collapsed)' if not args.no_collapse_monitor else '  (per-host)'),
          file=sys.stderr)
    print(f'  ALLOW:                 {stats["n_allow"]}', file=sys.stderr)
    print(f'  Critical ports:        {stats["n_critical"]}', file=sys.stderr)
    print(f'  High-risk ports:       {stats["n_high"]}', file=sys.stderr)
    print(f'  Source /24s:           {stats["n_src24"]}', file=sys.stderr)
    print(f'  Destination IPs:       {stats["n_dest"]}', file=sys.stderr)
    print(f'  PCI source subnets:    {stats["n_pci_src"]}', file=sys.stderr)
    print(f'  Key findings:          {len(findings)}', file=sys.stderr)

    if args.dry_run:
        log('\nDry run — no files written.', force=True)
        return

    # ── Build HTML ────────────────────────────────────────────────────────────
    # Serialise for the data blob — strip sets (already converted) and keep minimal payload
    # Finalize rfc_violations counts
    rfc_seen_final = {}
    for v in rfc_violations:
        k = (v['src_ip'], v['dst_ip'], v['port'])
        rfc_seen_final[k] = rfc_seen_final.get(k, 0) + 1
    rfc_deduped = []
    seen_rfc_keys = set()
    for v in rfc_violations:
        k = (v['src_ip'], v['dst_ip'], v['port'])
        if k not in seen_rfc_keys:
            seen_rfc_keys.add(k)
            v['count'] = rfc_seen_final.get(k, 1)
            rfc_deduped.append(v)
    rfc_deduped.sort(key=lambda x: -x['count'])

    # ── v2.0 payload compaction ────────────────────────────────────────────
    # Dedupe ipam/dest blobs into shared lookup tables keyed by src24/dest_ip.
    # Also precompute per-rule search haystack so the client never rebuilds it.
    compact_rules, ipam_by_src24, dest_by_ip = build_lookup_tables(rule_list)

    # Pre-split rules by action so the client can swap arrays on tab change
    # instead of filtering 161K rows per keystroke. Store INDICES rather than
    # full rule objects — otherwise the JSON wire payload doubles since
    # rules_by_action would contain copies of everything in `rules`.
    rules_by_action = {'BLOCK': [], 'REVIEW': [], 'MONITOR': [], 'ALLOW': []}
    for idx, r in enumerate(compact_rules):
        r['_i'] = idx   # stable index for DOM id reuse + index-lookup
        act = r.get('action', '')
        if act in rules_by_action:
            rules_by_action[act].append(idx)

    data_payload = {
        'stats':    stats,
        'findings': findings,
        'funnel':   funnel,
        'rules':    compact_rules,        # keeps 'all rules' path alive
        'rules_by_action': rules_by_action,
        'ipam_by_src24':   ipam_by_src24,
        'dest_by_ip':      dest_by_ip,
        'ports':    port_summary,
        'src24':    src24_list,
        'dests':    dest_list,
        'rfc':      rfc_deduped,
        'policy':   policy_recs,
        'loc_breakdown': loc_breakdown,
    }

    blob     = compress_blob(data_payload)

    # Report compaction stats
    import json as _json
    full_json = _json.dumps(data_payload, separators=(',', ':'))
    print('', file=sys.stderr)
    print('=== PAYLOAD COMPACTION (v2.0) ===', file=sys.stderr)
    print(f'  Rules:                 {len(compact_rules):,}', file=sys.stderr)
    print(f'  ipam_by_src24 entries: {len(ipam_by_src24):,}', file=sys.stderr)
    print(f'  dest_by_ip entries:    {len(dest_by_ip):,}', file=sys.stderr)
    for act, arr in rules_by_action.items():
        print(f'  {act:22s} {len(arr):>7,}', file=sys.stderr)
    print(f'  JSON size (decompressed): {len(full_json)/1024/1024:>6.1f} MB', file=sys.stderr)
    print(f'  Gzipped + base64:         {len(blob)/1024/1024:>6.1f} MB', file=sys.stderr)
    title    = args.title or (f'PA Firewall Rule Recommendations — {", ".join(os.path.basename(f) for f in log_files)}')
    dvc      = sessions[0]['dvc'] if sessions else 'Unknown'
    generated= stats['generated_utc']

    html = HTML_TEMPLATE
    html = html.replace('%%TITLE%%',     title)
    html = html.replace('%%MIN_PKTS%%',  str(args.min_pkts))
    html = html.replace('%%DVC%%',       dvc)
    html = html.replace('%%GENERATED%%', generated)
    html = html.replace('%%DATA_BLOB%%', blob)

    # ── Write ─────────────────────────────────────────────────────────────────
    os.makedirs(args.out_dir, exist_ok=True)
    seq      = next_report_num(args.out_dir)
    date_str = datetime.now().strftime('%Y%m%d')
    fname    = f'fw_report_{seq:06d}-{date_str}.html'
    out_path = os.path.join(args.out_dir, fname)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)

    size_kb = os.path.getsize(out_path) / 1024
    log(f'\nWritten: {out_path}  ({size_kb:.0f} KB)', force=True)

    # ── Unregistered subnets CSV ───────────────────────────────────────────────
    csv_fname = f'unregistered_subnets_{seq:06d}-{date_str}.csv'
    csv_path  = os.path.join(args.out_dir, csv_fname)
    n_unreg = write_unregistered_csv(rule_list, src24_list, csv_path)
    if n_unreg:
        log(f'Written: {csv_path}  ({n_unreg} unregistered subnets)', force=True)
        log(f'  → Add these CIDRs to all_IP_networks before next report run.', force=True)
    else:
        log(f'  No unregistered subnets — all source subnets are in IPAM.', force=True)

    # ── Unknown hosts CSV ─────────────────────────────────────────────────────
    hosts_fname = f'unknown_hosts_{seq:06d}-{date_str}.csv'
    hosts_path  = os.path.join(args.out_dir, hosts_fname)
    n_hosts = write_unknown_hosts_csv(rule_list, hosts_path)
    if n_hosts:
        log(f'Written: {hosts_path}  ({n_hosts} hosts with no ENT record)', force=True)
        log(f'  → Add these IPs to ent_host_master before next report run.', force=True)
    else:
        log(f'  No unknown hosts — all source IPs matched ent_host_master.', force=True)
    elapsed = (datetime.now() - start).total_seconds()
    log(f'Done in {elapsed:.1f}s.', force=True)


if __name__ == '__main__':
    main()
