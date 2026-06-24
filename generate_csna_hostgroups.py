#!/usr/bin/env python3
"""
generate_csna_hostgroups.py  v4.0.0

SITE_CODE-driven zone and site derivation.  Replaces the CANONICAL_LOCATION
keyword-matching pipeline (zone()/derive_site()) with structured FK lookups:

    IP → IPAM LPM → SITE_CODE → location_master → LOCATION_TYPE + HERITAGE
                                                  → csna_zone_map  → CSNA zone
                              → csna_site_registry (via LM bridge) → SITE_DC_NAME

UNKNOWN is now a genuine data quality signal, not a fallback bucket.
Unresolved IPs are logged to csna_unresolved_<ts>.csv for investigation.

Resolution order for each IP:
  1. Remediation overlay (SITE_CODE or legacy CANONICAL_LOCATION)
  2. IPAM LPM (all_IP_networks + retail_networks /26 subnets)
  3. Device/host row SITE_CODE field
  4. Device/host row CANONICAL_LOCATION → LM name lookup (transition fallback)
  5. UNKNOWN — logged to unresolved queue

Zone derivation priority:
  1. SITE_CODE → csna_site_registry → SITE_CLASS (explicit operational assignment)
  2. SITE_CODE components + LM LOCATION_TYPE + HERITAGE → csna_zone_map rules
  3. UNKNOWN

Breaking changes from v3.11.1:
  - zone(), derive_site(), _CLOUD_KEYWORDS, _COLO_KEYWORDS and all keyword
    constants removed.  Logic now lives in sc_to_zone() and sc_to_site().
  - resolve_location() replaced by resolve_sc().
  - LPM now includes retail_networks /26 subnets (store IP resolution).
  - Remediation overlay accepts SITE_CODE (preferred) or CANONICAL_LOCATION.
  - New: --zone-map arg (auto-discovered from registries/ dir).
  - New output: csna_unresolved_<ts>.csv — all IPs that resolved to UNKNOWN.

Retained unchanged from v3.11.1:
  - Tier 0a  VPN protected subnets (partner-keyed, not location-keyed)
  - Tier 0b  VPN ISAKMP peer anchors
  - Tier 0c  Retail /26 subnets (STATES-based grouping, no location lookup)
  - Tier 0d  P2P/MPLS partner subnets (dedicated circuit + MPLS, PARTNER-side only)
  - add(), build_lpm(), lpm_lookup()
  - XML tree builder, write_xml(), assign_ids(), continuity_check()
  - All node_type_* functions
  - _sanitise_cidr(), _is_invalid_ip()

Changelog:
    v4.0.3 2026-06-09  Tier 0a: LOCAL-direction rows excluded (same fix as Tier 0d).
                       VPN-PROTECTED-SUBNETS contains both LOCAL (CVS gateway
                       subnets) and REMOTE (partner-side) rows. CVS-side already
                       covered by IPAM pipeline. Only REMOTE rows emitted into
                       {SITE}-3PLZ-PEERS zones. Discovery order updated: prefer
                       ent-ipdataset-VPN-PROTECTED-SUBNETS* over legacy filename.
                       Tier 0d: CVS-direction rows excluded. P2P-PROTECTED-SUBNETS
                       carries both sides of each dedicated circuit (CVS + PARTNER).
                       CVS-side subnets are already covered by the IPAM pipeline
                       (Tiers 1-3) — adding them to partner zones created redundant
                       active/passive path entries. Only DIRECTION=PARTNER rows are
                       now emitted into {SITE}-P2P-PARTNERS zones.
    v4.0.2 2026-06-09  Tier 0d: P2P/MPLS partner subnets added. Reads
                       ent-ipdataset-P2P-PROTECTED-SUBNETS*.csv from
                       --vpn-dir. Maps to {SITE}-P2P-PARTNERS zone per
                       gateway_site. Both CVS and PARTNER direction rows
                       are included. --vpn-dir now covers both VPN and P2P
                       datasets (same ipam-db directory).
    v4.0.1 2026-05-28  Tier 0a/0b VPN file discovery updated to also match
                       ent-ipdataset-VPN-* naming convention.
                       Tier 0b: group name now derived from csna_hostgroup_path
                       (IP-based, stable across ASA tunnel-group renames) with
                       partner_name as fallback.
    v4.0.0 2026-05-11  SITE_CODE pipeline. See module docstring.
    v3.11.1            Versioned site registry support + #comment skip.
    (prior changelog retained in git history)
"""

import argparse, bisect, csv, glob, ipaddress, os, re, sys
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime
from xml.sax.saxutils import escape

SCRIPT_VERSION = '4.0.3'
ROOT_NAME      = 'CSNA Export v1'   # overridden at runtime
XML_START_ID   = 20000

# ── SITE_CLASS → CSNA zone ────────────────────────────────────────────────────
# Authoritative: if SITE_CODE resolves to a csna_site_registry entry with a
# known SITE_CLASS, use this mapping.  CLOUD entries are further split by
# provider extracted from the SITE_CODE second component.
_SC_TO_ZONE = {
    'CVS-DC':             'CVS-DC',
    'AETNA-DC':           'AETNA-DC',
    'DC-OWNED':           'DC-OWNED',
    'DC-COLO':            'DC-COLO',
    'CORPORATE':          'CORPORATE',
    'RETAIL':             'RETAIL',
    'DISTRO':             'DISTRO',
    'SPECIALTY':          'SPECIALTY',
    'OMNICARE':           'SPECIALTY',
    'CAREPLUS':           'SPECIALTY',
    'DR':                 'DR',
    'CVS-CALLCENTER':     'CVS-CALLCENTER',
    'AETNA-CALLCENTER':   'AETNA-CALLCENTER',
    'CALLCENTER-PARTNER': 'CALLCENTER-PARTNER',
    'PARTNER':            'CALLCENTER-PARTNER',
    'NAAS-HUB':           'CLOUD',
    # 'CLOUD' handled separately — split by provider
}

# ── LM LOCATION_TYPE → CSNA zone (fallback for sites not in registry) ─────────
_LT_TO_ZONE = {
    'Retail':       'RETAIL',
    'Corporate':    'CORPORATE',
    'CO':           'CORPORATE',
    'Partner':      'CORPORATE',
    'TP':           'CORPORATE',
    'Distribution': 'DISTRO',
    'Specialty':    'SPECIALTY',
    'SP':           'SPECIALTY',
    'Omnicare':     'SPECIALTY',
    'CarePlus':     'SPECIALTY',
    'Coram':        'CORAM',
    'Mail-Order':   'MAIL',
    'MO':           'CVS-CALLCENTER',
    'CVS-CC':       'CVS-CALLCENTER',
    'INS-CC':       'AETNA-CALLCENTER',
    'GHC-CC':       'AETNA-CALLCENTER',
    'COB-CC':       'AETNA-CALLCENTER',
    'DR':           'DR',
    'Field-Clinic': 'SPECIALTY',
    'Field-Office': 'CORPORATE',
    'HP':           'CORPORATE',
    'CP':           'CLOUD',
    'NH':           'CLOUD',
    'SS':           'CORPORATE',
    'HMR':          'CORPORATE',
    # IS, CI, DC, Call-Center resolved contextually in sc_to_zone()
}

# ── Location-level zone promotion (v3.11 behaviour retained) ──────────────────
_LOCATION_LEVEL_ZONES = frozenset({
    'DC-COLO', 'DC-OWNED', 'DISTRO', 'SPECIALTY', 'CORAM', 'MAIL', 'DR',
})
_CLOUD_ZONES = frozenset({'Cloud-Azure', 'Cloud-GCP', 'Cloud-AWS', 'CLOUD'})


def effective_zone_and_site(broad_zone, site):
    """Promote site to zone level for location-level zones."""
    if broad_zone in _LOCATION_LEVEL_ZONES and site:
        return site, ''
    if broad_zone in _CLOUD_ZONES:
        return broad_zone, ''
    return broad_zone, site


# ── Cloud provider extraction ─────────────────────────────────────────────────

def _cloud_zone_from_provider(token: str) -> str:
    t = token.upper()
    if 'AZR' in t or 'AZURE' in t: return 'Cloud-Azure'
    if 'GCP' in t or 'GOOGLE' in t: return 'Cloud-GCP'
    if 'AWS' in t or 'AMAZON' in t: return 'Cloud-AWS'
    return 'CLOUD'


# ── Exclusion ─────────────────────────────────────────────────────────────────
# Offshore TP sites (non-US country code + TP LOCATION_TYPE) are excluded.
# WAH pools have no SITE_CODE (removed from all registries) — resolve to UNKNOWN
# and are captured by the unresolved log; no special handling needed.

def is_excluded(site_code: str, lm_row: dict) -> bool:
    if not site_code or not lm_row:
        return False
    lt = lm_row.get('LOCATION_TYPE','').upper()
    if lt == 'TP' and not site_code.upper().startswith('US_'):
        return True
    return False


# ── Bogon / invalid IP filter ─────────────────────────────────────────────────
_INVALID_IPS = {
    '255.255.255.0','255.255.255.128','255.255.255.192','255.255.255.224',
    '255.255.255.240','255.255.255.248','255.255.255.252','255.255.255.254',
    '255.255.255.255','255.255.0.0','255.0.0.0','0.0.0.0',
    '1.1.1.1','1.1.1.2','1.1.1.3',
    '6.6.6.6','6.6.6.5','6.6.6.4',
    '8.8.8.8','8.8.4.4','9.9.9.9',
    '127.0.0.1','169.254.0.1','169.254.1.1',
}

def _is_invalid_ip(ip_str):
    bare = ip_str.split('/')[0].strip()
    if bare in _INVALID_IPS: return True
    if bare.startswith('255.'): return True
    if bare.startswith('6.6.6.'): return True
    return False


def _sanitise_cidr(cidr_str):
    if not cidr_str or '/' not in cidr_str:
        return cidr_str
    host_part, prefix_part = cidr_str.split('/', 1)
    if re.match(r'^\d+$', prefix_part.strip()):
        return cidr_str
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', prefix_part.strip()):
        fixed = f'{host_part.strip()}/32'
        print(f'  WARNING: IP/IP CIDR corrected: {cidr_str} → {fixed}')
        return fixed
    print(f'  WARNING: Unrecognised CIDR format: {cidr_str}')
    return cidr_str


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_lm(path):
    """
    Returns (lm_by_sc, lm_by_name).
      lm_by_sc   : {SITE_CODE: lm_row}
      lm_by_name : {CANONICAL_NAME.lower(): lm_row}
    """
    by_sc, by_name = {}, {}
    if not path or not os.path.exists(path):
        return by_sc, by_name
    with open(path, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(l for l in f if not l.startswith('#')):
            sc   = row.get('SITE_CODE','').strip()
            name = row.get('CANONICAL_NAME','').strip()
            if sc:   by_sc[sc]             = row
            if name: by_name[name.lower()]  = row
    return by_sc, by_name


def load_csna_registry_v4(path, lm_by_name):
    """
    Returns (by_sc, by_name).
      by_sc   : {SITE_CODE: (SITE_DC_NAME, SITE_CLASS, row)}
                Built by bridging SITE_DC_NAME → LM CANONICAL_NAME → SITE_CODE.
                CX7 invariant guarantees SITE_DC_NAME == LM CANONICAL_NAME.
      by_name : {SITE_DC_NAME.lower(): row}  — for partner/VPN site lookups
    """
    by_name, by_sc = {}, {}
    if not path or not os.path.exists(path):
        return by_sc, by_name
    with open(path, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(l for l in f if not l.startswith('#')):
            site_dc = row.get('SITE_DC_NAME','').strip()
            if not site_dc:
                continue
            by_name[site_dc.lower()] = row
            lm_row = lm_by_name.get(site_dc.lower())
            if lm_row:
                sc = lm_row.get('SITE_CODE','').strip()
                if sc:
                    by_sc[sc] = (site_dc, row.get('SITE_CLASS','').strip(), row)
    return by_sc, by_name


def load_site_registry(path):
    """v3.x compatibility shim — keyword list for VPN zone fallback only."""
    entries = []
    if not path or not os.path.exists(path):
        return entries
    with open(path, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(l for l in f if not l.startswith('#')):
            site  = row.get('SITE_DC_NAME','').strip()
            kws   = [k.strip().lower() for k in row.get('LOCATION_KEYWORDS','').split('|') if k.strip()]
            sclass= row.get('SITE_CLASS','').strip()
            if site and kws:
                entries.append((kws, site, sclass, row))
    return entries


def load_remediation(path):
    """Returns {IP: SITE_CODE_or_CANONICAL_LOCATION} for resolved rows."""
    overlay = {}
    if not path or not os.path.exists(path):
        return overlay
    with open(path, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(l for l in f if not l.startswith('#')):
            ip     = row.get('IP_ADDRESS','').strip()
            sc     = row.get('SITE_CODE','').strip()
            canon  = row.get('CANONICAL_LOCATION','').strip()
            action = row.get('FIX_ACTION','').strip()
            if ip and action not in ('UNRESOLVED','NEEDS_MANUAL_MAPPING',''):
                overlay[ip] = sc or canon
    return overlay


# ── Zone and site derivation (v4.0 — SITE_CODE driven) ───────────────────────

def sc_to_zone(site_code: str, lm_row: dict, registry_by_sc: dict) -> str:
    """
    Derive CSNA zone from SITE_CODE.

    Priority:
      1. Registry SITE_CLASS  (explicit operational assignment by network team)
      2. SITE_CODE components + LM LOCATION_TYPE + HERITAGE (structural rule)
      3. 'UNKNOWN'  (genuine data gap — will be logged to unresolved queue)
    """
    if not site_code:
        return 'UNKNOWN'

    parts     = site_code.split('_')
    site_type = parts[-1].upper() if parts else ''
    provider  = parts[1].upper() if len(parts) >= 3 else ''
    lt        = (lm_row.get('LOCATION_TYPE','') if lm_row else '')
    heritage  = (lm_row.get('HERITAGE','').upper() if lm_row else '')
    facility  = (lm_row.get('FACILITY_OWNER','').upper() if lm_row else '')

    # 1. Registry SITE_CLASS — authoritative
    if site_code in registry_by_sc:
        _, sclass, _ = registry_by_sc[site_code]
        if sclass == 'CLOUD':
            return _cloud_zone_from_provider(provider)
        z = _SC_TO_ZONE.get(sclass)
        if z:
            return z

    # 2. Structural derivation

    # IS (cloud IAAS) — provider from 2nd SITE_CODE component
    if site_type == 'IS':
        return _cloud_zone_from_provider(provider)

    # CI (colocation) — Switch → DC-COLO, others (Equinix etc.) → CLOUD
    if site_type == 'CI':
        if 'SWITCH' in heritage or 'SWITCH' in facility:
            return 'DC-COLO'
        return 'CLOUD'

    # DC (data center) — split by heritage
    if site_type == 'DC' or lt == 'Datacenter':
        if 'CVS' in heritage or 'CAREMARK' in heritage:
            return 'CVS-DC'
        if 'AETNA' in heritage:
            return 'AETNA-DC'
        return 'DC-OWNED'

    # Retail store (5-digit SITE_CODE)
    if re.match(r'^\d{5}$', site_code):
        return 'RETAIL'

    # Call-Center — split by heritage
    if lt == 'Call-Center':
        if 'CVS' in heritage or 'CAREMARK' in heritage:
            return 'CVS-CALLCENTER'
        if 'AETNA' in heritage:
            return 'AETNA-CALLCENTER'
        return 'CORPORATE'

    # CP / NH hub types — cloud connectivity, provider from 2nd component
    if site_type in ('CP',) or lt == 'CP':
        return _cloud_zone_from_provider(provider)

    # LT_TO_ZONE table
    z = _LT_TO_ZONE.get(lt)
    if z:
        return z

    return 'UNKNOWN'


def sc_to_site(site_code: str, lm_row: dict, registry_by_sc: dict) -> str:
    """
    Derive CSNA site name from SITE_CODE.

    Priority:
      1. Registry SITE_DC_NAME (direct operational name)
      2. Retail store — 'Retail Stores - {STATE}' grouping
      3. LM CANONICAL_NAME (fallback for new sites not yet in registry)
      4. 'UNKNOWN'
    """
    if not site_code:
        return 'UNKNOWN'

    if site_code in registry_by_sc:
        return registry_by_sc[site_code][0]

    if re.match(r'^\d{5}$', site_code) and lm_row:
        state = (lm_row.get('STATE','') or '').strip()
        return f'Retail Stores - {state}' if state else 'Retail Stores'

    if lm_row:
        name = lm_row.get('CANONICAL_NAME','').strip()
        if name:
            return name

    return 'UNKNOWN'


# ── Site code resolution for a single IP ─────────────────────────────────────

def resolve_sc(ip, ipam_row, source_row, overlay, lm_by_name, lm_by_sc):
    """
    Returns (site_code, lm_row, routing_domain, net_type).

    Resolution order:
      1. Remediation overlay — SITE_CODE (preferred) or CANONICAL_LOCATION (legacy)
      2. IPAM LPM hit         — SITE_CODE from all_IP_networks / retail_networks
      3. source_row SITE_CODE — device/host row if EHM carries SITE_CODE
      4. source_row CANONICAL_LOCATION → LM name lookup  (transition fallback)
      5. ('', None, '', '')   — unresolved
    """
    rd, nt = '', ''
    if ipam_row:
        rd = ipam_row.get('ROUTING_DOMAIN','')
        nt = ipam_row.get('NET_TYPE','')

    # 1. Remediation overlay
    if ip in overlay:
        val = overlay[ip].strip()
        if re.match(r'^[A-Z]{2}_[A-Z0-9]+_', val):
            # Looks like a SITE_CODE
            lm_row = lm_by_sc.get(val)
            return val, lm_row, rd or (lm_row.get('ROUTING_DOMAIN','') if lm_row else ''), nt
        else:
            # Legacy CANONICAL_LOCATION
            lm_row = lm_by_name.get(val.lower())
            if lm_row:
                sc = lm_row.get('SITE_CODE','').strip()
                if sc:
                    return sc, lm_row, rd, nt

    # 2. IPAM LPM
    if ipam_row:
        sc = ipam_row.get('SITE_CODE','').strip()
        if sc:
            lm_row = lm_by_sc.get(sc)
            return sc, lm_row, rd, nt

    # 3. Source row SITE_CODE
    if source_row:
        sc = source_row.get('SITE_CODE','').strip()
        if sc:
            lm_row = lm_by_sc.get(sc)
            return sc, lm_row, rd, nt

    # 4. Legacy CANONICAL_LOCATION from source row (transition)
    if source_row:
        for field in ('CANONICAL_LOCATION','HOSTNAME_DERIVED_LOCATION','SOURCE_DECLARED_LOCATION'):
            canon = source_row.get(field,'').strip()
            if canon:
                lm_row = lm_by_name.get(canon.lower())
                if lm_row:
                    sc = lm_row.get('SITE_CODE','').strip()
                    if sc:
                        return sc, lm_row, rd, nt
                break

    return '', None, rd, nt


# ── Node type derivation (unchanged from v3.11.1) ────────────────────────────

def node_type_host(row):
    og  = str(row.get('OS_GROUP','') or row.get('OS_NORMALIZED','') or '').lower()
    sc  = str(row.get('SERVER_CLASS','') or '').lower()
    af  = str(row.get('ASSET_FAMILY','') or '').lower()
    apm = str(row.get('PRIMARY_APM_ID','') or '').strip()
    acr = str(row.get('PRIMARY_ACRONYM','') or '').strip()
    pci = str(row.get('PCI','') or '').lower() in ('yes','true','1')
    if 'kubernetes' in og or 'k8' in af:      return 'K8-Node'
    if 'esx' in og or 'vmware' in og:         os_p = 'VMware'
    elif 'windows' in og:                      os_p = 'Win'
    elif 'linux' in og or 'unix' in og or 'aix' in og: os_p = 'Lin'
    elif 'mainframe' in og or 'zos' in og:     os_p = 'Mainframe'
    elif 'appliance' in og:                    os_p = 'Appliance'
    else:                                      os_p = 'Other'
    if 'f5' in af:      return f'{os_p}-LB'
    if pci:             return f'{os_p}-PCI-Node'
    if apm and acr:     return f'{os_p}-App-{acr[:10]}'
    if 'virtual' in sc: return f'{os_p}-VM'
    return f'{os_p}-Server'

def node_type_network(device_type, vendor='', model=''):
    dt = str(device_type or '').lower()
    v  = str(vendor or '').lower()
    m  = str(model or '').lower()
    if 'router' in dt:                            return 'Network-Router'
    if 'switch' in dt or 'catalyst' in m or 'nexus' in m: return 'Network-Switch'
    if 'firewall' in dt or 'palo alto' in v:      return 'Network-Firewall'
    if 'load balancer' in dt or 'f5' in v:        return 'Network-LB'
    if 'wireless' in dt or 'access point' in dt:  return 'Network-AP'
    if 'vpn' in dt or 'concentrator' in dt:       return 'Network-VPN'
    if 'end system' in dt or 'end device' in dt:  return 'End-Device'
    return 'Network-Device'

def node_type_infra(row):
    af = str(row.get('ASSET_FAMILY','') or row.get('SERVER_CLASS','')).lower()
    if any(x in af for x in ('esx','vmware','vsphere')):            return 'Infra-ESX'
    if any(x in af for x in ('hmc','power systems','ibm power')):   return 'Infra-HMC'
    if any(x in af for x in ('iseries','as400','as/400','ibm i')):  return 'Infra-iSeries'
    if any(x in af for x in ('physical','bare metal','baremetal')):  return 'Infra-Physical'
    if any(x in af for x in ('hyper-v','hyperv')):                   return 'Infra-HyperV'
    if 'xen' in af:                                                  return 'Infra-Xen'
    og = str(row.get('OS_GROUP','') or '').lower()
    if 'esx' in og or 'vmware' in og: return 'Infra-ESX'
    if 'aix' in og:                   return 'Infra-AIX'
    return 'Infra-Host'

def node_type_platform(row):
    pt = str(row.get('PLATFORM_TYPE','') or '').lower()
    if any(x in pt for x in ('kubernetes','k8s','ocp','openshift')): return 'Delivery-K8s'
    if any(x in pt for x in ('docker','container','podman')):         return 'Delivery-Container'
    if any(x in pt for x in ('vmware','vsphere','vcenter')):          return 'Delivery-VMware'
    if 'openstack' in pt:                                             return 'Delivery-OpenStack'
    return 'Delivery-Platform'

def node_type_subnet(net_type):
    return {
        'DataCenter':'DC-Subnet','Corporate':'Corp-Subnet',
        'Retail-Store':'Retail-Subnet','Distribution':'Distro-Subnet',
        'Specialty':'Spec-Subnet','Retail-MinuteClinic':'Clinic-Subnet',
        'Retail-Optical':'Optical-Subnet','Cloud-Azure':'Cloud-Azure-Subnet',
        'Cloud-GCP':'Cloud-GCP-Subnet','Cloud-AWS':'Cloud-AWS-Subnet',
        'COLO':'COLO-Subnet','Partner':'Partner-Subnet',
        'Call-Center':'CallCenter-Subnet','Mail-Order':'MailOrder-Subnet',
        'VPN':'VPN-Subnet','Omnicare':'Omnicare-Subnet','Coram':'Coram-Subnet',
    }.get(str(net_type or '').strip(), 'IP-Subnet')


# ── LPM ───────────────────────────────────────────────────────────────────────

def build_lpm(paths: list):
    """Build longest-prefix-match index from one or more IPAM CSV files."""
    by_prefix = defaultdict(list)
    for fpath in paths:
        if not fpath or not os.path.exists(fpath): continue
        with open(fpath, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                cidr = row.get('CIDR','').strip()
                if not cidr or ':' in cidr: continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    by_prefix[net.prefixlen].append(
                        (int(net.network_address), int(net.broadcast_address), row))
                except: pass
    prefix_lens = sorted(by_prefix.keys(), reverse=True)
    for pl in prefix_lens: by_prefix[pl].sort(key=lambda x: x[0])
    return dict(by_prefix), prefix_lens

def lpm_lookup(ip_str, by_prefix, prefix_lens):
    try: ip_int = int(ipaddress.ip_address(ip_str.split('/')[0].strip()))
    except: return None
    for pl in prefix_lens:
        grp = by_prefix[pl]
        idx = bisect.bisect_right([e[0] for e in grp], ip_int) - 1
        if idx >= 0 and grp[idx][0] <= ip_int <= grp[idx][1]:
            return grp[idx][2]
    return None


# ── XML builder (unchanged from v3.11.1) ─────────────────────────────────────

class XNode:
    def __init__(self, name): self.name=name; self.children=OrderedDict(); self.cidrs=[]; self.id=None
    def get(self, n):
        if n not in self.children: self.children[n] = XNode(n)
        return self.children[n]

_emitted_names = set()

def _unique_name(name, parent_name=''):
    global _emitted_names
    if name not in _emitted_names:
        _emitted_names.add(name)
        return name
    candidate = f'{parent_name}-{name}' if parent_name else f'{name}-2'
    if candidate not in _emitted_names:
        _emitted_names.add(candidate)
        return candidate
    i = 2
    while True:
        c2 = f'{name}-{i}'
        if c2 not in _emitted_names:
            _emitted_names.add(c2)
            return c2
        i += 1

def build_tree(rows_out, root_name):
    root = XNode(root_name)
    for cidr, path in rows_out:
        parts = [p for p in path.split('/') if p]
        node = root
        for p in parts[1:]:   # skip ROOT_NAME
            node = node.get(p)
        node.cidrs.append(cidr)
    return root

def assign_ids(node, start):
    node.id = start
    nxt = start + 1
    for child in node.children.values():
        nxt = assign_ids(child, nxt)
    return nxt

def write_xml(root, out_path, meta=None):
    global _emitted_names
    _emitted_names = set()
    lines = 0
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        if meta:
            f.write('<!--\n')
            for k, v in meta.items():
                if v: f.write(f'  {k}: {v}\n')
            f.write('-->\n')
        def emit(node, depth=0):
            nonlocal lines
            indent = '  ' * depth
            name_attr = escape(_unique_name(node.name, node.name))
            if not node.children and not node.cidrs:
                return
            f.write(f'{indent}<host-group name="{name_attr}" id="{node.id}">\n')
            lines += 1
            for cidr in node.cidrs:
                f.write(f'{indent}  <ip-address-ranges>{cidr}</ip-address-ranges>\n')
                lines += 1
            for child in node.children.values():
                emit(child, depth+1)
            f.write(f'{indent}</host-group>\n')
            lines += 1
        emit(root)
    return lines


def continuity_check(csv_path, xml_path, rows_out):
    import xml.etree.ElementTree as ET
    from collections import Counter as _Counter
    print('\nRunning continuity check...')
    issues = []

    csv_rows = []
    with open(csv_path, newline='', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(',', 1)
            if len(parts) == 2: csv_rows.append(tuple(parts))
    csv_ips   = [r[0] for r in csv_rows]
    csv_count = len(csv_rows)
    rows_count = len(rows_out)

    try: xml_root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        issues.append(f'XML parse error: {e}')
        print(f'  XML parse:             FAIL — {e}')
        print(f'\n  ✗ CONTINUITY FAIL — {len(issues)} issue(s)')
        for i in issues: print(f'      {i}')
        return False

    xml_ips = [e.text for e in xml_root.iter('ip-address-ranges') if e.text]

    if csv_count == len(xml_ips):
        print(f'  Row count:             OK  ({csv_count:,} in both CSV and XML)')
    else:
        msg = f'FAIL — CSV {csv_count:,} rows vs XML {len(xml_ips):,} <ip-address-ranges>'
        print(f'  Row count:             {msg}'); issues.append(msg)

    csv_set, xml_set = set(csv_ips), set(xml_ips)
    only_csv = csv_set - xml_set; only_xml = xml_set - csv_set
    if not only_csv and not only_xml:
        print(f'  IP set match:          OK  ({len(csv_set):,} unique IPs)')
    else:
        msg = f'FAIL — {len(only_csv)} only in CSV, {len(only_xml)} only in XML'
        print(f'  IP set match:          {msg}'); issues.append(msg)

    dup_xml = {ip: c for ip, c in _Counter(xml_ips).items() if c > 1}
    if not dup_xml:
        print(f'  XML duplicates:        OK')
    else:
        msg = f'FAIL — {len(dup_xml)} duplicate IP(s) in XML'
        print(f'  XML duplicates:        {msg}'); issues.append(msg)

    hg_ids = [hg.get('id') for hg in xml_root.iter('host-group')]
    dup_ids = {i: c for i, c in _Counter(hg_ids).items() if c > 1}
    if not dup_ids:
        print(f'  Host-group IDs:        OK  ({len(hg_ids):,} unique)')
    else:
        msg = f'FAIL — {len(dup_ids)} duplicate host-group ID(s)'
        print(f'  Host-group IDs:        {msg}'); issues.append(msg)

    empty_hg = [hg.get('name','?') for hg in xml_root.iter('host-group')
                if not list(hg) and not any(e.tag == 'ip-address-ranges' for e in hg)]
    if not empty_hg:
        print(f'  Empty host groups:     OK')
    else:
        msg = f'FAIL — {len(empty_hg)} empty host group(s)'
        print(f'  Empty host groups:     {msg}'); issues.append(msg)

    # CIDR format check
    _re2 = re.compile
    ip_ip = [ip for ip in xml_ips if '/' in ip and
             re.match(r'^\d+\.\d+\.\d+\.\d+/\d+\.\d+\.\d+\.\d+$', ip.strip())]
    non_num = [ip for ip in xml_ips if '/' in ip and
               not re.match(r'^[^\s/]+/\d+$', ip.strip())]
    bad = sorted(set(ip_ip + non_num))
    if not bad:
        print(f'  CIDR format:           OK  (all {len(xml_ips):,} entries valid)')
    else:
        msg = f'FAIL — {len(bad)} malformed CIDR(s)'; print(f'  CIDR format:           {msg}')
        for b in bad[:5]: print(f'    BAD: {b}')
        issues.append(msg)

    hg_names = [hg.get('name','') for hg in xml_root.iter('host-group')]
    dup_names = {n: c for n, c in _Counter(hg_names).items() if c > 1}
    if not dup_names:
        print(f'  Host-group names:      OK  ({len(hg_names):,} unique)')
    else:
        msg = f'FAIL — {len(dup_names)} duplicate name(s) — CSNA import will reject'
        print(f'  Host-group names:      {msg}')
        for n, c in sorted(dup_names.items(), key=lambda x:-x[1])[:5]: print(f'    {c}x  {n}')
        issues.append(msg)

    print()
    if not issues:
        print(f'  ✓ CONTINUITY PASS — CSV and XML are fully consistent')
        return True
    else:
        print(f'  ✗ CONTINUITY FAIL — {len(issues)} issue(s):')
        for i in issues: print(f'      {i}')
        return False


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=f'generate_csna_hostgroups.py v{SCRIPT_VERSION}')
    ap.add_argument('--ipam-dir',        default='ipam-db')
    ap.add_argument('--nms-dir',         default='.')
    ap.add_argument('--host-master',     default='')
    ap.add_argument('--infra-master',    default='')
    ap.add_argument('--platform-master', default='')
    ap.add_argument('--loc-master',      default='')
    ap.add_argument('--zone-map',        default='', help='csna_zone_map.csv path (auto-discovered if omitted)')
    ap.add_argument('--vpn-dir',         default='ipam-db')
    ap.add_argument('--remediation-csv', default='')
    ap.add_argument('--ipam-patch',      default='')
    ap.add_argument('--out-dir',         default='csna_output')
    ap.add_argument('--dry-run',         action='store_true')
    ap.add_argument('--no-xml',          action='store_true')
    ap.add_argument('-v','--verbose',    action='store_true')
    ap.add_argument('-V','--version',    action='version',
                    version=f'generate_csna_hostgroups.py v{SCRIPT_VERSION}')
    args = ap.parse_args()

    idir, ndir, odir = args.ipam_dir, args.nms_dir, args.out_dir

    def latest(directory, pattern):
        matches = glob.glob(os.path.join(directory, pattern))
        if not matches: return None
        def vk(p):
            nums = [int(x) for x in re.findall(r'\d+', os.path.basename(p))]
            return nums if nums else [0]
        return sorted(matches, key=vk)[-1]

    ipam_path    = latest(idir, 'all_IP_networks_v*.csv')
    retail_path  = latest(idir, 'retail_networks_v*.csv')
    reg_path     = (latest(idir, 'csna_site_registry_v*.csv') or
                    latest(idir, 'csna_site_registry.csv'))
    lm_path      = (args.loc_master or
                    latest(idir, 'location_master_v*.csv') or
                    latest(idir, 'location_master_table.csv') or '')
    ndm_path     = latest(idir, 'ent_network_device_master_v*.csv')
    nms_path     = (latest(ndir, '1_network_devices_by_location.csv') or
                    latest(idir, '1_network_devices_by_location.csv'))
    infra_path   = (args.infra_master if args.infra_master and os.path.isfile(args.infra_master)
                    else latest(idir, 'delivery_infrastructure_v*.csv'))
    platform_path= (args.platform_master if args.platform_master and os.path.isfile(args.platform_master)
                    else latest(idir, 'delivery_platform_v*.csv'))

    # Zone map: --zone-map arg, then registries/ sibling dir, then ipam-dir
    zone_map_path = (args.zone_map or
                     latest(os.path.join(os.path.dirname(idir), 'registries'), 'csna_zone_map*.csv') or
                     latest(os.path.join(idir, '..', 'registries'), 'csna_zone_map*.csv') or
                     latest(idir, 'csna_zone_map*.csv') or '')

    _hm_candidates = [p for p in glob.glob(os.path.join(idir, 'ent_host_master_v*.csv'))
                      if not any(s in os.path.basename(p) for s in (
                          '_conflict','_offshore','_unknown','_source_declared',
                          '_hostname_resolved','_cloud_public',
                          '_cmdb_new_servers','_cmdb_pci_conflicts','_cmdb_risk_conflicts'))]
    host_path = (args.host_master if args.host_master and os.path.isfile(args.host_master)
                 else (sorted(_hm_candidates,
                              key=lambda p: [int(x) for x in re.findall(r'\d+', os.path.basename(p))] or [0])[-1]
                       if _hm_candidates else None))

    rem_csv   = (args.remediation_csv or
                 latest(odir, 'host_master_remediation_*.csv') or '')
    patch_csv = args.ipam_patch or latest(odir, 'ipam_patch_v*.csv') or ''

    print(f'generate_csna_hostgroups.py v{SCRIPT_VERSION} — {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    print(f'  IPAM:              {ipam_path}')
    print(f'  Retail networks:   {retail_path or "(none)"}')
    print(f'  IPAM patch:        {patch_csv or "(none)"}')
    print(f'  Location master:   {lm_path or "(none — zone derivation degraded)"}')
    print(f'  Zone map:          {zone_map_path or "(none — LT fallback only)"}')
    print(f'  Site registry:     {reg_path}')
    print(f'  Host master:       {host_path}')
    print(f'  Remediation CSV:   {rem_csv or "(none)"}')
    print(f'  NMS devices:       {nms_path}')
    print(f'  Network dev mstr:  {ndm_path}')
    print(f'  Infra master:      {infra_path or "(none)"}')
    print(f'  Platform master:   {platform_path or "(none)"}')
    print()

    if not ipam_path: sys.exit('ERROR: all_IP_networks CSV not found')
    if not lm_path:   print('WARNING: location_master not found — zone derivation will be limited')

    # ── Load master data ──────────────────────────────────────────────────────
    print('Loading location master...')
    lm_by_sc, lm_by_name = load_lm(lm_path)
    print(f'  {len(lm_by_sc):,} entries by SITE_CODE  |  {len(lm_by_name):,} by name')

    print('Loading CSNA site registry...')
    registry_by_sc, registry_by_name = load_csna_registry_v4(reg_path, lm_by_name)
    print(f'  {len(registry_by_sc):,} entries indexed by SITE_CODE  |  {len(registry_by_name):,} by name')
    if len(registry_by_sc) < len(registry_by_name) * 0.5:
        print(f'  WARNING: Only {len(registry_by_sc)} of {len(registry_by_name)} registry entries '
              f'resolved to SITE_CODE via LM bridge.  '
              f'Ensure SITE_CODE is populated in location_master for all registry sites.')

    print('Building LPM index...')
    all_patches = sorted([p for p in glob.glob(os.path.join(odir, 'ipam_patch_v*.csv'))
                          if os.path.exists(p)])
    if patch_csv and patch_csv not in all_patches and os.path.exists(patch_csv):
        all_patches.append(patch_csv)
    # Include retail_networks /26 subnets in LPM for host IP resolution
    lpm_sources = [f for f in [ipam_path] + all_patches if f and os.path.exists(f)]
    by_prefix, prefix_lens = build_lpm(lpm_sources)
    # Augment LPM with retail /26 subnets (store IPs need store SITE_CODE)
    retail_lpm_count = 0
    if retail_path and os.path.exists(retail_path):
        with open(retail_path, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                cidr = row.get('CIDR','').strip()
                if not cidr or ':' in cidr: continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if net.prefixlen == 26:
                        by_prefix.setdefault(net.prefixlen, []).append(
                            (int(net.network_address), int(net.broadcast_address), row))
                        retail_lpm_count += 1
                except: pass
        if 26 in by_prefix:
            by_prefix[26].sort(key=lambda x: x[0])
        if 26 not in prefix_lens:
            prefix_lens = sorted(by_prefix.keys(), reverse=True)
    print(f'  {sum(len(v) for v in by_prefix.values()):,} prefixes  '
          f'({len(lpm_sources)} IPAM file(s) + {retail_lpm_count:,} retail /26s)')

    print('Loading remediation overlay...')
    overlay = load_remediation(rem_csv)
    print(f'  {len(overlay):,} IP overrides')
    print()

    rows_out   = []
    _seen_cidr = set()
    covered    = set()
    unresolved = []   # (ip_or_cidr, source_tier, reason)
    stats = {'hosts':0,'net_devices':0,'infra_hosts':0,'platform_hosts':0,
             'subnets':0,'vpn_peers':0,'retail':0}
    zone_dist = defaultdict(int)

    def make_path(z, s, n): return f'/{ROOT_NAME}/{z}/{s}/{n}'

    def add(cidr, z, s, n):
        cidr = _sanitise_cidr(cidr)
        if not cidr: return
        addr = cidr.split('/')[0]
        if (addr.startswith('255.') or addr.startswith('0.') or
                addr in ('1.1.1.1','1.1.1.2','6.6.6.5','6.6.6.6',
                         '8.8.8.8','8.8.4.4','9.9.9.9','192.168.1.1')):
            return
        if cidr in _seen_cidr: return
        _seen_cidr.add(cidr)
        hpath = make_path(z, s, n)
        rows_out.append((cidr, hpath))
        zone_dist[z] += 1
        if args.verbose: print(f'  {cidr:25s} → {z}/{s}/{n}')

    # ── Tier 0a: VPN partner IPSec targets ───────────────────────────────────
    vpn_dir  = args.vpn_dir
    vpn_subs = (latest(vpn_dir, 'ent-ipdataset-VPN-PROTECTED-SUBNETS*.csv') or
                latest(vpn_dir, 'vpn_protected_subnets*.csv') or
                (os.path.join(vpn_dir,'vpn_protected_subnets.csv')
                 if os.path.exists(os.path.join(vpn_dir,'vpn_protected_subnets.csv')) else ''))
    if vpn_subs and os.path.exists(vpn_subs):
        print(f'Processing VPN protected subnets: {os.path.basename(vpn_subs)}')
        _GW_ZONE = {'SHEA':'SHEA-3PLZ-PEERS','WOONSOCKET':'RI-3PLZ-PEERS',
                    'WDC':'WDC-3PLZ-PEERS','MDC':'MDC-3PLZ-PEERS'}
        with open(vpn_subs, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                cidr      = str(row.get('IP_NETWORK','')).strip()
                partner   = str(row.get('PARTNER_NAME','')).strip().replace('/','_')
                gw_site   = str(row.get('gateway_site','')).strip().upper()
                direction = str(row.get('direction','')).strip().upper()
                if not cidr or not partner or not gw_site: continue
                if _is_invalid_ip(cidr): continue
                # Only partner-side — CVS-side already covered by IPAM pipeline
                if direction == 'LOCAL': continue
                zone_name = _GW_ZONE.get(gw_site, 'RI-3PLZ-PEERS')
                node_name = 'IPSec-Target-Remote'
                add(cidr, zone_name, partner, node_name)
                stats['vpn_peers'] += 1
        print(f'  {stats["vpn_peers"]:,} VPN subnet entries')
    else:
        print('  vpn_protected_subnets.csv not found — skipping Tier 0a')

    # ── Tier 0b: VPN ISAKMP peer anchors (unchanged) ─────────────────────────
    vpn_peers = (latest(vpn_dir, 'vpn_peer_registry*.csv') or
                 latest(vpn_dir, 'ent-ipdataset-VPN-PEER-REGISTRY*.csv') or
                 (os.path.join(vpn_dir,'vpn_peer_registry.csv')
                  if os.path.exists(os.path.join(vpn_dir,'vpn_peer_registry.csv')) else ''))
    isakmp_count = 0
    if vpn_peers and os.path.exists(vpn_peers):
        print(f'Processing VPN peer registry: {os.path.basename(vpn_peers)}')
        _GW_ZONE = {'SHEA':'SHEA-3PLZ-PEERS','WOONSOCKET':'RI-3PLZ-PEERS',
                    'WDC':'WDC-3PLZ-PEERS','MDC':'MDC-3PLZ-PEERS'}
        with open(vpn_peers, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                peer_ip   = str(row.get('peer_ip','')).strip()
                partner   = str(row.get('partner_name','')).strip().replace('/','_')
                csna_path = str(row.get('csna_hostgroup_path','')).strip()
                gw_site   = str(row.get('gateway_site','')).strip().upper()
                if not peer_ip or not gw_site: continue
                if _is_invalid_ip(peer_ip): continue
                try: ipaddress.ip_address(peer_ip)
                except: continue
                # IP-based: use pre-computed CSNA path (stable across tunnel-group renames)
                # Falls back to partner_name when path is absent
                if csna_path:
                    group_name = csna_path.rstrip('/').split('/')[-1].replace('/','_')
                else:
                    group_name = partner
                if not group_name: continue
                zone_name = _GW_ZONE.get(gw_site, 'RI-3PLZ-PEERS')
                add(f'{peer_ip}/32', zone_name, group_name, 'ISAKMP-Anchor')
                isakmp_count += 1
        print(f'  {isakmp_count:,} ISAKMP anchor entries')
    else:
        print('  vpn_peer_registry.csv not found — skipping Tier 0b')
    print()


    # ── Tier 0d: P2P/MPLS partner subnets ────────────────────────────────────
    p2p_subs = (latest(vpn_dir, 'ent-ipdataset-P2P-PROTECTED-SUBNETS*.csv') or
                latest(vpn_dir, 'p2p_protected_subnets*.csv') or '')
    p2p_count = 0
    if p2p_subs and os.path.exists(p2p_subs):
        print(f'Processing P2P/MPLS protected subnets: {os.path.basename(p2p_subs)}')
        _P2P_ZONE = {'SHEA':       'SHEA-P2P-PARTNERS',
                     'WOONSOCKET': 'RI-P2P-PARTNERS',
                     'WDC':        'WDC-P2P-PARTNERS',
                     'MDC':        'MDC-P2P-PARTNERS',
                     'PDC':        'PDC-P2P-PARTNERS'}
        with open(p2p_subs, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                cidr      = str(row.get('IP_NETWORK', '') or row.get('CIDR', '')).strip()
                partner   = str(row.get('PARTNER_NAME', '')).strip().replace('/', '_')
                gw_site   = str(row.get('GATEWAY_SITE', '') or row.get('gateway_site', '')).strip().upper()
                direction = str(row.get('DIRECTION', '')).strip().upper()
                link_type = str(row.get('LINK_TYPE', '')).strip()
                if not cidr or not partner or not gw_site: continue
                if _is_invalid_ip(cidr): continue
                # Only partner-side — CVS-side already covered by IPAM pipeline
                if direction == 'CVS': continue
                zone_name = _P2P_ZONE.get(gw_site, 'SHEA-P2P-PARTNERS')
                node_name = f'P2P-{link_type}'
                add(cidr, zone_name, partner, node_name)
                p2p_count += 1
        print(f'  {p2p_count:,} P2P/MPLS subnet entries')
    else:
        print('  ent-ipdataset-P2P-PROTECTED-SUBNETS*.csv not found — skipping Tier 0d')
    print()

    seen_cidrs = set()


    # ── Tier 0c: Retail /26 store subnets (unchanged — STATES-based) ─────────
    if retail_path and os.path.exists(retail_path):
        print(f'Processing retail networks: {os.path.basename(retail_path)}')
        _RETAIL_NODE = {
            'Retail-Store':        'Retail-Store',
            'Retail-MinuteClinic': 'Retail-MinuteClinic',
            'Retail-Optical':      'Retail-Optical',
        }
        with open(retail_path, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                cidr = row.get('CIDR','').strip()
                if not cidr: continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except: continue
                if net.prefixlen != 26: continue
                if row.get('STORE_CLOSED_DATE','').strip(): continue
                if cidr in seen_cidrs: continue
                seen_cidrs.add(cidr)
                state = (row.get('STATES','') or '').strip()
                nt    = (row.get('NET_TYPE','') or 'Retail-Store').strip()
                node  = _RETAIL_NODE.get(nt, 'Retail-Store')
                site  = f'Retail Stores - {state}' if state else 'Retail Stores'
                add(cidr, 'RETAIL', site, node)
                stats['retail'] += 1
        print(f'  {stats["retail"]:,} retail /26 store subnet entries')
    else:
        print('  retail_networks_v*.csv not found — skipping Tier 0c')
    print()

    # ── Tiers 1–3: SITE_CODE pipeline ────────────────────────────────────────
    # Shared helper — resolve SITE_CODE then zone/site for a single IP
    def process_ip(ip, source_row, tier_label):
        if not ip or ':' in ip or _is_invalid_ip(ip): return False
        try: ipaddress.ip_address(ip)
        except: return False
        if ip in covered: return False
        ipam_row = lpm_lookup(ip, by_prefix, prefix_lens)
        sc, lm_row, rd, nt = resolve_sc(ip, ipam_row, source_row, overlay, lm_by_name, lm_by_sc)
        if not lm_row and sc:
            lm_row = lm_by_sc.get(sc)
        if is_excluded(sc, lm_row):
            return False
        z = sc_to_zone(sc, lm_row, registry_by_sc)
        s = sc_to_site(sc, lm_row, registry_by_sc)
        if z == 'UNKNOWN' or s == 'UNKNOWN':
            unresolved.append((f'{ip}/32', tier_label,
                               f'sc={sc!r} lt={lm_row.get("LOCATION_TYPE","?") if lm_row else "no-lm"}'))
        z, s = effective_zone_and_site(z, s)
        n = None  # caller sets node type
        return (z, s, lm_row, nt)

    # ── Tier 1: Network devices ───────────────────────────────────────────────
    for fpath, label in [(nms_path,'NMS'),(ndm_path,'NDM')]:
        if not fpath or not os.path.exists(fpath): continue
        print(f'Processing {label}: {os.path.basename(fpath)}')
        with open(fpath, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                ip = str(row.get('MANAGEMENT_IP','') or row.get('IP_ADDRESS','')).strip()
                if not ip or ip == '127.0.0.1': continue
                ipam_row = lpm_lookup(ip, by_prefix, prefix_lens)
                sc, lm_row, rd, nt = resolve_sc(ip, ipam_row, row, overlay, lm_by_name, lm_by_sc)
                if not lm_row and sc: lm_row = lm_by_sc.get(sc)
                if is_excluded(sc, lm_row): continue
                z = sc_to_zone(sc, lm_row, registry_by_sc)
                s = sc_to_site(sc, lm_row, registry_by_sc)
                if z == 'UNKNOWN':
                    unresolved.append((f'{ip}/32', label,
                                       f'sc={sc!r} lt={(lm_row or {}).get("LOCATION_TYPE","?")}'))
                z, s = effective_zone_and_site(z, s)
                n = node_type_network(row.get('DEVICE_TYPE',''), row.get('VENDOR',''), row.get('MODEL',''))
                add(f'{ip}/32', z, s, n)
                covered.add(ip)
                stats['net_devices'] += 1
    print(f'  {stats["net_devices"]:,} network device entries')

    # ── Tier 1b: Delivery infrastructure ─────────────────────────────────────
    if infra_path and os.path.exists(infra_path):
        print(f'Processing delivery infrastructure: {os.path.basename(infra_path)}')
        with open(infra_path, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                ip = str(row.get('IP_ADDRESS','') or row.get('IP','')).strip()
                if not ip or ':' in ip or ip in covered: continue
                try: ipaddress.ip_address(ip)
                except: continue
                ipam_row = lpm_lookup(ip, by_prefix, prefix_lens)
                sc, lm_row, rd, nt = resolve_sc(ip, ipam_row, row, overlay, lm_by_name, lm_by_sc)
                if not lm_row and sc: lm_row = lm_by_sc.get(sc)
                if is_excluded(sc, lm_row): continue
                z = sc_to_zone(sc, lm_row, registry_by_sc)
                s = sc_to_site(sc, lm_row, registry_by_sc)
                if z == 'UNKNOWN':
                    unresolved.append((f'{ip}/32', 'Infra',
                                       f'sc={sc!r} lt={(lm_row or {}).get("LOCATION_TYPE","?")}'))
                z, s = effective_zone_and_site(z, s)
                add(f'{ip}/32', z, s, node_type_infra(row))
                covered.add(ip); stats['infra_hosts'] += 1
        print(f'  {stats["infra_hosts"]:,} infrastructure host entries')
    else:
        print('  delivery_infrastructure not found — skipping Tier 1b')
    print()

    # ── Tier 1c: Delivery platform ────────────────────────────────────────────
    if platform_path and os.path.exists(platform_path):
        print(f'Processing delivery platform: {os.path.basename(platform_path)}')
        with open(platform_path, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                ip = str(row.get('IP_ADDRESS','') or row.get('IP','')).strip()
                if not ip or ':' in ip or ip in covered: continue
                try: ipaddress.ip_address(ip)
                except: continue
                ipam_row = lpm_lookup(ip, by_prefix, prefix_lens)
                sc, lm_row, rd, nt = resolve_sc(ip, ipam_row, row, overlay, lm_by_name, lm_by_sc)
                if not lm_row and sc: lm_row = lm_by_sc.get(sc)
                if is_excluded(sc, lm_row): continue
                z = sc_to_zone(sc, lm_row, registry_by_sc)
                s = sc_to_site(sc, lm_row, registry_by_sc)
                if z == 'UNKNOWN':
                    unresolved.append((f'{ip}/32', 'Platform',
                                       f'sc={sc!r} lt={(lm_row or {}).get("LOCATION_TYPE","?")}'))
                z, s = effective_zone_and_site(z, s)
                add(f'{ip}/32', z, s, node_type_platform(row))
                covered.add(ip); stats['platform_hosts'] += 1
        print(f'  {stats["platform_hosts"]:,} platform host entries')
    else:
        print('  delivery_platform not found — skipping Tier 1c')
    print()

    # ── Tier 2: Known hosts ───────────────────────────────────────────────────
    if host_path and os.path.exists(host_path):
        print(f'Processing host master: {os.path.basename(host_path)}')
        with open(host_path, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                ip = str(row.get('IP_ADDRESS','') or row.get('IP','')).strip()
                if not ip or ':' in ip or ip in covered: continue
                try: ipaddress.ip_address(ip)
                except: continue
                ipam_row = lpm_lookup(ip, by_prefix, prefix_lens)
                sc, lm_row, rd, nt = resolve_sc(ip, ipam_row, row, overlay, lm_by_name, lm_by_sc)
                if not lm_row and sc: lm_row = lm_by_sc.get(sc)
                if is_excluded(sc, lm_row): continue
                z = sc_to_zone(sc, lm_row, registry_by_sc)
                s = sc_to_site(sc, lm_row, registry_by_sc)
                if z == 'UNKNOWN':
                    unresolved.append((f'{ip}/32', 'EHM',
                                       f'sc={sc!r} lt={(lm_row or {}).get("LOCATION_TYPE","?")}'))
                z, s = effective_zone_and_site(z, s)
                add(f'{ip}/32', z, s, node_type_host(row))
                covered.add(ip); stats['hosts'] += 1
    print(f'  {stats["hosts"]:,} host entries')

    # ── Tier 3: IPAM subnets (gap fill) ──────────────────────────────────────
    print('Processing IPAM subnets...')
    ipam_files = [f for f in [ipam_path] + all_patches if f and os.path.exists(f)]
    for fpath in ipam_files:
        with open(fpath, newline='', encoding='utf-8-sig') as f:
            for row in csv.DictReader(l for l in f if not l.startswith('#')):
                cidr = row.get('CIDR','').strip()
                if not cidr or ':' in cidr or cidr in seen_cidrs: continue
                seen_cidrs.add(cidr)
                try: net = ipaddress.ip_network(cidr, strict=False)
                except: continue
                if net.prefixlen == 32 and str(net.network_address) in covered: continue
                sc = row.get('SITE_CODE','').strip()
                lm_row = lm_by_sc.get(sc) if sc else None
                if is_excluded(sc, lm_row): continue
                z = sc_to_zone(sc, lm_row, registry_by_sc)
                s = sc_to_site(sc, lm_row, registry_by_sc)
                if z == 'UNKNOWN':
                    unresolved.append((cidr, 'IPAM-T3',
                                       f'sc={sc!r} lt={(lm_row or {}).get("LOCATION_TYPE","?")}'))
                z, s = effective_zone_and_site(z, s)
                nt = (lm_row.get('NET_TYPE','') if lm_row else '') or row.get('NET_TYPE','')
                add(cidr, z, s, node_type_subnet(nt))
                stats['subnets'] += 1
    print(f'  {stats["subnets"]:,} subnet entries')

    # ── Summary ───────────────────────────────────────────────────────────────
    total = sum(stats.values())
    print(f'\nTotal rows:   {total:,}')
    print(f'  VPN peers:        {stats["vpn_peers"]:,}')
    print(f'  Network devices:  {stats["net_devices"]:,}')
    print(f'  Infra hosts:      {stats["infra_hosts"]:,}')
    print(f'  Platform hosts:   {stats["platform_hosts"]:,}')
    print(f'  App/Server hosts: {stats["hosts"]:,}')
    print(f'  Retail subnets:   {stats["retail"]:,}')
    print(f'  IPAM subnets:     {stats["subnets"]:,}')
    print(f'\nUnresolved (UNKNOWN zone): {len(unresolved):,}')
    print()
    print('Zone distribution:')
    for z, cnt in sorted(zone_dist.items(), key=lambda x:-x[1]):
        if cnt == 0: continue
        bar = '█' * min(40, int(40*cnt/max(total,1)))
        pct = f'{100*cnt/max(total,1):.1f}%'
        print(f'  {z:<22} {cnt:7,}  {pct:6}  {bar}')

    if args.dry_run:
        print('\n[DRY RUN] No files written.')
        return

    os.makedirs(odir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Write unresolved log
    if unresolved:
        unres_path = os.path.join(odir, f'csna_unresolved_{ts}.csv')
        with open(unres_path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['CIDR_OR_IP','TIER','REASON'])
            w.writerows(unresolved)
        print(f'\nUnresolved log: {unres_path}  ({len(unresolved):,} entries)')

    # Auto-increment export version
    global ROOT_NAME
    def _next_import_version(out_dir):
        max_ver = 0
        for xf in glob.glob(os.path.join(out_dir, 'CSNA_Import_*.xml')):
            try:
                with open(xf, encoding='utf-8', errors='ignore') as _f:
                    for line in _f:
                        m = re.search(r'name="CSNA Export v(\d+)\.0"', line)
                        if m:
                            max_ver = max(max_ver, int(m.group(1)))
                            break
            except OSError: continue
        return max_ver + 1

    _import_ver = _next_import_version(odir)
    ROOT_NAME = f'CSNA Export v{_import_ver}.0'
    print(f'Import version: {ROOT_NAME}')

    csv_path = os.path.join(odir, f'CSNA_hostgroups_{ts}.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        for cidr, path in rows_out:
            f.write(f'{cidr},{path}\r\n')
    print(f'\nCSV written: {csv_path}  ({total:,} rows)')

    if not args.no_xml:
        root = build_tree(rows_out, ROOT_NAME)
        assign_ids(root, XML_START_ID)
        xml_path = os.path.join(odir, f'CSNA_Import_{ts}.xml')
        xml_meta = {
            'generated_by':  f'generate_csna_hostgroups.py v{SCRIPT_VERSION}',
            'generated_at':  datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            'pipeline':      'SITE_CODE-driven (v4.0)',
            'ipam_file':     os.path.basename(ipam_path) if ipam_path else None,
            'retail_file':   os.path.basename(retail_path) if retail_path else None,
            'lm_file':       os.path.basename(lm_path) if lm_path else None,
            'host_master':   os.path.basename(host_path) if host_path else None,
            'ndm_file':      os.path.basename(ndm_path) if ndm_path else None,
        }
        lines = write_xml(root, xml_path, meta=xml_meta)
        kb = os.path.getsize(xml_path) / 1024
        print(f'XML written: {xml_path}  ({lines:,} lines, {kb:.0f} KB)')
        ok = continuity_check(csv_path, xml_path, rows_out)
        if not ok:
            sys.exit(1)

    print('\nDone.')


if __name__ == '__main__':
    main()
