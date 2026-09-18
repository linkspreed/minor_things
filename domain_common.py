#!/usr/bin/env python3
"""
Gemeinsames Cloudflare-Inventar-Modul fuer alle Domain-/DNS-Sicherheits-
Workflows. Einzige Quelle der Wahrheit: die tatsaechliche DNS-Konfiguration
bei Cloudflare, live bei jedem Lauf abgefragt - keine manuell gepflegten
Domain-Listen mehr noetig. Unterstuetzt beliebig viele Zonen (Domains) unter
demselben Cloudflare-Konto/Token.

Ergaenzt common.py, ohne dort etwas zu veraendern.
"""
import ipaddress
import socket
from typing import Optional

from common import http_get, with_retry


class CloudflareClient:
    def __init__(self, api_token: str, logger=None):
        self.headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
        self.logger = logger

    def list_zones(self) -> list:
        zones = []
        page = 1
        while True:
            r = http_get(
                'https://api.cloudflare.com/client/v4/zones',
                headers=self.headers, params={'per_page': 50, 'page': page},
                timeout=30, description='Cloudflare-Zonen auflisten', logger=self.logger,
            )
            r.raise_for_status()
            data = r.json()
            zones.extend(data.get('result') or [])
            info = data.get('result_info') or {}
            if page >= info.get('total_pages', 1):
                break
            page += 1
        return zones

    def list_dns_records(self, zone_id: str) -> list:
        records = []
        page = 1
        while True:
            r = http_get(
                f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
                headers=self.headers, params={'per_page': 100, 'page': page},
                timeout=30, description='Cloudflare-DNS-Eintraege auflisten', logger=self.logger,
            )
            r.raise_for_status()
            data = r.json()
            records.extend(data.get('result') or [])
            info = data.get('result_info') or {}
            if page >= info.get('total_pages', 1):
                break
            page += 1
        return records


def parse_list(raw: Optional[str]) -> list:
    """Wandelt eine kommagetrennte (oder zeilenweise) optionale Secret-Liste in
    eine saubere, deduplizierte Liste um. Kommentare mit '#' und Leerzeilen
    werden ignoriert. Wird nur noch fuer wenige, bewusst manuelle Ausnahme-
    Listen genutzt (z.B. Ignore-Listen), NICHT mehr fuer die Kern-Domainliste."""
    if not raw:
        return []
    items = []
    for chunk in raw.replace('\n', ',').split(','):
        val = chunk.strip().lower()
        if not val or val.startswith('#'):
            continue
        if val not in items:
            items.append(val)
    return items


def get_zones(api_token: str, zone_exclude: Optional[list] = None, logger=None) -> list:
    """Laedt alle Zonen (Domains), auf die der Token Zugriff hat. Optional
    lassen sich einzelne Zonen per Name ausschliessen (z.B. private, nicht mit
    LINKSPREED verbundene Domains im selben Cloudflare-Konto)."""
    cf = CloudflareClient(api_token, logger=logger)
    zones = with_retry(cf.list_zones, 'Cloudflare-Zonen laden', max_retries=3, base_delay=5, logger=logger)
    exclude = set((zone_exclude or []))
    return [z for z in zones if z.get('name') not in exclude]


def get_all_records(api_token: str, zones: list, logger=None) -> list:
    """Liefert eine flache Liste von (zone_name, zone_status, record_dict) fuer
    ALLE DNS-Eintraege (alle Typen) ueber alle uebergebenen Zonen hinweg."""
    cf = CloudflareClient(api_token, logger=logger)
    all_records = []
    for zone in zones:
        try:
            records = with_retry(
                lambda z=zone: cf.list_dns_records(z['id']),
                f"DNS-Eintraege laden ({zone.get('name', '?')})",
                max_retries=3, base_delay=5, logger=logger,
            )
        except Exception:
            continue
        for rec in records:
            all_records.append((zone.get('name'), zone.get('status'), rec))
    return all_records


def web_hostnames(all_records: list) -> dict:
    """Filtert aus der vollstaendigen Record-Liste nur die tatsaechlichen Web-
    Hostnamen heraus (A/AAAA/CNAME), ohne Wildcards und ohne interne
    Kontroll-Eintraege (z.B. _acme-challenge). Rueckgabe:
    {hostname: {'zone': zone_name, 'type': ..., 'content': ..., 'proxied': bool}}
    """
    hosts = {}
    for zone_name, _status, rec in all_records:
        if rec.get('type') not in ('A', 'AAAA', 'CNAME'):
            continue
        name = (rec.get('name') or '').lower()
        if not name or name.startswith('*') or name.split('.')[0].startswith('_'):
            continue
        hosts[name] = {
            'zone': zone_name,
            'type': rec.get('type'),
            'content': rec.get('content'),
            'proxied': bool(rec.get('proxied')),
        }
    return hosts


def txt_records_by_name(all_records: list) -> dict:
    """Gruppiert alle TXT-Eintraege nach Hostname (fuer SPF/DMARC/DKIM-Checks).
    Rueckgabe: {hostname: [content, content, ...]}"""
    out = {}
    for _zone_name, _status, rec in all_records:
        if rec.get('type') != 'TXT':
            continue
        name = (rec.get('name') or '').lower()
        content = (rec.get('content') or '').strip('"')
        out.setdefault(name, []).append(content)
    return out


def zone_status_map(zones: list) -> dict:
    return {z.get('name'): z.get('status') for z in zones}


# --- Subdomain-Takeover-Fingerprints (oeffentlich bekannt, kuratiert) ---

TAKEOVER_FINGERPRINTS = [
    ('github.io', "There isn't a GitHub Pages site here"),
    ('herokuapp.com', 'no such app'),
    ('herokudns.com', 'no such app'),
    ('s3.amazonaws.com', 'NoSuchBucket'),
    ('s3-website', 'NoSuchBucket'),
    ('cloudfront.net', 'ERROR: The request could not be satisfied'),
    ('azurewebsites.net', '404 Web Site not found'),
    ('trafficmanager.net', '404 Web Site not found'),
    ('blob.core.windows.net', 'BlobNotFound'),
    ('netlify.app', 'Not Found - Request ID'),
    ('surge.sh', 'project not found'),
    ('readthedocs.io', 'unknown'),
    ('shopify.com', 'Sorry, this shop is currently unavailable'),
    ('zendesk.com', 'Help Center Closed'),
    ('fastly.net', 'Fastly error: unknown domain'),
    ('wordpress.com', 'Do you want to register'),
    ('pantheonsite.io', '404 error unknown site'),
    ('desk.com', 'Please try again or try Desk.com'),
    ('helpjuice.com', "We could not find what you're looking for"),
    ('helpscoutdocs.com', 'No settings were found for this company'),
    ('ghost.io', 'The thing you were looking for is no longer here'),
    ('bitbucket.io', 'Repository not found'),
    ('unbouncepages.com', 'The requested URL was not found on this server'),
    ('tumblr.com', "Whatever you were looking for doesn't currently exist"),
]


def check_takeover_fingerprint(target: str) -> Optional[str]:
    for marker, _ in TAKEOVER_FINGERPRINTS:
        if marker in target:
            return marker
    return None


def fingerprint_text_for(marker: str) -> Optional[str]:
    for m, t in TAKEOVER_FINGERPRINTS:
        if m == marker:
            return t
    return None


def target_resolves(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        socket.gethostbyname(target)
        return True
    except Exception:
        return False


def fetch_body_snippet(hostname: str, logger=None) -> str:
    import requests
    for scheme in ('https', 'http'):
        try:
            r = requests.get(f'{scheme}://{hostname}', timeout=15, allow_redirects=True,
                              headers={'User-Agent': 'linkspreed-isms-security-scan/1.0'})
            return r.text[:5000]
        except Exception:
            continue
    return ''
