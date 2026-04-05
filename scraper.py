"""
Vulnerability Intelligence Feed Scraper
========================================
Aggregates vulnerability data from RSS feeds and APIs.

Key behaviour:
  - CVE-aware deduplication: if the same CVE ID appears in multiple
    sources, the entry is MERGED rather than duplicated. New source
    URLs are appended to a `related_links` list on the existing entry.
  - Priority categories: emergency > infrastructure > web_app > cloud
  - Sources that require API keys read them from environment variables
    so secrets are never hard-coded.

Output files (served by Vercel):
  feed.json        page 1 — newest 50 entries
  feed-2.json      page 2
  ...
  feed-5.json      page 5  (250 entries total across all pages)
  archive.json     full rolling store (not served publicly)

Environment variables required for API sources:
  NVD_API_KEY          — get free key at https://nvd.nist.gov/developers/request-an-API-key
  VULDB_API_KEY        — get at https://vuldb.com/?subscribe
  OTX_API_KEY          — get at https://otx.alienvault.com (free account)
  GITHUB_TOKEN         — optional: raises GitHub API rate limit from 60 to 5000/hr
"""

import feedparser
import requests
import json
import hashlib
import re
import os
import logging
import time
from datetime import datetime, timezone, timedelta

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============================================================================
# PAGINATION SETTINGS
# ============================================================================

ARCHIVE_SIZE = 250
PAGE_SIZE    = 50
ARCHIVE_PATH = 'archive.json'

def page_filename(n):
    return 'feed.json' if n == 1 else f'feed-{n}.json'

# ============================================================================
# API KEYS  (read from environment — set as GitHub Secrets)
# ============================================================================

NVD_API_KEY    = os.getenv('NVD_API_KEY', '')
VULDB_API_KEY  = os.getenv('VULDB_API_KEY', '')
OTX_API_KEY    = os.getenv('OTX_API_KEY', '')
GITHUB_TOKEN   = os.getenv('GITHUB_TOKEN', '')

# ============================================================================
# CATEGORIES & KEYWORD MAPPING
# ============================================================================
# Priority order: emergency > infrastructure > web_app > cloud
# An article is assigned the HIGHEST priority category whose keywords match.

CATEGORY_PRIORITY = ['emergency', 'infrastructure', 'web_app', 'cloud']

CATEGORY_KEYWORDS = {
    'emergency': [
        'zero-day', 'zero day', '0-day', 'actively exploited', 'active exploitation',
        'exploited in the wild', 'RCE', 'remote code execution', 'unauthenticated',
        'mass exploitation', 'critical', 'CVSS 9', 'CVSS 10', 'patch tuesday emergency',
        'emergency patch', 'actively being exploited',
    ],
    'infrastructure': [
        'windows server', 'linux kernel', 'vmware', 'exchange server', 'VPN gateway',
        'fortinet', 'cisco ios', 'active directory', 'domain controller', 'hyper-v',
        'palo alto', 'juniper', 'F5 BIG-IP', 'LDAP', 'Kerberos', 'NTLM',
        'network device', 'router', 'firewall', 'switch vulnerability',
    ],
    'web_app': [
        'SQL injection', 'XSS', 'cross-site scripting', 'broken authentication',
        'SSRF', 'server-side request forgery', 'supply chain attack', 'dependency',
        'NPM package', 'PyPI', 'open source', 'Log4j', 'deserialization',
        'path traversal', 'file inclusion', 'CSRF', 'API vulnerability',
    ],
    'cloud': [
        'AWS IAM', 'Azure tenant', 'S3 bucket', 'kubernetes', 'docker container',
        'container escape', 'cloud misconfiguration', 'GCP', 'Azure AD',
        'IAM privilege escalation', 'serverless', 'lambda function', 'ECR', 'EKS',
    ],
}


def categorize(text):
    """
    Return the highest-priority matching category for a block of text.
    Returns None if no keywords match (article will be dropped).
    """
    lower = text.lower()
    for cat in CATEGORY_PRIORITY:
        for kw in CATEGORY_KEYWORDS[cat]:
            if kw.lower() in lower:
                return cat
    return None


# ============================================================================
# CVE EXTRACTION
# ============================================================================

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

def extract_cve_ids(text):
    """Return a sorted, deduplicated list of CVE IDs found in text."""
    found = CVE_PATTERN.findall(text or '')
    return sorted(set(c.upper() for c in found))


# ============================================================================
# SHARED HELPERS
# ============================================================================

def clean_text(text):
    if not text:
        return ''
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def make_hash(url):
    return hashlib.sha256(url.encode()).hexdigest()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def parse_feed_date(entry):
    for attr in ('published_parsed', 'updated_parsed'):
        parsed = getattr(entry, attr, None)
        if parsed:
            try:
                return datetime(*parsed[:6], tzinfo=timezone.utc).isoformat()
            except Exception:
                pass
    return now_iso()


RSS_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (compatible; VulnFeed/1.0; '
        '+https://github.com/your-org/vuln-feed)'
    )
}


def build_entry(url, title, summary, source, category, date, cve_ids=None, cvss=None):
    """Construct a normalised article dict."""
    return {
        'id':            make_hash(url),
        'url':           url,
        'title':         title,
        'summary':       summary[:400],
        'source':        source,
        'category':      category,
        'date':          date,
        'cve_ids':       cve_ids or [],
        'cvss':          cvss,           # float or None
        'related_links': [],             # filled in during CVE merge
    }


# ============================================================================
# RSS SOURCES
# ============================================================================

RSS_SOURCES = {
    'zdi': {
        'name':  'Zero Day Initiative',
        'url':   'https://www.zerodayinitiative.com/rss/published/',
    },
    'fulldisclosure': {
        'name':  'Full Disclosure',
        'url':   'https://seclists.org/rss/fulldisclosure.rss',
    },
    'packetstorm': {
        'name':  'Packet Storm',
        'url':   'https://rss.packetstormsecurity.com/files/',
    },
    'exploitdb': {
        'name':  'Exploit-DB',
        'url':   'https://www.exploit-db.com/rss.xml',
    },
    'hackerone': {
        'name':  'HackerOne',
        'url':   'https://hackerone.com/hacktivity.rss',
    },
    'googleprojectzero': {
        'name':  'Google Project Zero',
        'url':   'https://googleprojectzero.blogspot.com/feeds/posts/default',
    },
    'bleepingcomputer': {
        'name':  'Bleeping Computer',
        'url':   'https://www.bleepingcomputer.com/feed/',
    },
    'certcc': {
        'name':  'CERT/CC',
        'url':   'https://kb.cert.org/vince/comm/vulnerability/rss/',
    },
    'ubuntu': {
        'name':  'Ubuntu Security',
        'url':   'https://ubuntu.com/security/notices/rss.xml',
    },
    'cisco': {
        'name':  'Cisco Advisories',
        'url':   'https://tools.cisco.com/security/center/psirtrss20.xml',
    },
    'trendmicro': {
        'name':  'Trend Micro',
        'url':   'https://feeds.feedburner.com/TrendMicroSecurityIntelligence',
    },
    'qualys': {
        'name':  'Qualys Blog',
        'url':   'https://blog.qualys.com/category/vulnerabilities-threat-research/feed/',
    },
    'rapid7': {
        'name':  'Rapid7',
        'url':   'https://www.rapid7.com/blog/rss/',
    },
}


def fetch_rss(source_id, config):
    """Parse an RSS feed and return a list of normalised entry dicts."""
    entries = []
    logging.info(f"  RSS: {config['name']}")
    try:
        feed = feedparser.parse(config['url'], request_headers=RSS_HEADERS)
        if feed.bozo:
            logging.warning(f"    Feed warning: {feed.bozo_exception}")

        for item in feed.entries:
            try:
                title   = clean_text(item.get('title', ''))
                url     = item.get('link', '').strip()
                if not title or not url:
                    continue

                raw_summary = (
                    item.get('summary', '') or
                    item.get('description', '') or
                    (item.get('content') or [{}])[0].get('value', '')
                )
                summary  = clean_text(raw_summary)
                combined = title + ' ' + summary
                category = categorize(combined)
                if category is None:
                    continue

                cve_ids = extract_cve_ids(combined)
                entries.append(build_entry(
                    url      = url,
                    title    = title,
                    summary  = summary,
                    source   = config['name'],
                    category = category,
                    date     = parse_feed_date(item),
                    cve_ids  = cve_ids,
                ))
            except Exception as e:
                logging.warning(f"    Skipped entry: {e}")

        logging.info(f"    → {len(entries)} entries")
    except Exception as e:
        logging.error(f"    Failed: {e}")
    return entries


def fetch_all_rss():
    all_entries = []
    for sid, cfg in RSS_SOURCES.items():
        all_entries.extend(fetch_rss(sid, cfg))
        time.sleep(1)   # be polite between sources
    return all_entries


# ============================================================================
# CISA KEV  (JSON API — no key required)
# ============================================================================

CISA_KEV_URL = (
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
)


def fetch_cisa_kev():
    """
    Pull the CISA Known Exploited Vulnerabilities catalogue.
    Every entry here IS actively exploited → always 'emergency'.
    Returns entries published in the last 30 days to keep volume manageable.
    """
    entries = []
    logging.info('  API: CISA KEV')
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        cutoff = datetime.now(timezone.utc) - timedelta(days=30)

        for vuln in data.get('vulnerabilities', []):
            try:
                date_added = vuln.get('dateAdded', '')
                if date_added:
                    dt = datetime.strptime(date_added, '%Y-%m-%d').replace(
                        tzinfo=timezone.utc)
                    if dt < cutoff:
                        continue
                    date_iso = dt.isoformat()
                else:
                    date_iso = now_iso()

                cve_id  = vuln.get('cveID', '')
                title   = f"{cve_id}: {vuln.get('vulnerabilityName', 'Unknown vulnerability')}"
                summary = (
                    f"{vuln.get('shortDescription', '')} "
                    f"Affected product: {vuln.get('product', '')} by "
                    f"{vuln.get('vendorProject', '')}. "
                    f"Required action: {vuln.get('requiredAction', '')}"
                ).strip()
                url     = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}"

                entries.append(build_entry(
                    url      = url,
                    title    = title,
                    summary  = summary,
                    source   = 'CISA KEV',
                    category = 'emergency',      # all KEV entries are actively exploited
                    date     = date_iso,
                    cve_ids  = [cve_id] if cve_id else [],
                    cvss     = None,             # CISA KEV doesn't include CVSS
                ))
            except Exception as e:
                logging.warning(f"    Skipped KEV entry: {e}")

        logging.info(f"    → {len(entries)} recent KEV entries")
    except Exception as e:
        logging.error(f"    CISA KEV failed: {e}")
    return entries


# ============================================================================
# NVD / NIST  (REST API — free key required)
# ============================================================================

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def fetch_nvd():
    """
    Pull CVEs published in the last 7 days from the NVD.
    Only keeps entries with CVSS >= 7.0 or that match a category keyword.
    Requires NVD_API_KEY environment variable.
    """
    entries = []
    if not NVD_API_KEY:
        logging.warning('  API: NVD skipped — NVD_API_KEY not set')
        return entries

    logging.info('  API: NVD/NIST')
    try:
        end_dt   = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=7)
        params = {
            'pubStartDate': start_dt.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate':   end_dt.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': 100,
        }
        headers = {'apiKey': NVD_API_KEY}

        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        for item in data.get('vulnerabilities', []):
            try:
                cve     = item.get('cve', {})
                cve_id  = cve.get('id', '')
                descs   = cve.get('descriptions', [])
                summary = next(
                    (d['value'] for d in descs if d.get('lang') == 'en'), ''
                )

                # Extract CVSS score (prefer v3.1, fall back to v3.0 or v2)
                cvss = None
                metrics = cve.get('metrics', {})
                for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                    if key in metrics and metrics[key]:
                        try:
                            cvss = float(
                                metrics[key][0]['cvssData']['baseScore']
                            )
                            break
                        except (KeyError, ValueError, IndexError):
                            pass

                # Filter: keep CVSS >= 7.0 or keyword match
                combined = cve_id + ' ' + summary
                category = categorize(combined)
                if cvss and cvss >= 9.0:
                    category = 'emergency'
                elif cvss and cvss >= 7.0 and category is None:
                    category = 'infrastructure'  # high severity gets infra slot
                elif category is None:
                    continue

                published = cve.get('published', now_iso())
                title     = f"{cve_id} — CVSS {cvss:.1f}" if cvss else cve_id
                url       = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                entries.append(build_entry(
                    url      = url,
                    title    = title,
                    summary  = summary,
                    source   = 'NVD/NIST',
                    category = category,
                    date     = published,
                    cve_ids  = [cve_id],
                    cvss     = cvss,
                ))
            except Exception as e:
                logging.warning(f"    Skipped NVD entry: {e}")

        logging.info(f"    → {len(entries)} entries (CVSS >= 7.0)")
    except Exception as e:
        logging.error(f"    NVD fetch failed: {e}")
    return entries


# ============================================================================
# GITHUB ADVISORY  (REST API — token optional but recommended)
# ============================================================================

GITHUB_ADVISORY_URL = 'https://api.github.com/advisories'


def fetch_github_advisories():
    """
    Pull recent GitHub Security Advisories (GHSA).
    Covers open-source supply chain vulnerabilities (Log4j style).
    """
    entries = []
    logging.info('  API: GitHub Advisory')
    try:
        headers = {'Accept': 'application/vnd.github+json'}
        if GITHUB_TOKEN:
            headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'

        resp = requests.get(
            GITHUB_ADVISORY_URL,
            params={'per_page': 50, 'direction': 'desc', 'sort': 'published'},
            headers=headers,
            timeout=20,
        )
        resp.raise_for_status()
        advisories = resp.json()

        for adv in advisories:
            try:
                title   = adv.get('summary', '')
                summary = adv.get('description', '')[:400]
                url     = adv.get('html_url', '')
                if not title or not url:
                    continue

                combined = title + ' ' + summary
                category = categorize(combined)
                if category is None:
                    category = 'web_app'  # GHSA is always supply-chain / code

                cve_ids  = [c for c in (adv.get('cve_id') or [])] if isinstance(
                    adv.get('cve_id'), list
                ) else (
                    [adv['cve_id']] if adv.get('cve_id') else []
                )

                severity = adv.get('severity', '')
                if severity == 'critical':
                    category = 'emergency'

                cvss = None
                cvss_v = adv.get('cvss', {})
                if isinstance(cvss_v, dict) and 'score' in cvss_v:
                    try:
                        cvss = float(cvss_v['score'])
                        if cvss >= 9.0:
                            category = 'emergency'
                    except ValueError:
                        pass

                published = adv.get('published_at', now_iso())

                entries.append(build_entry(
                    url      = url,
                    title    = f"GHSA: {title}",
                    summary  = summary,
                    source   = 'GitHub Advisory',
                    category = category,
                    date     = published,
                    cve_ids  = cve_ids,
                    cvss     = cvss,
                ))
            except Exception as e:
                logging.warning(f"    Skipped advisory: {e}")

        logging.info(f"    → {len(entries)} advisories")
    except Exception as e:
        logging.error(f"    GitHub Advisory failed: {e}")
    return entries


# ============================================================================
# MICROSOFT SECURITY UPDATE API  (no key required)
# ============================================================================

MSRC_API_URL = 'https://api.msrc.microsoft.com/cvrf/v2.0/updates'


def fetch_microsoft_updates():
    """Pull the latest Microsoft Security Response Center update list."""
    entries = []
    logging.info('  API: Microsoft MSRC')
    try:
        resp = requests.get(
            MSRC_API_URL,
            headers={'Accept': 'application/json'},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()

        for update in data.get('value', [])[:20]:   # latest 20 update cycles
            try:
                title   = update.get('DocumentTitle', '')
                date_s  = update.get('CurrentReleaseDate', now_iso())
                doc_id  = update.get('ID', '')
                url     = f"https://msrc.microsoft.com/update-guide/releaseNote/{doc_id}"
                summary = (
                    f"Microsoft security update: {title}. "
                    f"Alias: {update.get('Alias', '')}."
                )

                combined = title + ' ' + summary
                category = categorize(combined)
                if category is None:
                    category = 'infrastructure'   # MSRC is always infra

                cve_ids = extract_cve_ids(combined)

                entries.append(build_entry(
                    url      = url,
                    title    = f"MSRC: {title}",
                    summary  = summary,
                    source   = 'Microsoft MSRC',
                    category = category,
                    date     = date_s,
                    cve_ids  = cve_ids,
                ))
            except Exception as e:
                logging.warning(f"    Skipped MSRC entry: {e}")

        logging.info(f"    → {len(entries)} MSRC entries")
    except Exception as e:
        logging.error(f"    MSRC failed: {e}")
    return entries


# ============================================================================
# CVE-AWARE DEDUPLICATION & ARCHIVE MERGE
# ============================================================================

def merge_into_archive(new_entries, existing):
    """
    Merge new entries into the existing archive with CVE-aware deduplication.

    Rules:
      1. URL-level dedup (same as cyber news feed): if the same URL was seen
         before, the new entry replaces the old one (fresher data wins).
      2. CVE-level dedup: if entry A and entry B share a CVE ID, they are
         treated as the SAME vulnerability. The FIRST (highest-priority)
         entry keeps its place; later entries' URLs are appended to
         `related_links` instead of creating a separate row.

    This keeps the dashboard clean — a single CVE won't flood the feed
    with 10 identical alerts from 10 different sources.
    """
    # Start from a clean map of existing entries keyed by URL hash
    by_id  = {e['id']: e for e in existing}

    # Also build a reverse map: CVE ID → entry id (first seen wins)
    cve_to_entry_id = {}
    for e in existing:
        for cve in e.get('cve_ids', []):
            if cve not in cve_to_entry_id:
                cve_to_entry_id[cve] = e['id']

    for entry in new_entries:
        # Check if any of this entry's CVE IDs already exist in the archive
        matched_entry_id = None
        for cve in entry.get('cve_ids', []):
            if cve in cve_to_entry_id:
                matched_entry_id = cve_to_entry_id[cve]
                break

        if matched_entry_id and matched_entry_id in by_id:
            # CVE match — append this URL as a related link instead
            existing_entry = by_id[matched_entry_id]
            if entry['url'] not in existing_entry['related_links'] \
                    and entry['url'] != existing_entry['url']:
                existing_entry['related_links'].append(entry['url'])
                # If new source has a higher-priority category, upgrade
                existing_cat = existing_entry['category']
                new_cat      = entry['category']
                if (CATEGORY_PRIORITY.index(new_cat) <
                        CATEGORY_PRIORITY.index(existing_cat)):
                    existing_entry['category'] = new_cat
                # Carry forward CVE IDs and CVSS if new entry has them
                for cve in entry.get('cve_ids', []):
                    if cve not in existing_entry['cve_ids']:
                        existing_entry['cve_ids'].append(cve)
                if entry.get('cvss') and (
                    not existing_entry.get('cvss') or
                    entry['cvss'] > existing_entry['cvss']
                ):
                    existing_entry['cvss'] = entry['cvss']
        else:
            # New unique entry — add it to the archive
            by_id[entry['id']] = entry
            # Register its CVE IDs
            for cve in entry.get('cve_ids', []):
                if cve not in cve_to_entry_id:
                    cve_to_entry_id[cve] = entry['id']

    merged = list(by_id.values())
    merged.sort(key=lambda e: e['date'], reverse=True)
    return merged[:ARCHIVE_SIZE]


# ============================================================================
# ARCHIVE I/O
# ============================================================================

def load_archive():
    if os.path.exists(ARCHIVE_PATH):
        try:
            with open(ARCHIVE_PATH, 'r', encoding='utf-8') as f:
                return json.load(f).get('articles', [])
        except Exception as e:
            logging.warning(f"Could not read archive: {e}")
    return []


def save_archive(articles, updated_ts):
    with open(ARCHIVE_PATH, 'w', encoding='utf-8') as f:
        json.dump({
            'updated':  updated_ts,
            'total':    len(articles),
            'articles': articles,
        }, f, ensure_ascii=False, indent=2)
    logging.info(f"Wrote {ARCHIVE_PATH}  ({len(articles)} articles)")


# ============================================================================
# PAGE FILE OUTPUT
# ============================================================================

def write_page_files(archive, updated_ts):
    total     = len(archive)
    act_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    for page_num in range(1, act_pages + 1):
        start  = (page_num - 1) * PAGE_SIZE
        chunk  = archive[start:start + PAGE_SIZE]
        path   = page_filename(page_num)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({
                'updated':        updated_ts,
                'page':           page_num,
                'total_pages':    act_pages,
                'total_articles': total,
                'page_size':      PAGE_SIZE,
                'articles':       chunk,
            }, f, ensure_ascii=False, indent=2)
        logging.info(f"Wrote {path}  ({len(chunk)} entries, page {page_num}/{act_pages})")


# ============================================================================
# MAIN
# ============================================================================

def main():
    logging.info('=' * 60)
    logging.info('Vulnerability Intelligence Feed Scraper')
    logging.info('=' * 60)

    updated_ts = now_iso()
    all_new    = []

    # ── RSS sources ───────────────────────────────────────────────
    logging.info('Fetching RSS sources…')
    all_new.extend(fetch_all_rss())

    # ── API sources ───────────────────────────────────────────────
    logging.info('Fetching API sources…')
    all_new.extend(fetch_cisa_kev())
    all_new.extend(fetch_nvd())
    all_new.extend(fetch_github_advisories())
    all_new.extend(fetch_microsoft_updates())

    # Basic URL-level dedup on freshly scraped batch before merge
    seen    = set()
    unique  = []
    for e in all_new:
        if e['id'] not in seen:
            seen.add(e['id'])
            unique.append(e)

    logging.info(f'Total unique new entries scraped: {len(unique)}')

    # ── Archive merge (CVE-aware) ─────────────────────────────────
    existing = load_archive()
    archive  = merge_into_archive(unique, existing)
    logging.info(f'Archive size after merge: {len(archive)}')

    save_archive(archive, updated_ts)
    write_page_files(archive, updated_ts)

    logging.info('Done.')


if __name__ == '__main__':
    main()
