#!/usr/bin/env python3
import os, re, json, time, datetime, hashlib
from typing import List, Dict, Any
import requests, feedparser, yaml
from bs4 import BeautifulSoup

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
CONFIG_DIR = os.path.join(os.path.dirname(__file__), "..", "config")
SOURCES_FILE = os.path.join(CONFIG_DIR, "sources.yaml")
LATEST_FILE = os.path.join(DATA_DIR, "latest.json")
LAST_SEEN_FILE = os.path.join(DATA_DIR, "last_seen.json")
EMAIL_SUMMARY_FILE = os.path.join(DATA_DIR, "email_summary.txt")

DEFAULT_KEV = os.getenv(
    "KEV_FEED_URL",
    # Public KEV JSON feed; change anytime via secret
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

USER_AGENT = "GitHubActions-OSINT-Monitor/1.0 (+https://github.com)"
TIMEOUT = 20
SLEEP_BETWEEN_REQ = 1.0

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

KEYWORDS = [
    "exploited in the wild",
    "actively exploited",
    "exploit available",
    "proof-of-concept",
    "PoC",
    "0-day",
    "zero-day",
    "under active exploitation",
    "observed exploitation",
    "failed exploitation",
    "successful exploitation",
    "attackers are exploiting",
    "exploitation ongoing",
]

def _req(url: str, headers: Dict[str, str] | None = None) -> requests.Response:
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    r = requests.get(url, headers=h, timeout=TIMEOUT)
    r.raise_for_status()
    time.sleep(SLEEP_BETWEEN_REQ)
    return r

def load_sources() -> Dict[str, Any]:
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def extract_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(" ", strip=True)

def extract_cves(text: str) -> List[str]:
    return sorted(set(m.upper() for m in CVE_RE.findall(text)))

def classify_claim(text: str) -> str:
    lower = text.lower()
    hits = [k for k in KEYWORDS if k.lower() in lower]
    if not hits and extract_cves(text):
        # Mentioning CVEs without keywords -> advisory/POC mention
        return "mention"
    if not hits:
        return "none"
    # Rough tiering
    if any(k in lower for k in ["exploited in the wild", "actively exploited", "under active exploitation", "observed exploitation", "successful exploitation"]):
        return "verified/active"
    if any(k in lower for k in ["0-day", "zero-day", "proof-of-concept", "poc"]):
        return "likely/poc"
    if "failed exploitation" in lower:
        return "failed"
    return "rumor"

def load_kev_set(kev_url: str) -> set[str]:
    kev = set()
    try:
        res = _req(kev_url)
        data = res.json()
        items = data.get("vulnerabilities") or data.get("known_exploited_vulnerabilities") or []
        for v in items:
            cve = (v.get("cveID") or v.get("cve_id") or "").upper()
            if cve.startswith("CVE-"):
                kev.add(cve)
    except Exception as e:
        print(f"[warn] KEV load failed: {e}; proceeding without KEV filter.")
    return kev

def load_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path: str, obj: Any):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def hash_key(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
    return h.hexdigest()[:16]

def collect_from_rss(url: str, name: str) -> List[Dict[str, Any]]:
    out = []
    feed = feedparser.parse(url)
    for e in feed.entries:
        title = getattr(e, "title", "") or ""
        link = getattr(e, "link", "") or ""
        summary = extract_text(getattr(e, "summary", "") or "")
        published = (getattr(e, "published", "") or getattr(e, "updated", "") or "")
        text = " ".join([title, summary])
        cves = extract_cves(text)
        claim = classify_claim(text)
        out.append({
            "source": name, "type": "rss", "title": title, "url": link,
            "published": published, "cves": cves, "claim": claim
        })
    return out

def collect_from_json(url: str, name: str, headers: Dict[str, str] | None = None) -> List[Dict[str, Any]]:
    out = []
    data = _req(url, headers).json()
    # Try common shapes; users can tailor for specific APIs
    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for k in ("items", "data", "results", "entries"):
            if k in data and isinstance(data[k], list):
                items = data[k]
                break
    for e in items:
        text_parts = []
        for k in ("title", "summary", "description", "body", "content", "text"):
            v = e.get(k)
            if isinstance(v, str):
                text_parts.append(v)
        text = " ".join(text_parts)
        link = e.get("url") or e.get("link") or ""
        title = e.get("title") or ""
        published = e.get("published") or e.get("date") or ""
        cves = extract_cves(text)
        claim = classify_claim(text)
        out.append({
            "source": name, "type": "json", "title": title, "url": link,
            "published": published, "cves": cves, "claim": claim
        })
    return out

def collect_from_html(url: str, name: str) -> List[Dict[str, Any]]:
    out = []
    res = _req(url)
    text = extract_text(res.text)
    cves = extract_cves(text)
    claim = classify_claim(text)
    out.append({
        "source": name, "type": "html", "title": url, "url": url,
        "published": "", "cves": cves, "claim": claim
    })
    return out

def main():
    sources = load_sources()
    kev = load_kev_set(DEFAULT_KEV)
    seen = load_json(LAST_SEEN_FILE, {"items": [], "cves": []})
    seen_urls = set(i.get("url") for i in seen.get("items", []))
    seen_cves = set(seen.get("cves", []))

    all_items: List[Dict[str, Any]] = []

    for s in sources.get("rss", []) or []:
        all_items += collect_from_rss(s["url"], s["name"])
    for s in sources.get("json", []) or []:
        headers = s.get("headers")
        all_items += collect_from_json(s["url"], s["name"], headers)
    for s in sources.get("html", []) or []:
        all_items += collect_from_html(s["url"], s["name"])

    # Filter: remove items where ALL CVEs are already on KEV
    filtered: List[Dict[str, Any]] = []
    for it in all_items:
        cves = set(it.get("cves") or [])
        if not cves:
            # Keep rumor/0-day mentions without CVE
            filtered.append(it)
        else:
            if not cves.issubset(kev):
                filtered.append(it)

    # Dedup by URL
    dedup_map: Dict[str, Dict[str, Any]] = {}
    for it in filtered:
        key = it.get("url") or hash_key(it.get("source", ""), it.get("title", ""))
        if key not in dedup_map:
            dedup_map[key] = it

    final_items = list(dedup_map.values())

    # Compute "new" vs last_seen
    new_items = []
    new_cves = set()
    for it in final_items:
        url = it.get("url")
        cves = it.get("cves") or []
        is_new = (url not in seen_urls) or any(cv not in seen_cves for cv in cves)
        if is_new:
            new_items.append(it)
        for cv in cves:
            new_cves.add(cv)

    # Persist latest and seen state
    save_json(LATEST_FILE, {"generated_at": datetime.datetime.utcnow().isoformat() + "Z", "items": final_items})
    save_json(LAST_SEEN_FILE, {"items": final_items, "cves": sorted(seen_cves.union(new_cves))})

    # Build email summary (only for new)
    lines = []
    if new_items:
        lines.append("New non‑KEV exploitation activity detected:\n")
        for it in new_items:
            title = it.get("title", "")
            src = it.get("source", "")
            url = it.get("url", "")
            claim = it.get("claim", "none")
            cves = ", ".join(it.get("cves") or [])
            lines.append(f"- [{src}] {title}\n  Type: {claim}\n  CVEs: {cves or 'N/A'}\n  Link: {url}\n")
    else:
        lines.append("No new non‑KEV items since the last run.\n")

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(EMAIL_SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[info] items collected: {len(all_items)}, after KEV filter: {len(final_items)}, new: {len(new_items)}")

if __name__ == "__main__":
    main()
