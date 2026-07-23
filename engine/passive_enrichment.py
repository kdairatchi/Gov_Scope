"""Collect passive asset evidence for domains already in scope.

This module only queries public indexes and registration data. It does not
submit URLs for scanning and it does not make requests to discovered hosts.

Usage:
    python engine/passive_enrichment.py scope_chunk.txt
    python engine/passive_enrichment.py scope/rijksoverheid.txt --ip-file ip.txt

Optional environment variable:
    URLSCAN_API_KEY   API key for higher urlscan.io search quotas.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
import tldextract


USER_AGENT = "DutchGovScopePassiveEnrichment/1.0 (+https://github.com/kdairatchi/Gov_Scope)"
DEFAULT_TIMEOUT = 20
_extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def root_domain(value: str) -> str | None:
    ext = _extract(value.strip().lower().rstrip("."))
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def hostname(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    parsed = urlparse(value if "://" in value else "https://" + value)
    host = (parsed.hostname or "").lower().rstrip(".")
    return host or None


def in_scope_subdomain(host: str | None, domain: str) -> bool:
    return bool(host and host != domain and host.endswith("." + domain))


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_json(url: str, headers: dict[str, str] | None = None) -> object | None:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    for attempt in range(3):
        try:
            response = requests.get(url, headers=request_headers, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < 2:
                    time.sleep(2**attempt)
                    continue
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError):
            if attempt < 2:
                time.sleep(2**attempt)
    return None


def ct_hosts(domain: str) -> set[str]:
    data = get_json(f"https://crt.sh/?q={quote('%.' + domain)}&output=json")
    hosts: set[str] = set()
    if not isinstance(data, list):
        return hosts
    for item in data:
        if not isinstance(item, dict):
            continue
        for value in str(item.get("name_value", "")).splitlines():
            host = value.strip().lower().lstrip("*.").rstrip(".")
            if in_scope_subdomain(host, domain):
                hosts.add(host)
    return hosts


def urlscan_hosts(domain: str) -> set[str]:
    headers = {}
    if os.environ.get("URLSCAN_API_KEY"):
        headers["api-key"] = os.environ["URLSCAN_API_KEY"]
    data = get_json(
        "https://urlscan.io/api/v1/search/?q=" + quote(f"domain:{domain}") + "&size=100",
        headers,
    )
    hosts: set[str] = set()
    if not isinstance(data, dict):
        return hosts
    for result in data.get("results", []):
        if not isinstance(result, dict):
            continue
        page = result.get("page") or {}
        task = result.get("task") or {}
        if not isinstance(page, dict) or not isinstance(task, dict):
            continue
        values = [page.get("domain"), page.get("url"), task.get("url")]
        for value in values:
            host = hostname(str(value)) if value else None
            if in_scope_subdomain(host, domain):
                hosts.add(host)
    return hosts


def wayback_hosts(domain: str) -> set[str]:
    url = (
        "https://web.archive.org/cdx/search/cdx?url=*."
        + quote(domain)
        + "/*&output=json&fl=original&filter=statuscode:200"
        "&collapse=urlkey&limit=1000"
    )
    data = get_json(url)
    hosts: set[str] = set()
    if isinstance(data, list):
        values = data[1:] if data and data[0] == ["original"] else data
        for row in values:
            value = row[0] if isinstance(row, list) and row else row
            host = hostname(str(value)) if value else None
            if in_scope_subdomain(host, domain):
                hosts.add(host)
    return hosts


def commoncrawl_index() -> str | None:
    data = get_json("https://index.commoncrawl.org/collinfo.json")
    if not isinstance(data, list):
        return None
    for item in data:
        if isinstance(item, dict) and item.get("cdx-api"):
            return str(item["cdx-api"])
    return None


def commoncrawl_hosts(domain: str, index_url: str | None) -> set[str]:
    if not index_url:
        return set()
    url = f"{index_url}?url=*.{quote(domain)}/*&output=json&filter=status:200&pageSize=1000"
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=request_headers, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 404:
            return set()
        response.raise_for_status()
    except requests.RequestException:
        return set()
    hosts: set[str] = set()
    for line in response.text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            host = hostname(str(item.get("url", "")))
            if in_scope_subdomain(host, domain):
                hosts.add(host)
    return hosts


def rdap_domain(domain: str) -> dict[str, object] | None:
    data = get_json(f"https://rdap.org/domain/{quote(domain)}")
    if not isinstance(data, dict):
        return None
    nameservers = []
    for item in data.get("nameservers", []) or []:
        if isinstance(item, dict) and item.get("ldhName"):
            nameservers.append(str(item["ldhName"]).lower().rstrip("."))
    return {
        "domain": domain,
        "ldhName": data.get("ldhName"),
        "status": data.get("status", []),
        "nameservers": sorted(set(nameservers)),
        "entities": [
            entity.get("handle")
            for entity in data.get("entities", []) or []
            if isinstance(entity, dict) and entity.get("handle")
        ],
    }


def rdap_ip(ip: str) -> dict[str, object] | None:
    data = get_json(f"https://rdap.org/ip/{quote(ip)}")
    if not isinstance(data, dict):
        return None
    return {
        "ip": ip,
        "startAddress": data.get("startAddress"),
        "endAddress": data.get("endAddress"),
        "name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "entities": [
            entity.get("handle")
            for entity in data.get("entities", []) or []
            if isinstance(entity, dict) and entity.get("handle")
        ],
    }


def collect(domain: str, index_url: str | None) -> tuple[str, dict[str, set[str]], dict[str, object] | None]:
    functions = {
        "crtsh": lambda: ct_hosts(domain),
        "urlscan": lambda: urlscan_hosts(domain),
        "wayback": lambda: wayback_hosts(domain),
        "commoncrawl": lambda: commoncrawl_hosts(domain, index_url),
    }
    found: dict[str, set[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {name: pool.submit(function) for name, function in functions.items()}
        for name, future in futures.items():
            try:
                found[name] = future.result()
            except Exception:
                found[name] = set()
    return domain, found, rdap_domain(domain)


def read_domains(path: Path) -> list[str]:
    domains = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        domain = root_domain(line)
        if domain:
            domains.add(domain)
    return sorted(domains)


def merge_passive(domain_dir: Path, records: list[dict[str, object]]) -> None:
    path = domain_dir / "passive.jsonl"
    existing: dict[tuple[str, str], dict[str, object]] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
                key = (str(item.get("source")), str(item.get("host")))
                if key[0] and key[1]:
                    existing[key] = item
            except (json.JSONDecodeError, AttributeError):
                continue
    for record in records:
        key = (str(record["source"]), str(record["host"]))
        if key in existing:
            existing[key]["last_seen"] = record["last_seen"]
        else:
            existing[key] = record
    path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in sorted(existing.values(), key=lambda x: (x["host"], x["source"]))),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect passive scope enrichment")
    parser.add_argument("input", help="Scope file, one root domain per line")
    parser.add_argument("--storage", default="storage/rijksoverheid")
    parser.add_argument("--ip-file", help="Optional CIDR/IP file for RDAP IP/ASN metadata")
    parser.add_argument("--concurrency", type=int, default=3)
    args = parser.parse_args()

    domains = read_domains(Path(args.input))
    storage = Path(args.storage)
    storage.mkdir(parents=True, exist_ok=True)
    index_url = commoncrawl_index()
    print(f"Passive enrichment: {len(domains)} domains; Common Crawl: {bool(index_url)}")

    candidates: set[str] = set()
    evidence_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = [pool.submit(collect, domain, index_url) for domain in domains]
        for future in concurrent.futures.as_completed(futures):
            domain, sources, rdap = future.result()
            domain_dir = storage / domain
            if not domain_dir.exists():
                continue
            records = []
            for source, hosts in sources.items():
                for host in sorted(hosts):
                    record = {"host": host, "source": source, "first_seen": now(), "last_seen": now()}
                    records.append(record)
                    candidates.add(host)
                    evidence_count += 1
            if records:
                merge_passive(domain_dir, records)
            if rdap is not None:
                (domain_dir / "rdap.json").write_text(json.dumps({"observed_at": now(), **rdap}, indent=2) + "\n", encoding="utf-8")

    # Rebuild the aggregate from every per-domain evidence file so rotating
    # daily chunks do not make older passive candidates disappear.
    all_candidates: set[str] = set()
    for domain_dir in storage.iterdir():
        evidence_file = domain_dir / "passive.jsonl"
        if not evidence_file.exists():
            continue
        for line in evidence_file.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                host = json.loads(line).get("host")
                if isinstance(host, str) and host:
                    all_candidates.add(host)
            except json.JSONDecodeError:
                continue
    (storage / "passive_candidates.txt").write_text(
        "".join(host + "\n" for host in sorted(all_candidates)), encoding="utf-8"
    )

    if args.ip_file:
        ip_path = Path(args.ip_file)
        output = storage / "rdap_ip.jsonl"
        old = {}
        if output.exists():
            for line in output.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    item = json.loads(line)
                    old[item.get("ip")] = item
                except json.JSONDecodeError:
                    pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
            futures = {}
            for line in ip_path.read_text(encoding="utf-8").splitlines():
                value = line.strip().split("/", 1)[0]
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                futures[pool.submit(rdap_ip, value)] = value
            for future in concurrent.futures.as_completed(futures):
                item = future.result()
                if item:
                    old[item["ip"]] = {"observed_at": now(), **item}
        output.write_text("".join(json.dumps(old[key], ensure_ascii=False) + "\n" for key in sorted(old)), encoding="utf-8")

    print(f"Passive evidence records observed: {evidence_count}")
    print(f"Passive candidates: {len(all_candidates)}")


if __name__ == "__main__":
    main()
