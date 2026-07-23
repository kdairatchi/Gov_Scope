# Dutch Government Scope Monitor

An automated, evidence-backed inventory of Dutch government-related domains and subdomains.

> This repository is **not** an official bug bounty scope. Always verify current eligibility and follow the target's coordinated vulnerability disclosure policy before testing.

To report a vulnerability or to learn more about Coordinated Vulnerability Disclosure (CVD), visit:  
👉 [https://www.ncsc.nl/contact/kwetsbaarheid-melden](https://www.ncsc.nl/contact/kwetsbaarheid-melden)


## Overview

The project separates verified scope from discovery data. This prevents a stale certificate, archived URL, or third-party index result from being treated as an authorized target automatically.

### What is in scope?

This repository focuses on verified, government-related resources. Each domain is included only after passing a multi-tier verification pipeline:

1. **HTTP and TLS evidence**: government metadata, accessibility statements, government infrastructure references, redirects, and certificate organization fields.
2. **Rendered DOM evidence**: Playwright catches signals that appear only after a SPA renders.
3. **Optional visual review**: an image-capable model can inspect a screenshot for government branding. If no vision API key is configured, uncertain results remain in manual review.
4. **Human review boundary**: confirmed, rejected, and uncertain domains are written separately; passive observations never promote a domain automatically.


### How It Works

All analysis runs via **GitHub Actions**. Results are stored as plain text files in the repository.

1. **Domain scope maintenance** — `engine/refresh_rijksoverheid.py`:
   - Monthly sync with the official [CommunicatieRijk websiteregister](https://www.communicatierijk.nl/vakkennis/r/rijkswebsites/verplichte-richtlijnen/websiteregister-rijksoverheid)
   - New domains are verified through the three-tier pipeline (`engine/verify_rijksoverheid.py`)
   - Confirmed domains → `scope/rijksoverheid.txt`; rejected/uncertain → `scope/rijksoverheid_invalid.txt`

2. **Subdomain discovery** — runs daily via GitHub Actions:
   - Subfinder scans a rotating approximately 3% slice with overlap.
   - `-active` performs DNS validation, so this stage is hybrid passive discovery plus active DNS resolution.
   - Validated results are merged into per-domain storage and deduplicated aggregates.

3. **Passive enrichment** — runs with each rotating scan and as a weekly full refresh:
   - Certificate Transparency (`crt.sh`) for names present in issued certificates.
   - urlscan.io history for previously observed URLs and hostnames.
   - Wayback CDX and Common Crawl for historical URL evidence.
   - RDAP metadata for scoped domains and the IP ranges in `ip.txt`.
   - Passive candidates are stored separately and are not automatically promoted to confirmed scope.

4. **Distribution** — selected scope files can be synchronized to the configured GitHub Gist after subdomain scans.

### Automation schedule

| Workflow | Schedule | Purpose |
| --- | --- | --- |
| `Subdomain scan` | Daily, 03:00 UTC | Rotating Subfinder discovery plus passive enrichment |
| `Passive enrichment` | Sundays, 02:30 UTC | Full-scope passive refresh and IP RDAP metadata |
| `Communicatierijk scope update` | Monthly, 1st day, 04:00 UTC | Refresh and verify newly registered government domains |
| `Subdomain scan (manual)` | Manual | Scan a selected chunk or the full scope |
| `basisbeveiliging exec` | Manual | Optional scope update from basisbeveiliging data |
| `Update Gist` / `Gist sync` | Manual or after scan | Publish configured Gist files |


### Repository Structure

- [`scope/rijksoverheid.txt`](https://raw.githubusercontent.com/kdairatchi/Gov_Scope/main/scope/rijksoverheid.txt) – Verified root domains
- [`scope/rijksoverheid_invalid.txt`](https://raw.githubusercontent.com/kdairatchi/Gov_Scope/main/scope/rijksoverheid_invalid.txt) – Rejected or uncertain domains
- [`storage/subdomains.txt`](https://raw.githubusercontent.com/kdairatchi/Gov_Scope/main/storage/subdomains.txt) – All validated subdomains
- [`storage/rijksoverheid/subdomains.txt`](https://raw.githubusercontent.com/kdairatchi/Gov_Scope/main/storage/rijksoverheid/subdomains.txt) – Rijksoverheid subdomains
- `storage/rijksoverheid/<domain>/passive.jsonl` – Passive hostname observations with source and timestamps
- `storage/rijksoverheid/passive_candidates.txt` – Historical passive candidates for review
- `storage/rijksoverheid/<domain>/rdap.json` – Domain registration and nameserver metadata
- `storage/rijksoverheid/rdap_ip.jsonl` – IP-range RDAP metadata from `ip.txt`

The optional `URLSCAN_API_KEY` GitHub Actions secret increases urlscan.io search quota. Without it, enrichment still runs using unauthenticated public search limits. The optional `ANTHROPIC_API_KEY` enables screenshot review during scope verification.

### Evidence and confidence

| Data | Meaning | Default treatment |
| --- | --- | --- |
| `scope/rijksoverheid.txt` | Domain passed the government-identity verification pipeline | Confirmed scope candidate |
| `storage/.../subdomains.txt` | Host discovered by Subfinder and DNS-validated | High-confidence discovered host |
| `passive.jsonl` | Host observed in an external index or archive | Review before testing |
| `passive_candidates.txt` | Deduplicated union of passive observations | Discovery only |
| `rdap*.json*` | Registration, nameserver, or IP allocation metadata | Context and attribution |


## Usage

### Download the maintained lists

```bash
BASE=https://raw.githubusercontent.com/kdairatchi/Gov_Scope/main
curl --fail --silent --show-error "$BASE/scope/rijksoverheid.txt" -o scope.txt
curl --fail --silent --show-error "$BASE/storage/rijksoverheid/subdomains.txt" -o subdomains.txt
curl --fail --silent --show-error "$BASE/storage/rijksoverheid/passive_candidates.txt" -o passive_candidates.txt
```

Treat `passive_candidates.txt` as a review queue. Do not merge it into an authorized scan list without confirming scope and current ownership.

### Run the local enrichment engine

```bash
python3 -m pip install requests tldextract
python3 engine/passive_enrichment.py \
  scope/rijksoverheid.txt \
  --storage storage/rijksoverheid \
  --ip-file ip.txt \
  --concurrency 3
```

This queries public indexes and RDAP only. It does not submit URLs to urlscan or request pages from discovered hosts.

### Run scope verification

```bash
python3 engine/verify_rijksoverheid.py \
  scope/rijksoverheid.txt \
  --output-dir verification_results \
  --no-vision \
  --concurrency 5
```

Use `--no-vision` for a free HTTP/TLS-only verification pass. Browser verification requires Playwright and Chromium; screenshot review additionally requires the configured vision provider.

### Scan validated hosts responsibly

The following examples use Nuclei templates against the validated subdomain list. Only run active templates when you have confirmed authorization, and keep rate limits conservative.

```
curl --fail --silent --show-error "$BASE/storage/rijksoverheid/subdomains.txt" \
  | ./nuclei -silent -id geoserver-login-panel -rl 2
```

```
curl --fail --silent --show-error "$BASE/storage/rijksoverheid/subdomains.txt" \
  | ./nuclei -silent -id exposure -severity critical,high -rl 2
```

#### Scanning via Docker

```
curl --fail --silent --show-error "$BASE/storage/rijksoverheid/subdomains.txt" -o subdomains.txt
docker run --rm -v "$PWD:/data" projectdiscovery/nuclei \
  -silent -id geoserver-login-panel -rl 2 -l /data/subdomains.txt
```

Keep scan output private until a finding has been reproduced, triaged, and reported through the appropriate CVD channel.

## Development and maintenance

The main components are:

- `engine/refresh_rijksoverheid.py` — official register refresh and verification orchestration.
- `engine/verify_rijksoverheid.py` — HTTP/TLS, browser, and optional visual verification.
- `engine/process_subdomains.py` — validates, merges, and aggregates Subfinder output.
- `engine/passive_enrichment.py` — public-index and RDAP enrichment.

Before opening a change, run:

```bash
python3 -m compileall -q engine
git diff --check
ruby -e 'require "yaml"; ARGV.each { |f| YAML.load_file(f) }' .github/workflows/*.y*ml
```

The workflows require GitHub Actions to be enabled with `contents: write`. Optional secrets are `URLSCAN_API_KEY`, `ANTHROPIC_API_KEY`, `GIST_ID`, and `GIST_TOKEN`.


## Links and Acknowledgements

- [Bug Bounty Dutch Government Scope – Gist](https://gist.github.com/zzzteph/99a7bd2acde12cb4b2626fc9261bc56d)  
- [basisbeveiliging.nl](https://basisbeveiliging.nl/)  
- [overheid.nl](https://www.overheid.nl/english/dutch-government-websites)  
- [communicatierijk.nl](https://www.communicatierijk.nl/vakkennis/r/rijkswebsites/verplichte-richtlijnen/websiteregister-rijksoverheid)  
- [ncsc.nl](https://www.ncsc.nl/contact/kwetsbaarheid-melden/cvd-meldingen-formulier)  
- [NCSC Wall of Fame](https://www.ncsc.nl/contact/kwetsbaarheid-melden/wall-of-fame)  

---

To report a vulnerability or learn more, please visit:  
👉 [https://www.ncsc.nl/contact/kwetsbaarheid-melden](https://www.ncsc.nl/contact/kwetsbaarheid-melden)
