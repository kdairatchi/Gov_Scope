import os
import sys
import requests

FILES = {
    "scope.txt": "scope/rijksoverheid.txt",
    "README.md": "README.md",
}


def api_error(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = response.text.strip()
    if isinstance(payload, dict):
        message = payload.get("message") or payload.get("error") or payload
        documentation = payload.get("documentation_url")
        return f"{message}" + (f" ({documentation})" if documentation else "")
    return str(payload)


def update_gist():
    gist_id = os.environ.get("GIST_ID", "").strip()
    gist_token = os.environ.get("GIST_TOKEN", "").strip()
    if not gist_id or not gist_token:
        raise RuntimeError("GIST_ID and GIST_TOKEN GitHub Actions secrets are required")

    # Accept either the raw ID or a pasted gist URL.
    gist_id = gist_id.rstrip("/").rsplit("/", 1)[-1]
    url = f"https://api.github.com/gists/{gist_id}"
    headers = {
        "Authorization": f"Bearer {gist_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "DutchGovScope-GistSync/1.0",
    }

    response = requests.get(url, headers=headers, timeout=20)
    if response.status_code != 200:
        raise RuntimeError(f"GitHub Gist lookup failed ({response.status_code}): {api_error(response)}")
    try:
        gist = response.json()
    except ValueError as exc:
        raise RuntimeError("GitHub Gist lookup returned invalid JSON") from exc
    if not isinstance(gist, dict) or not isinstance(gist.get("files"), dict):
        raise RuntimeError("GitHub Gist lookup returned an unexpected response without a files object")

    current = {name: gist["files"].get(name, {}).get("content", "") for name in FILES}

    updates = {}
    for target, source in FILES.items():
        if not os.path.exists(source):
            print(f"File not found: {source}")
            continue
        with open(source, "r", encoding="utf-8") as f:
            content = f.read()
        if content.strip() != current[target].strip():
            updates[target] = {"content": content}

    if not updates:
        print("No changes — gist is up to date.")
        return

    response = requests.patch(url, json={"files": updates}, headers=headers, timeout=20)
    if response.status_code == 200:
        print(f"Gist updated: {', '.join(updates.keys())}")
    else:
        raise RuntimeError(f"GitHub Gist update failed ({response.status_code}): {api_error(response)}")


if __name__ == "__main__":
    try:
        update_gist()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
