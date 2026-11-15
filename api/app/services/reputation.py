from urllib.parse import urlparse
import aiosqlite
from app.schemas import CheckRequest, CheckResponse


def extract_hostname(url: str) -> str | None:
    if not url:
        return None
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname is None:
            parsed = urlparse(f"//{url}")
            hostname = parsed.hostname
        if hostname:
            return hostname.lower().strip(".")
    except Exception:
        return None
    return None


def get_candidate_suffixes(hostname: str) -> list[str]:
    parts = hostname.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


async def check_reputation(db: aiosqlite.Connection, request: CheckRequest) -> CheckResponse:
    is_malicious = False
    threat_category: str | None = None
    flagged_urls: list[str] = []
    official_cert_match: bool | None = None

    # 1. Check SHA256 against malicious_hashes
    if request.sha256:
        norm_hash = request.sha256.lower().strip()
        cursor = await db.execute(
            "SELECT threat_category FROM malicious_hashes WHERE lower(sha256) = ?",
            (norm_hash,),
        )
        row = await cursor.fetchone()
        if row:
            is_malicious = True
            threat_category = row["threat_category"]

    # 2. Check URLs against malicious_domains
    if request.urls:
        url_host_map: list[tuple[str, str | None]] = []
        all_candidate_keys: set[str] = set()

        for url in request.urls:
            hostname = extract_hostname(url)
            url_host_map.append((url, hostname))
            if hostname:
                suffixes = get_candidate_suffixes(hostname)
                for s in suffixes:
                    all_candidate_keys.add(s)
                    all_candidate_keys.add(f".{s}")

        matched_domain_map: dict[str, str] = {}
        if all_candidate_keys:
            placeholders = ",".join("?" for _ in all_candidate_keys)
            cursor = await db.execute(
                f"SELECT domain, threat_category FROM malicious_domains WHERE lower(domain) IN ({placeholders})",
                list(all_candidate_keys),
            )
            rows = await cursor.fetchall()
            for r in rows:
                domain_clean = r["domain"].lower().lstrip(".")
                matched_domain_map[domain_clean] = r["threat_category"]

        for url, hostname in url_host_map:
            if not hostname:
                continue
            suffixes = get_candidate_suffixes(hostname)
            matched_suffix = None
            for s in suffixes:
                if s in matched_domain_map:
                    matched_suffix = s
                    break
            if matched_suffix is not None:
                flagged_urls.append(url)
                is_malicious = True
                if threat_category is None:
                    threat_category = matched_domain_map[matched_suffix]

    # 3. Check official cert
    if request.cert_sha256 is not None:
        norm_cert = request.cert_sha256.lower().strip()
        cursor = await db.execute(
            "SELECT 1 FROM official_certs WHERE lower(cert_sha256) = ?",
            (norm_cert,),
        )
        row = await cursor.fetchone()
        official_cert_match = row is not None

    # 4. Resolve verdict
    if is_malicious:
        verdict = "malicious"
    elif official_cert_match is True:
        verdict = "clean"
    else:
        verdict = "unknown"

    return CheckResponse(
        verdict=verdict,
        threat_category=threat_category,
        official_cert_match=official_cert_match,
        flagged_urls=flagged_urls,
    )
