from __future__ import annotations

import ipaddress
import re

from src.models import IndicatorSet

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
IPV4_CANDIDATE_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>()\"']+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
IMAGE_PATTERN = re.compile(
    r"\b(?:[a-z0-9.-]+(?::\d+)?/)?[a-z0-9._-]+/[a-z0-9._-]+:[A-Za-z0-9._-]+"
    r"|\b(?:nginx|redis|ubuntu|alpine|debian|node|python|postgres|mysql):[A-Za-z0-9._-]+\b",
    re.IGNORECASE,
)

CONTAINER_KEYWORDS = [
    "Docker",
    "Kubernetes",
    "container",
    "OCI",
    "Amazon ECR",
    "Azure Container Registry",
    "Google Artifact Registry",
]

DOMAIN_EXCLUSIONS = {
    "microsoft.com",
    "slack.com",
}


def normalize_defanged_text(text: str) -> str:
    normalized = text
    normalized = re.sub(r"hxxps://", "https://", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"hxxp://", "http://", normalized, flags=re.IGNORECASE)
    normalized = normalized.replace("[.]", ".").replace("(.)", ".")
    normalized = normalized.replace("[dot]", ".").replace("(dot)", ".")
    normalized = normalized.replace("[:]", ":")
    return normalized


def extract_indicators(text: str) -> IndicatorSet:
    normalized = normalize_defanged_text(text)
    cves = sorted({match.group(0).upper() for match in CVE_PATTERN.finditer(normalized)})
    urls = _clean_urls(URL_PATTERN.findall(normalized))
    ipv4 = sorted({candidate for candidate in IPV4_CANDIDATE_PATTERN.findall(normalized) if _valid_ipv4(candidate)})
    hashes = _extract_hashes(normalized)
    domains = _extract_domains(normalized, urls)
    mitre_techniques = sorted({match.group(0).upper() for match in MITRE_PATTERN.finditer(normalized)})
    container_indicators = _extract_container_indicators(normalized)

    return IndicatorSet(
        cves=cves,
        ipv4=ipv4,
        urls=urls,
        domains=domains,
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        mitre_techniques=mitre_techniques,
        container_indicators=container_indicators,
    )


def _clean_urls(values: list[str]) -> list[str]:
    cleaned = {value.rstrip(".,;:)].") for value in values}
    return sorted(cleaned)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _extract_hashes(text: str) -> dict[str, list[str]]:
    sha256 = {match.group(0).lower() for match in SHA256_PATTERN.finditer(text)}
    sha1 = {match.group(0).lower() for match in SHA1_PATTERN.finditer(text)}
    md5 = {match.group(0).lower() for match in MD5_PATTERN.finditer(text)}
    return {
        "sha256": sorted(sha256),
        "sha1": sorted(sha1 - sha256),
        "md5": sorted(md5 - sha1 - sha256),
    }


def _extract_domains(text: str, urls: list[str]) -> list[str]:
    domains = {match.group(0).lower().rstrip(".") for match in DOMAIN_PATTERN.finditer(text)}
    for url in urls:
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
        if host:
            domains.add(host.lower())

    filtered = {
        domain
        for domain in domains
        if domain not in DOMAIN_EXCLUSIONS and not _valid_ipv4(domain) and not domain.startswith("cve-")
    }
    return sorted(filtered)


def _extract_container_indicators(text: str) -> list[str]:
    indicators = set()
    lower_text = text.lower()
    for keyword in CONTAINER_KEYWORDS:
        if keyword.lower() in lower_text:
            indicators.add(keyword)
    indicators.update(match.group(0) for match in IMAGE_PATTERN.finditer(text))
    return sorted(indicators)
