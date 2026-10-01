from __future__ import annotations

from src.indicator_extractor import extract_indicators, normalize_defanged_text


def test_defanged_indicators_are_normalized() -> None:
    text = "Visit hxxps://example[.]com and 84.32.188[.]57"

    normalized = normalize_defanged_text(text)
    indicators = extract_indicators(text)

    assert "https://example.com" in normalized
    assert "84.32.188.57" in indicators.ipv4
    assert "https://example.com" in indicators.urls
    assert "example.com" in indicators.domains


def test_extract_indicators_validates_ips_hashes_mitre_and_cves() -> None:
    text = (
        "CVE-2021-34473 bad ip 999.1.1.1 good 8.8.8.8 "
        "T1059.001 d41d8cd98f00b204e9800998ecf8427e "
        + ("a" * 64)
    )

    indicators = extract_indicators(text)

    assert indicators.cves == ["CVE-2021-34473"]
    assert indicators.ipv4 == ["8.8.8.8"]
    assert indicators.mitre_techniques == ["T1059.001"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in indicators.md5
    assert "a" * 64 in indicators.sha256


def test_extract_container_indicators() -> None:
    indicators = extract_indicators("Docker image registry.example.com/security/app:4.5 and nginx:1.25")

    assert "Docker" in indicators.container_indicators
    assert "registry.example.com/security/app:4.5" in indicators.container_indicators
    assert "nginx:1.25" in indicators.container_indicators
