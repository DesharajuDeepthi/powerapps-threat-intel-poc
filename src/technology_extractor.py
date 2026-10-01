from __future__ import annotations

import re

from src.models import TechnologyAssociation

TECHNOLOGY_PATTERNS = {
    "Microsoft Exchange Server": ("Microsoft", r"\bMicrosoft Exchange(?: Server)?\b|\bExchange Server\b"),
    "Microsoft Windows": ("Microsoft", r"\bMicrosoft Windows\b|\bWindows\b"),
    "FortiOS": ("Fortinet", r"\bFortiOS\b"),
    "Fortinet": ("Fortinet", r"\bFortinet\b"),
    "VMware ESXi": ("VMware", r"\bVMware ESXi\b|\bESXi\b"),
    "VMware": ("VMware", r"\bVMware\b"),
    "Linux": ("Linux", r"\bLinux\b"),
    "FreeBSD": ("FreeBSD", r"\bFreeBSD\b"),
    "Docker": ("Docker", r"\bDocker\b"),
    "Kubernetes": ("Kubernetes", r"\bKubernetes\b|\bk8s\b"),
    "Apache": ("Apache", r"\bApache\b"),
    "Cisco": ("Cisco", r"\bCisco\b"),
    "Palo Alto": ("Palo Alto Networks", r"\bPalo Alto\b|\bPAN-OS\b"),
    "Citrix": ("Citrix", r"\bCitrix\b"),
    "Ivanti": ("Ivanti", r"\bIvanti\b"),
    "Oracle": ("Oracle", r"\bOracle\b"),
    "Java": ("Oracle", r"\bJava\b"),
}


def associate_technology(context: str) -> TechnologyAssociation:
    for technology, (vendor, pattern) in TECHNOLOGY_PATTERNS.items():
        match = re.search(pattern, context, flags=re.IGNORECASE)
        if match:
            return TechnologyAssociation(
                technology=technology,
                vendor=vendor,
                association_evidence=_evidence_sentence(context, match.group(0)),
            )
    return TechnologyAssociation(
        technology="UNKNOWN",
        vendor="UNKNOWN",
        association_evidence="No supported technology pattern was found in the CVE context window.",
    )


def _evidence_sentence(context: str, matched_text: str) -> str:
    sentences = re.split(r"(?<=[.!?])\s+", context.strip())
    for sentence in sentences:
        if matched_text.lower() in sentence.lower():
            return sentence.strip()
    return context.strip()
