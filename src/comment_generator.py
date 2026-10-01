from __future__ import annotations


def generate_analyst_comment(
    *,
    cve: str,
    technology: str,
    semantic_category: str,
    relevance: str,
) -> str:
    technology_text = (
        f"is associated with {technology}"
        if technology != "UNKNOWN"
        else "was detected, but a specific affected technology was not reliably identified"
    )
    reason = semantic_category.replace("_", " ")

    if relevance == "HIGH":
        return (
            f"{cve} {technology_text}. The surrounding evidence aligns with {reason}. "
            f"Document relevance is HIGH."
        )
    if relevance == "REVIEW":
        return (
            f"{cve} {technology_text}. The surrounding evidence is potentially relevant "
            f"({reason}) and should be reviewed by an analyst."
        )
    return (
        f"{cve} was detected in the document, but the surrounding context appears primarily "
        f"{reason}. Document relevance is INFORMATIONAL."
    )
