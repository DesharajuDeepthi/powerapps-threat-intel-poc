from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from typing import Iterable

LOGGER = logging.getLogger(__name__)

SECURITY_INTENTS = {
    "active_exploitation": "Threat actors are actively exploiting this vulnerability.",
    "initial_access": "Attackers used this vulnerability to gain initial access to victim systems.",
    "remote_code_execution": "This vulnerability allows remote code execution and is relevant to the attack.",
    "privilege_escalation": "Attackers used this vulnerability for privilege escalation.",
    "authentication_bypass": "This vulnerability was used to bypass authentication or multifactor authentication.",
    "lateral_movement": "This vulnerability or technology was used for lateral movement.",
    "data_exfiltration": "This vulnerability or technology was used to enable data theft or exfiltration.",
    "background_reference": "This vulnerability is mentioned only as historical, reference, background, or informational material.",
    "mitigation_only": "This vulnerability is mentioned only in defensive guidance or mitigation recommendations.",
}

HIGH_INTENTS = {
    "active_exploitation",
    "initial_access",
    "remote_code_execution",
    "privilege_escalation",
    "authentication_bypass",
}

INFORMATIONAL_INTENTS = {"background_reference", "mitigation_only"}

KEYWORD_HINTS = {
    "active_exploitation": {"exploit", "exploited", "exploiting", "active", "weaponized", "used"},
    "initial_access": {"initial", "access", "gained", "entry", "compromise", "victim"},
    "remote_code_execution": {"remote", "code", "execution", "rce"},
    "privilege_escalation": {"privilege", "escalation", "elevated", "administrator", "root"},
    "authentication_bypass": {"authentication", "bypass", "mfa", "multifactor", "login"},
    "lateral_movement": {"lateral", "movement", "pivot", "smb", "rdp"},
    "data_exfiltration": {"exfiltration", "exfiltrate", "stolen", "data", "theft"},
    "background_reference": {"background", "historical", "reference", "previously", "advisory"},
    "mitigation_only": {"mitigation", "patch", "update", "remediate", "recommend"},
}


@dataclass(frozen=True)
class SemanticResult:
    semantic_scores: dict[str, float]
    semantic_category: str
    document_relevance: str


class SemanticAnalyzer:
    def __init__(
        self,
        *,
        high_threshold: float,
        review_threshold: float,
        model_name: str,
        enable_sentence_transformer: bool = True,
    ) -> None:
        self.high_threshold = high_threshold
        self.review_threshold = review_threshold
        self.model_name = model_name
        self.enable_sentence_transformer = enable_sentence_transformer
        self._model = None
        self._model_load_attempted = False

    def analyze(self, context: str) -> SemanticResult:
        scores = self._model_scores(context) if self.enable_sentence_transformer else None
        if scores is None:
            scores = self._keyword_scores(context)

        semantic_category = max(scores, key=scores.get)
        relevance = self._classify_relevance(scores, semantic_category)
        return SemanticResult(
            semantic_scores=scores,
            semantic_category=semantic_category,
            document_relevance=relevance,
        )

    def _model_scores(self, context: str) -> dict[str, float] | None:
        model = self._load_model()
        if model is None:
            return None

        try:
            labels = list(SECURITY_INTENTS)
            embeddings = model.encode([context, *[SECURITY_INTENTS[label] for label in labels]])
            context_vector = embeddings[0]
            scores = {
                label: round(_cosine_similarity(context_vector, embeddings[index + 1]), 4)
                for index, label in enumerate(labels)
            }
            return scores
        except Exception as exc:
            LOGGER.warning("Semantic embedding scoring failed, using keyword fallback: %s", exc)
            return None

    def _load_model(self):
        if self._model_load_attempted:
            return self._model
        self._model_load_attempted = True
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name)
            LOGGER.info("Loaded local sentence-transformer model: %s", self.model_name)
        except Exception as exc:
            LOGGER.warning("Could not load sentence-transformer model, using keyword fallback: %s", exc)
            self._model = None
        return self._model

    def _keyword_scores(self, context: str) -> dict[str, float]:
        words = set(re.findall(r"[a-z0-9]+", context.lower()))
        scores: dict[str, float] = {}
        for label, intent_text in SECURITY_INTENTS.items():
            intent_words = set(re.findall(r"[a-z0-9]+", intent_text.lower()))
            keyword_hits = words.intersection(KEYWORD_HINTS[label])
            overlap = _jaccard(words, intent_words)
            score = min(0.95, overlap + (0.18 * len(keyword_hits)))
            scores[label] = round(score, 4)
        return scores

    def _classify_relevance(self, scores: dict[str, float], semantic_category: str) -> str:
        high_score = max(scores[label] for label in HIGH_INTENTS)
        informational_score = max(scores[label] for label in INFORMATIONAL_INTENTS)

        if high_score >= self.high_threshold:
            return "HIGH"
        if informational_score >= self.review_threshold and high_score < self.review_threshold:
            return "INFORMATIONAL"
        if high_score >= self.review_threshold:
            return "REVIEW"
        if semantic_category in INFORMATIONAL_INTENTS:
            return "INFORMATIONAL"
        return "REVIEW"


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left.intersection(right)) / len(left.union(right))


def _cosine_similarity(left: Iterable[float], right: Iterable[float]) -> float:
    left_values = list(float(value) for value in left)
    right_values = list(float(value) for value in right)
    numerator = sum(a * b for a, b in zip(left_values, right_values))
    left_norm = math.sqrt(sum(value * value for value in left_values))
    right_norm = math.sqrt(sum(value * value for value in right_values))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return numerator / (left_norm * right_norm)
