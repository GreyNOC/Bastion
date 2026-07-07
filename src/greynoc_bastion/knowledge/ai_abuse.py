"""AI-abuse taxonomy — curated, offline classifier for AI/LLM threat categories.

Maps free text (advisories, CVE descriptions, campaign notes) to a defensive
taxonomy of AI-abuse categories aligned with OWASP LLM Top 10 and OWASP Agentic
threats. Detection/prioritization aid only — no attack content.
"""

from __future__ import annotations

import re
from typing import cast

# category id -> (label, owasp_ref, keyword patterns)
AI_ABUSE_CATEGORIES: dict[str, dict[str, object]] = {
    "prompt_injection": {
        "label": "Prompt injection",
        "owasp": "LLM01",
        "patterns": [r"prompt injection", r"jailbreak", r"ignore (?:previous|prior) instructions",
                     r"system prompt (?:leak|override)", r"indirect prompt injection"],
    },
    "insecure_output": {
        "label": "Insecure output handling",
        "owasp": "LLM02",
        "patterns": [r"insecure output", r"unsanitized (?:llm|model) output", r"output handling"],
    },
    "training_data_poisoning": {
        "label": "Training data poisoning",
        "owasp": "LLM03",
        "patterns": [r"data poisoning", r"training data (?:poison|manipulat)", r"backdoor(?:ed)? model"],
    },
    "model_dos": {
        "label": "Model denial of service",
        "owasp": "LLM04",
        "patterns": [r"model denial of service", r"token flood", r"context window exhaustion"],
    },
    "supply_chain": {
        "label": "AI supply chain",
        "owasp": "LLM05",
        "patterns": [r"model supply chain", r"malicious model", r"poisoned (?:weights|checkpoint)",
                     r"compromised (?:hugging ?face|model hub)"],
    },
    "sensitive_disclosure": {
        "label": "Sensitive information disclosure",
        "owasp": "LLM06",
        "patterns": [r"training data extraction", r"membership inference", r"model inversion",
                     r"pii (?:leak|disclosure) (?:from|via) (?:model|llm)"],
    },
    "insecure_plugin": {
        "label": "Insecure plugin / tool design",
        "owasp": "LLM07",
        "patterns": [r"insecure plugin", r"tool (?:abuse|injection)", r"mcp (?:server )?(?:abuse|vulnerab)"],
    },
    "excessive_agency": {
        "label": "Excessive agency / agent abuse",
        "owasp": "LLM08",
        "patterns": [r"excessive agency", r"agent(?:ic)? abuse", r"autonomous agent (?:hijack|abuse)",
                     r"unauthorized (?:tool|action) execution by (?:agent|llm)"],
    },
    "model_theft": {
        "label": "Model theft / extraction",
        "owasp": "LLM10",
        "patterns": [r"model (?:theft|extraction|stealing)", r"model exfiltration"],
    },
    "adversarial_examples": {
        "label": "Adversarial examples / evasion",
        "owasp": "ML01",
        "patterns": [r"adversarial (?:example|input|perturbation)", r"evasion attack", r"model evasion"],
    },
    "deepfake": {
        "label": "Synthetic media / deepfake",
        "owasp": "GEN",
        "patterns": [r"deepfake", r"synthetic (?:media|voice|identity)", r"voice cloning"],
    },
    "llm_malware": {
        "label": "LLM-assisted malware / phishing",
        "owasp": "GEN",
        "patterns": [r"llm[- ](?:generated|assisted) (?:malware|phishing)",
                     r"ai[- ]generated (?:malware|phishing|lure)"],
    },
}

_COMPILED = {
    cid: [re.compile(p, re.IGNORECASE) for p in cast("list[str]", cat["patterns"])]
    for cid, cat in AI_ABUSE_CATEGORIES.items()
}


def classify_ai_abuse(text: str, *, max_categories: int = 6) -> list[dict[str, str]]:
    """Return matched AI-abuse categories for ``text`` (empty if none/not AI)."""
    if not text:
        return []
    out: list[dict[str, str]] = []
    for cid, patterns in _COMPILED.items():
        if any(p.search(text) for p in patterns):
            cat = AI_ABUSE_CATEGORIES[cid]
            out.append({"id": cid, "label": str(cat["label"]), "owasp": str(cat["owasp"])})
        if len(out) >= max_categories:
            break
    return out


def is_ai_related(text: str) -> bool:
    """Coarse gate: does the text reference AI/LLM/model systems at all?"""
    if not text:
        return False
    return bool(re.search(
        r"\b(?:llm|large language model|genai|generative ai|\bai\b|model|agent|mcp|"
        r"prompt|neural|inference|hugging ?face|openai|anthropic)\b",
        text, re.IGNORECASE,
    ))
