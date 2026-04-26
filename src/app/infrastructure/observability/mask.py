"""Redaction for Langfuse trace payloads.

Customer source code passes through every Langfuse span. Without
redaction, an unauthorized Langfuse UI viewer reads everything — and
SCCAP's `visible_user_ids` scope does not apply on the Langfuse side
(see threat model G1, threats #2/#3).

Three redaction passes, applied in order:

1. **Provider-style key patterns.** AWS access keys, OpenAI / Anthropic /
   GitHub token formats, and similar high-confidence regexes. Mirrors the
   broad-strokes detection that Gitleaks runs pre-LLM; we re-apply here
   because Gitleaks is non-fatal for non-Critical hits — the LLM still
   sees the raw chunk for those, and so would Langfuse.
2. **Keyword=value lines.** Any line where the value side of an
   `(api[_-]?key|secret|token|authorization|password|bearer)` assignment
   gets replaced with `***`. Preserves the keyword so the trace still
   reads as "secret detected" rather than vanishing the line entirely.
3. **High-entropy bare strings.** Long alphanumeric tokens (≥20 chars,
   Shannon entropy > 4.0) get replaced with `***`. Catches one-off
   credentials that don't match a known provider format.

The function operates on strings. Langfuse SDK invokes `mask` recursively
on the `input` / `output` fields of each span; we pass the function as
the SDK's `mask=` callable and let it walk the tree.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# 1) Provider key patterns. Conservative — only formats with very low
# false-positive rates. The `(?i)` is on each pattern for case
# insensitivity where applicable. We do NOT try to enumerate every
# possible secret format — that's Gitleaks's job; this is a defense in
# depth for what slips past pre-LLM scanning.
_PROVIDER_PATTERNS: tuple[re.Pattern[str], ...] = (
    # AWS access key id (AKIA…, ASIA…). 16 base32 chars.
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    # OpenAI keys (sk-… and sk-proj-…).
    re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b"),
    # Anthropic keys (sk-ant-…).
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    # GitHub fine-grained tokens (ghp_, ghs_, gho_, ghu_, ghr_).
    re.compile(r"\bgh[psoru]_[A-Za-z0-9]{20,}\b"),
    # Slack bot tokens.
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}\b"),
    # Google API keys (AIzaSy…).
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    # JWTs — eyJ… header. Three base64url segments, dots between.
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
)

# 2) Keyword=value pattern. Match the keyword and `=` or `:` separator
# (with optional surrounding quotes), capture only the value side and
# replace it. Keep the keyword so the trace reader can see "secret was
# here" rather than the whole line vanishing.
_KW_VALUE_RE = re.compile(
    r"""(?ix)
    (
        \b
        ( api[_-]?key
        | secret
        | token
        | authorization
        | password
        | bearer
        )
        \b
        \s*[:=]\s*
    )
    ( ['"]? [^\s'"]+ ['"]? )
    """
)

# 3) High-entropy bare strings. Long alphanumeric/+/=/-/_ runs that look
# like tokens. Anchored on word boundaries so we don't shred URLs or
# package names. ≥20 chars + Shannon entropy > 4.0 is the threshold
# Gitleaks itself uses for its generic high-entropy rule.
_BARE_TOKEN_RE = re.compile(r"\b([A-Za-z0-9+/=_-]{20,})\b")
_ENTROPY_THRESHOLD = 4.0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _redact_high_entropy(match: re.Match[str]) -> str:
    candidate = match.group(1)
    if _shannon_entropy(candidate) > _ENTROPY_THRESHOLD:
        return "***"
    return candidate


def mask(value: object) -> object:
    """Redact secrets and high-entropy strings.

    Accepts any value (Langfuse passes us mixed dicts/lists/scalars). For
    strings, runs all three passes; for dicts / lists, recurses; for
    other types, returns unchanged. Failure-tolerant — any unexpected
    error returns the original value rather than risking a crash on the
    instrumented call path.
    """
    try:
        if isinstance(value, str):
            return _mask_str(value)
        if isinstance(value, dict):
            return {k: mask(v) for k, v in value.items()}
        if isinstance(value, list):
            return [mask(v) for v in value]
        if isinstance(value, tuple):
            return tuple(mask(v) for v in value)
        return value
    except Exception:
        return value


def _mask_str(value: str) -> str:
    redacted = value
    for pattern in _PROVIDER_PATTERNS:
        redacted = pattern.sub("***", redacted)
    redacted = _KW_VALUE_RE.sub(lambda m: f"{m.group(1)}***", redacted)
    redacted = _BARE_TOKEN_RE.sub(_redact_high_entropy, redacted)
    return redacted
