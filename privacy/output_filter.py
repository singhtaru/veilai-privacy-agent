from dataclasses import dataclass, field
from privacy.pii_detector import detect
from privacy.pseudonymizer import PLACEHOLDER_RE

# Strict, pattern-based types only (see notes below on why names are excluded)
OUTPUT_ENTITIES = ["EMAIL_ADDRESS", "IN_PHONE", "AADHAAR", "PAN", "VIT_REG_NO"]

# Identifiers that no tool ever returns. Finding one means something is seriously wrong.
HIGH_RISK = {"AADHAAR", "PAN"}

BLOCKED_MESSAGE = ("This response was withheld because it appeared to contain "
                   "highly sensitive identifiers.")


@dataclass
class FilterResult:
    text: str
    leaks: list = field(default_factory=list)   # entity types found, e.g. ["IN_PHONE"]
    blocked: bool = False

    @property
    def modified(self):
        return bool(self.leaks)


def filter_output(text):
    if not text:
        return FilterResult(text or "")

    placeholder_spans = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]

    def overlaps_placeholder(d):
        return any(d.start < end and d.end > start for start, end in placeholder_spans)

    leaks = [d for d in detect(text, OUTPUT_ENTITIES) if not overlaps_placeholder(d)]
    if not leaks:
        return FilterResult(text)

    leak_types = sorted({d.entity_type for d in leaks})

    # Level 2: Aadhaar or PAN anywhere -> withhold the whole answer
    if HIGH_RISK & set(leak_types):
        return FilterResult(BLOCKED_MESSAGE, leak_types, blocked=True)

    # Level 1: other raw identifiers -> redact just those spans
    for d in sorted(leaks, key=lambda d: d.start, reverse=True):
        text = text[:d.start] + f"[REDACTED_{d.entity_type}]" + text[d.end:]
    return FilterResult(text, leak_types)
