import logging
from presidio_analyzer import AnalyzerEngine
from privacy.recognizers import CUSTOM_RECOGNIZERS

# Hide Presidio's warnings about languages we don't use
logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

ALL_ENTITIES = [
    "PERSON", "LOCATION", "EMAIL_ADDRESS",
    "IN_PHONE", "AADHAAR", "PAN", "VIT_REG_NO",
]

# Regex-based types are more precise than NER, so they win when spans overlap
PATTERN_ENTITIES = {"EMAIL_ADDRESS", "IN_PHONE", "AADHAAR", "PAN", "VIT_REG_NO"}

SCORE_THRESHOLD = 0.5

# Created once when the module is first imported (loading spaCy takes a few seconds)
_analyzer = AnalyzerEngine()
for recognizer in CUSTOM_RECOGNIZERS:
    _analyzer.registry.add_recognizer(recognizer)


def _resolve_overlaps(results):
    """When two detections overlap, keep the more trustworthy one."""
    ranked = sorted(
        results,
        key=lambda r: (r.entity_type in PATTERN_ENTITIES, r.score, r.end - r.start),
        reverse=True,
    )
    chosen = []
    for r in ranked:
        if all(r.end <= c.start or r.start >= c.end for c in chosen):
            chosen.append(r)
    return sorted(chosen, key=lambda r: r.start)


def detect(text, entities=ALL_ENTITIES):
    """Return non-overlapping PII detections, sorted by position."""
    if not text or not text.strip():
        return []
    results = _analyzer.analyze(
        text=text,
        language="en",
        entities=entities,
        score_threshold=SCORE_THRESHOLD,
    )
    return _resolve_overlaps(results)


def entity_types(detections):
    """Just the types found, e.g. ['EMAIL_ADDRESS', 'IN_PHONE']. Safe for logs."""
    return sorted({d.entity_type for d in detections})
