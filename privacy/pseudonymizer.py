import re
from privacy.pii_detector import detect

PLACEHOLDER_RE = re.compile(r"\[[A-Z_]+_\d+\]")

# For structured database rows, the column name tells us the entity type directly
FIELD_ENTITY = {
    "name": "PERSON",
    "reg_no": "VIT_REG_NO",
    "email": "EMAIL_ADDRESS",
    "phone": "IN_PHONE",
    "address": "LOCATION",
    "aadhaar": "AADHAAR",
    "pan": "PAN",
}


def _normalize(value, entity):
    """Make different spellings of the same value share one placeholder."""
    v = value.strip()
    if entity == "IN_PHONE":
        return re.sub(r"\D", "", v)[-10:]       # drop +91, spaces, hyphens
    if entity == "AADHAAR":
        return re.sub(r"\D", "", v)             # drop spaces
    if entity in ("VIT_REG_NO", "PAN"):
        return v.upper()
    return " ".join(v.lower().split())          # names, emails, places


class Pseudonymizer:
    def __init__(self):
        self._key_to_placeholder = {}   # (entity, normalized value) -> placeholder
        self._placeholder_to_real = {}  # placeholder -> original value (first form seen)
        self._counters = {}             # entity type -> how many placeholders created

    def placeholder_for(self, value, entity):
        key = (entity, _normalize(value, entity))
        if key in self._key_to_placeholder:
            return self._key_to_placeholder[key]

        n = self._counters.get(entity, 0) + 1
        self._counters[entity] = n
        placeholder = f"[{entity}_{n}]"

        self._key_to_placeholder[key] = placeholder
        self._placeholder_to_real[placeholder] = value
        return placeholder

    def mask_text(self, text, detections):
        """Replace detected spans with placeholders. Placeholders are numbered
        left to right (reading order), then substituted from the end of the
        text backwards so earlier positions stay valid."""
        ordered = sorted(detections, key=lambda d: d.start)
        placeholders = [self.placeholder_for(text[d.start:d.end], d.entity_type) for d in ordered]
        for d, placeholder in reversed(list(zip(ordered, placeholders))):
            text = text[:d.start] + placeholder + text[d.end:]
        return text

    def mask(self, text):
        """Detect and mask in one step."""
        return self.mask_text(text, detect(text))

    def mask_record(self, record):
        """Mask a database row. Known columns are masked by name; other text
        fields are scanned with the detector; numbers are left as they are."""
        masked = {}
        for key, value in record.items():
            if key in FIELD_ENTITY and value:
                masked[key] = self.placeholder_for(str(value), FIELD_ENTITY[key])
            elif isinstance(value, str):
                masked[key] = self.mask(value)
            else:
                masked[key] = value
        return masked

    def restore(self, text):
        """Turn placeholders back into real values. Unknown placeholders stay as they are."""
        return PLACEHOLDER_RE.sub(
            lambda m: self._placeholder_to_real.get(m.group(0), m.group(0)), text
        )

    def masked_types(self):
        """Entity types that were masked in this request. Safe for audit logs."""
        return sorted(self._counters)

    def summary(self):
        """Count of placeholders per type, e.g. {'PERSON': 1, 'VIT_REG_NO': 2}. No values."""
        return dict(self._counters)
