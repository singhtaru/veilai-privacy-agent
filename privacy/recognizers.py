from presidio_analyzer import Pattern, PatternRecognizer

# Aadhaar: 12 digits, first digit 2-9, optionally spaced 4-4-4
aadhaar = PatternRecognizer(
    supported_entity="AADHAAR",
    patterns=[Pattern("aadhaar", r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b", 0.75)],
    context=["aadhaar", "aadhar", "uid", "uidai"],
)

# PAN: 5 letters + 4 digits + 1 letter.
# The 4th letter is the holder type (P = individual, C = company, etc.)
pan = PatternRecognizer(
    supported_entity="PAN",
    patterns=[Pattern("pan", r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b", 0.85)],
    context=["pan", "permanent account", "income tax"],
)

# VIT registration number, e.g. 22BCE1001
vit_reg = PatternRecognizer(
    supported_entity="VIT_REG_NO",
    patterns=[Pattern("vit_reg", r"\b\d{2}[A-Z]{3}\d{4}\b", 0.85)],
    context=["reg", "registration", "register", "roll"],
)

# Indian mobile: 10 digits starting 6-9, optional +91, optional space/hyphen after 5 digits
in_phone = PatternRecognizer(
    supported_entity="IN_PHONE",
    patterns=[Pattern("in_phone", r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)", 0.7)],
    context=["phone", "mobile", "call", "contact", "number", "whatsapp"],
)

CUSTOM_RECOGNIZERS = [aadhaar, pan, vit_reg, in_phone]
