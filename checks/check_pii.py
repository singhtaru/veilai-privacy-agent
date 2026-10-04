import time

start = time.perf_counter()
from privacy.pii_detector import detect, entity_types
print(f"Analyzer loaded in {time.perf_counter() - start:.1f}s\n")

# (text, expected types, kind) - "pattern" cases must pass; "ner" depends on the spaCy model
CASES = [
    ("My phone number is 9876543210",                  ["IN_PHONE"],       "pattern"),
    ("Call me on +91 98765 43210 tomorrow",            ["IN_PHONE"],       "pattern"),
    ("Aadhaar: 2345 6789 0123",                        ["AADHAAR"],        "pattern"),
    ("my aadhar is 234567890123",                      ["AADHAAR"],        "pattern"),
    ("PAN card ABCPS1234K",                            ["PAN"],            "pattern"),
    ("my reg no is 22bce1001",                         ["VIT_REG_NO"],     "pattern"),
    ("What is the CGPA of 22BCE1003?",                 ["VIT_REG_NO"],     "pattern"),
    ("Email rahul.sharma@vitstudent.ac.in",            ["EMAIL_ADDRESS"],  "pattern"),
    ("Reg 22BCE1001, phone 9876543210, Aadhaar 2345 6789 0123, "
     "PAN ABCPS1234K, mail rahul@gmail.com",
     ["AADHAAR", "EMAIL_ADDRESS", "IN_PHONE", "PAN", "VIT_REG_NO"],          "pattern"),
    ("Rahul Sharma lives in Chennai",                  ["LOCATION", "PERSON"], "ner"),
    ("For exam queries, contact the coordinator Dr. Meena Iyer "
     "at examcell.coord@vit.ac.in.",                   ["EMAIL_ADDRESS", "PERSON"], "ner"),
    # No PII: these should come back empty
    ("Any upcoming notices?",                          [],                 "pattern"),
    ("The exam is on 17 November and lasts 3 hours",   [],                 "pattern"),
    ("Room 12345, order 1234567890",                   [],                 "pattern"),
]

passed = {"pattern": 0, "ner": 0}
total = {"pattern": 0, "ner": 0}

for text, expected, kind in CASES:
    detections = detect(text)
    found = entity_types(detections)
    ok = found == sorted(expected)
    total[kind] += 1
    passed[kind] += ok

    print(f"{'PASS' if ok else 'FAIL'} [{kind}] {text}")
    print(f"     expected: {sorted(expected)}")
    print(f"     found:    {found}")
    # Printing values is fine here only because all test data is fake
    for d in detections:
        print(f"       - {d.entity_type:<14} '{text[d.start:d.end]}'  score={d.score:.2f}")
    print()

print(f"Pattern cases: {passed['pattern']}/{total['pattern']} passed (should be all)")
print(f"NER cases:     {passed['ner']}/{total['ner']} passed (model-dependent)")

start = time.perf_counter()
detect("Contact 9876543210 or rahul@gmail.com")
print(f"\nSecond call took {time.perf_counter() - start:.3f}s (analyzer is reused)")
