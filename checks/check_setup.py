import sys
import importlib

print(f"Python version: {sys.version.split()[0]}")
if sys.version_info < (3, 10):
    sys.exit("Python 3.10+ is required.")

print("\nChecking libraries...")
for pkg in ["streamlit", "groq", "presidio_analyzer", "spacy", "dotenv", "bcrypt", "pandas"]:
    try:
        importlib.import_module(pkg)
        print(f"  OK  {pkg}")
    except ImportError:
        print(f"  MISSING  {pkg}")

print("\nChecking Presidio + spaCy model...")
from presidio_analyzer import AnalyzerEngine
analyzer = AnalyzerEngine()
results = analyzer.analyze(text="Contact Rahul at rahul@gmail.com", language="en")
print("  Detected:", sorted({r.entity_type for r in results}))

print("\nChecking config...")
import config
print(f"  API key loaded: {bool(config.GROQ_API_KEY)}")
print(f"  Database path: {config.DB_PATH}")

print("\nChecking Groq API...")
from groq import Groq
client = Groq(api_key=config.GROQ_API_KEY)
try:
    response = client.chat.completions.create(
        model=config.MODEL_NAME,
        messages=[{"role": "user", "content": "Reply with only the word OK."}],
    )
    print(f"  Groq replied: {response.choices[0].message.content.strip()}")
except Exception as e:
    print(f"  Groq call failed: {e}")
    print("  Available Groq models:")
    for m in client.models.list().data:
        print("   ", m.id)

print("\nSetup check complete.")
