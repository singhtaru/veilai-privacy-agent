# VeilAI: A Privacy-by-Design Architecture for Autonomous AI Agents

A university assistant built on an LLM agent, where authentication, role-based access control,
data minimization, PII masking, output filtering, and audit logging are built into the pipeline.

## Setup
Run these inside WSL (Ubuntu). On Windows with Smart App Control on, spaCy's compiled files are blocked natively.

1. `python3 -m venv ~/venvs/veilai` and `source ~/venvs/veilai/bin/activate`
2. `pip install -r requirements.txt`
3. `python -m spacy download en_core_web_lg`
4. Copy `.env.example` to `.env` and add your Groq API key
5. `python check_setup.py`
