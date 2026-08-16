# ARCHITECTURE DECISIONS DOCUMENT — AGENT WAZUH SOC ASSISTANT

## Decision Log

### AD-01: 2-Layer Hybrid Architecture (Static Lookup + Local LLM RAG)
- **Status**: Accepted
- **Context**: Terminology precision is essential for academic thesis defense.
- **Decision**:
  - **Layer 1: Static Rule-Based Lookup (`./config/mitre_mapping.json`)**: 100% deterministic ground-truth mapping for known Wazuh Rule IDs ↔ MITRE Technique IDs.
  - **Layer 2: Local LLM RAG Reasoning (Qwen2.5-3B-Instruct Q4_K_M)**: Handles natural language queries, incident summarization, evidence synthesis, and fallback reasoning for unmapped events.

### AD-02: Local Model Memory Budget (~2.5GB RAM Limit)
- **Status**: Accepted
- **Context**: System free RAM is ~3.7GB. Large 7-8B models risk Out-Of-Memory (OOM) crashes.
- **Decision**: Restrict local LLM model to **`Qwen2.5-3B-Instruct`** (or `Llama3.2-3B`) via Ollama (`http://localhost:11434`), Quantization `Q4_K_M`, capping RAM usage to ~2.5GB max.

### AD-03: Relative Paths & Privacy Preservation
- **Status**: Accepted
- **Context**: Absolute paths expose personal username (`kweismann`) and break when shared on other machines.
- **Decision**: Use clean relative paths (`./config/local_rules.xml`, `./incident_assistant.py`, `./web/index.html`) across all code and documentation.

### AD-04: Anti-Hallucination Reviewer Criterion
- **Status**: Accepted
- **Context**: False positive AI statements in SOC investigation can mislead security analysts.
- **Decision**: Enforce Anti-Hallucination check: When evidence is insufficient in Wazuh logs, AI MUST return `"Không đủ dữ liệu để kết luận"` rather than making up answers.
