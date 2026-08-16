# WORKSPACE SYSTEM RULES — AGENT WAZUH SOC ASSISTANT (REFINED SPEC)

All agents operating in this workspace MUST strictly obey the **AI Development Environment Vision**:

1. **Persistent Knowledge**: Store architectural decisions in `./.ai/architecture_decisions.md`, bugs in `./.ai/memory/bugs.md`, and progress in `./.ai/memory/progress.md`.
2. **2-Layer Hybrid Architecture**:
   - **Layer 1: Static Lookup (`./config/mitre_mapping.json`)**: Deterministic Rule ID ↔ MITRE Technique mapping.
   - **Layer 2: Local RAG / LLM (`Qwen2.5-3B-Instruct Q4_K_M`)**: RAM budget ~2.5GB max via Ollama (`http://localhost:11434`).
3. **Relative File Paths**: ALWAYS use clean relative paths (`./config/local_rules.xml`, `./incident_assistant.py`, `./web/index.html`) to protect privacy and ensure portability.
4. **5 Specialized Roles**:
   - `@claude` (Architect): 2-Layer Hybrid architecture & API contract specs.
   - `@rule-designer` (Detection Rule Engineer): `./config/local_rules.xml` & `./config/mitre_mapping.json`.
   - `@ui-designer` (UI/UX Designer): Wireframes, `./web/design-tokens.css`, visual aesthetic review.
   - `@codex` (Implementation Worker): Python backend + Frontend JS (Max 3 files, Max 300 lines limit per task).
   - `@reviewer` (Security & Anti-Hallucination Auditor): SSL, OWASP, WCAG, and Anti-Hallucination audit (CHỈ PHÁT HIỆN LỖI, KHÔNG SỬA CODE).
5. **Human Supervision & Staging**:
   - Never write code directly to disk without Sandbox staging and Git Diff review.
   - Priority hierarchy: **Correctness > Maintainability > Scalability > Security > Performance > Speed**.
