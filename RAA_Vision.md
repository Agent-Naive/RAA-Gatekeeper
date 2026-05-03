# Project: Trust File Checker (RAA-Certified)
**Status:** Development Phase 1 (The Gatekeeper)
**Stack:** Tauri v2 | Rust | Void Editor | xAI Grok / Google Gemini

## 1. The Core Philosophy (RAA)
Restrictive Access Ability (RAA) is a **Read-Only** security layer. It acts as a digital firewall between local source code and AI Agents.
- **NEVER EDIT:** The app must never modify, strip, or sanitize user files.
- **ANALYZE & ADVISE:** The app reports threat levels and advises the human NOT to use specific files in AI context.

## 2. Key Modules
### A. The Gatekeeper (Rust)
- Detects non-ASCII/Binary patterns in text-intended files.
- Flags "Agent Hijacking" instructions (hidden prompts that could redirect AI behavior).
### B. RAA Shell-Check
- Audits terminal commands before execution.
- Flags destructive wildcards (e.g., rm -rf .*) and unauthorized Privilege Escalation (sudo/chmod).

## 3. Immediate Goal
Build the Tauri v2 bridge to the Rust backend to handle high-speed initial file scans.
