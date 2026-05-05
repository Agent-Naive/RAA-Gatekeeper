# ⚓ PERMANENT ANCHORS (DO NOT ALTER)
- **API Endpoint:** '.post("https://api.x.ai/v1/chat/completions")' - (Hard-locked in `lib.rs`).
- **Path Protocol:** Always use `fs::canonicalize` for file paths to ensure absolute path matching in ledgers.
- **Ledger Pathing:** Automated Routing to `~/dev/RAA-Gatekeeper/raa-*` dedicated test folders.
- **UI Logic:** Mutually exclusive toggles for Ledger vs. Snapshot modes (Radio-style checkboxes).
- **UX Logic:** All interactive inputs must have explicit `type="text"` and `onsubmit` form wrappers for Enter-key support.

# 🛡️ RAA Gatekeeper Roadmap

## 📂 Phase 1: Core Engine & UX Transparency (v0.2.x) - ACTIVE 🚧
- [x] Audit Command Line logic (Enter key support).
- [x] Deep File Certification (Mathematical Hash + AI Verdict).
- [x] ZIP/Archive Peeking (Scan without extraction).
- [x] Automated Ledger Routing (Test folder isolation).
- [x] High-Context Security Report Cards.
- [ ] **Dual-Pane Live Monitor:** Split-view during scans (Analyze/Certify/ZIP):
    - **Left Pane:** Current active file audit/status (Real-time AI/Hash progress).
    - **Right Pane:** Real-time list of skipped/ignored files (Transparency for excludes).
- [x] **Terminal Cleanup:** Suppress Svelte `a11y` warnings and Rust `unused` warnings via code tags.
- [ ] **Type-Safe Inputs:** Ensure every input has explicit `type="text"` attribute.

## ⚡ Phase 2: Performance & Scaling (v0.3.0)
- [ ] **Batch Processing:** Group 10-20 small files into a single AI prompt to save 80% on token costs.
- [ ] **Parallel Hashing:** Use Rust threads to hash multiple files simultaneously.
- [ ] **Global Exclude List:** UI settings to permanently ignore folders like `node_modules`, `.git`, `dist`, and `target`.
- [ ] **Token Counter:** Display estimated cost/token usage for each scan in the UI.

## 🔍 Phase 3: Forensic UI & History (v0.4.0)
- [ ] **Ledger Viewer:** A tab to read and search through existing `.raa` files without leaving the app.
- [ ] **Violation Archive:** A "Wall of Shame" listing every threat found across all folders.
- [ ] **Export Reports:** Generate a clean PDF or Markdown security summary for a project.
- [ ] **Diff-Checker:** If a file hash mismatches, show a visual "Diff" of what exactly changed in the code.

## 🔐 Phase 4: Local Intelligence & Privacy (v0.5.0)
- [ ] **Ollama/Local LLM Integration:** Toggle to use local models for zero-cost, offline auditing.
- [ ] **Cryptographic Signing:** Sign the `.raa` manifest with a private key so only "Authorized Auditors" can certify.
- [ ] **Quarantine Mode:** Automatically move "Violation" files to a hidden `.raa-quarantine` folder.

## 🛠️ Phase 5: Auto-Fix & Remediation (v1.0.0-BETA)
- [ ] **Security Patching:** "Fix" button for common issues (e.g., auto-generating a safe CSP for Tauri).
- [ ] **Environment Hardening:** Auto-encrypt `.env` files.
- [ ] **Dependency Auditor:** Check `package.json` for known vulnerable libraries.

## 💡 Future Ideas / Brainstorming
- [ ] Menu bar icon for "Silent Monitoring" of terminal commands.
- [ ] Browser extension to audit code snippets on StackOverflow/GitHub before copying.
- [ ] Multi-user auditing roles (Auditor vs Developer).
