# 🛡️ RAA Gatekeeper Roadmap (v0.3.0)

# ⚓ PERMANENT ANCHORS (DO NOT ALTER)
- **API Endpoint:** `.post("https://x.ai")` - (Hard-locked in `lib.rs`).
- **Path Protocol:** Always use `fs::canonicalize` for absolute path matching in ledgers.
- **Ledger Pathing:** Automated Routing to `~/dev/RAA-Gatekeeper/raa-*` test folders.
- **UI Logic:** Mutually exclusive toggles for Ledger vs. Snapshot modes (Radio-style).
- **UX Logic:** All interactive inputs must have explicit `type="text"` and `onsubmit` wrappers.

---

## 📂 Phase 1: Core Engine & UX Transparency - COMPLETE ✅
- [x] **Audit Command Line:** Captured terminal safety fingerprints with Enter-key support.
- [x] **Deep File Certification:** Integrated mathematical hashing with Grok-powered logic.
- [x] **ZIP/Archive Peeking:** Enabled deep-scan capabilities without extraction.
- [x] **High-Context Report Cards:** Implemented Emerald/Crimson glow-coding for triage.
- [x] **Wide Theatre UI:** Re-architected navigation to horizontal tabs for visibility.
- [x] **"Bring Your Own LLM":** Decoupled backend for dynamic URLs and Model Names.
- [x] **Arm Protocol:** Added activation handshake and persistent onboarding screen.
- [x] **Persistence:** Established LocalStorage sync so settings survive app restarts.
- [x] **Terminal Cleanup:** Suppress Svelte `a11y` and Rust `unused` warnings.

## ⚡ Phase 2: Performance & Scaling - COMPLETE ✅
- [x] **Parallel Collection:** Real-time dual-pane population (Skipped vs. Active).
- [x] **Parallel Hashing:** (Rayon Integration) Fingerprinting across all CPU cores.
- [x] **Bin-Packing/Batching:** Smart character-count buckets to slash API latency and costs.
- [x] **macOS Junk Filter:** Surgical exclusion of `__MACOSX` and `._` metadata files.
- [x] **Binary Safety:** Implemented string-read bypass to prevent binary file crashes.
- [x] **Catch-47 ZIP DNA:** Restored hashing for files nested inside archives.
- [x] **Mission Success Feedback:** High-visibility toast notifications for scan completion.
- [x] **Alphabetized Audit Logic:** UI toggle chips for 14+ AI-stack file extensions.

## 🔍 Phase 3: Forensic UI & Ledger Viewer - ACTIVE 🚧
- [ ] **In-App Ledger Browser:** A dedicated tab to view and search `.raa` files directly.
- [ ] **DNA Verification:** UI indicator to verify if current hashes match the last ledger entry.
- [ ] **Violation "Wall of Shame":** Persistent dashboard of all historical threats found.
- [ ] **Token Economy:** Live footer counter for batch density and estimated token savings.
- [ ] **Export Reports:** Generate clean Markdown/PDF security summaries for project handoffs.
- [ ] **Diff-Checker:** Visual code comparison tool for mismatched file hashes.

## 🔐 Phase 4: Local Intelligence & Privacy
- [ ] **Local LLM Integration:** One-click toggle for Ollama/LocalAI offline auditing.
- [ ] **Quarantine Mode:** Auto-isolation of infected files to hidden `.raa-quarantine` folders.
- [ ] **Private Key Signing:** Cryptographically sign manifests to prove "Authorized Auditor" status.

## 🛠️ Phase 5: Auto-Fix & Remediation (v1.0.0-BETA)
- [ ] **Security Patching:** AI-suggested "one-click fixes" for detected vulnerabilities (e.g., Tauri CSP).
- [ ] **Environment Hardening:** Automated encryption for sensitive `.env` files.
- [ ] **Dependency Auditor:** Deep-scan `package.json` against known CVE security databases.

---

## 📝 TODO / FUTURE UI REFACTOR
- [ ] **Settings Layout Shift:** Move **Model Name** to a dropdown on the left.
- [ ] **Base URL Expansion:** Move **Base URL** input to the right of the model dropdown and increase width by 50% to prevent character cutoff (e.g., `.../completions`).

## 💡 Future Ideas / Brainstorming
- [ ] Menu bar icon for "Silent Monitoring" of terminal commands.
- [ ] Browser extension to audit code snippets on StackOverflow before copying.
