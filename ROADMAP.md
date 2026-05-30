# 🛡️ RAA Gatekeeper Roadmap

**Current Status:** Active Development — Phase 3 + 4 Core Complete  
**Last Major Update:** Vault propagation fixed + in-app roadmap viewer removed

---

## ⚓ PERMANENT ANCHORS (DO NOT ALTER)

- **API Endpoint:** Uses dynamic Base URL (user-configurable). No hard-coded `x.ai`.
- **Path Protocol:** Always use `fs::canonicalize` for absolute path matching in ledgers.
- **Ledger Pathing:** Respects user-selected `vaultRootPath` (falls back to `~/Documents/RAA_Vault`).
- **Read-Only Mandate:** The Gatekeeper never modifies user files.
- **Advisory Only:** All verdicts are diagnostic. Human remains the decision maker.

---

## ✅ Phase 1 + 2: Core Engine & Performance — COMPLETE

- [x] Terminal command auditing with Bible instant-recall (SHA-256 cache)
- [x] Deep file integrity scanning (hash + LLM)
- [x] Archive deep-peeking (ZIP contents audited without full extraction, 2MB safety valve)
- [x] Parallel hashing with Rayon across all CPU cores
- [x] Smart bin-packing / batching to reduce API calls
- [x] macOS junk filter (`__MACOSX`, `._` files)
- [x] Binary safety (string-read bypass)
- [x] Real-time dual-pane collection UI (Active vs Skipped)
- [x] High-visibility mission success toasts
- [x] "Bring Your Own LLM" (fully dynamic Base URL + Model Name)
- [x] Persistent settings via LocalStorage
- [x] Performance telemetry (LOCAL handoff ms + ORACLE total time)

---

## ✅ Phase 3 + 4: Forensic UI & Silent Monitoring — CORE COMPLETE

- [x] **Silent Watcher** — Kernel-level file monitoring with DNA change alerts
- [x] **DNA Toast + Forensic Queue** — "Teleport to Analyze" from watcher events
- [x] **Configurable Watcher** — Up to 5 folders, depth control (1-5), persisted
- [x] **Ledger Tab** — Basic access to historical `.raa` files
- [x] **Integrity Guard** — 7/7 self-check dashboard (parallel hashing, disk-first, etc.)
- [x] **User-Selectable Vault** — Full `vaultRootPath` propagation to all audit types
- [x] **Real-time Timers** — Handoff + total oracle timing on every operation
- [x] **Disk-First Verification** — Reports pulled from SSD, not just memory

### Currently In Progress / Next

- [ ] **Rich Ledger Browser** — Proper file list, searchable, parsed incident cards, per-file DNA verification
- [ ] **DNA Verification UI** — "Does current hash match last ledger entry?" indicator
- [ ] **Export Reports** — Clean Markdown export of any audit or full manifest
- [ ] **Violation History Dashboard** ("Wall of Shame")
- [ ] **Token Economy Counter** — Live batch density + estimated savings

---

## 🔐 Phase 4+ (Future)

- [ ] Local LLM support (Ollama / LocalAI toggle)
- [ ] Quarantine mode for high-confidence violations
- [ ] Cryptographic signing of manifests

---

## 🛠️ Phase 5 (v1.0 Vision)

- [ ] AI-suggested auto-remediation for common issues
- [ ] Dependency CVE scanning
- [ ] Environment hardening helpers

---

## 📝 Known Polish Items

- Settings layout: Model selector as dropdown + wider Base URL field
- Remove duplicated vault-fallback blocks in UI
- Make Integrity Guard reflect real vault path state instead of hardcoded true

---

*"Trust, then Certify."*