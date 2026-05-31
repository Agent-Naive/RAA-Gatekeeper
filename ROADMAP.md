# 🛡️ RAA Gatekeeper Roadmap

**Current Status:** Active Development — Phase 3 + 4 Core Complete + New Granular Architecture Path Initiated  
**Last Major Update:** New Path Forward architecture defined (ONE FILE = ONE REPORT + Job Folders + ~RAA-CONTROL-Manifest as first stage)

---

## ⚓ PERMANENT ANCHORS (DO NOT ALTER)

- **API Endpoint:** Uses dynamic Base URL (user-configurable). No hard-coded `x.ai`.
- **Path Protocol:** Always use `fs::canonicalize` for absolute path matching in ledgers.
- **Ledger Pathing:** Respects user-selected `vaultRootPath` (falls back to `~/Documents/RAA-Vault`).
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

## 🚨 Critical Bugs / High Priority Fixes

*(No open critical bugs at this time. Historical issues from the monolithic report era have been addressed.)*

---

## 📝 Known Polish Items

- Settings layout: Model selector as dropdown + wider Base URL field
- Remove duplicated vault-fallback blocks in UI
- Make Integrity Guard reflect real vault path state instead of hardcoded true
- Layout deep clean (global CSS consolidation, reduce inline styles, improve long-term maintainability and contributor friendliness)

---

## 🚀 New Path Forward: Granular Per-File Forensic Ledgers + Job Folders (Initiated 2025)

**Core Philosophy**  
"Trust, then Certify." — taken to its logical conclusion: every individual file audited deserves its own first-class, self-contained forensic artifact.

**Major Architectural Shift**
- Move from "one large .raa file per job" (with many internal blocks) to **ONE FILE = ONE REPORT**.
- Every file that receives AI analysis (whether from a Certify folder run or from inside an Archive) produces its own dedicated `.raa` ledger containing:
  - Full oracle analysis paragraph
  - Clear verdict
  - Its own DNA (SHA-256) hash
- All artifacts from a single user-initiated job are grouped inside a **dated Job Folder** inside the RAA-Vault.
- A master **~RAA-CONTROL-Manifest** (inventory control sheet) is created as the very first artifact on job start.

**Key Benefits Targeted**
- Much stronger long-term DNA ownership per file
- Dramatically easier post-facto analysis, after-action reporting, and singular culprit identification (filesystem + job folder becomes the index)
- Clearer forensic packages that Joe can understand and share
- Better real-time comfort UX during long jobs
- Natural hierarchy preservation for duplicate filename safety

**Important Commitments**
- Archive scanning ability is preserved (in-memory analysis of ZIP contents still works and will emit per-file .raa reports inside job folders).
- The existing skipped-files logic and bottom-bar temporary holding pattern are preserved for future stages.
- The right pane is initially repurposed strictly as a live "what I just did" comfort feed (showing .raa files as they are created in real time). It is not yet interactive/clickable.

**Enduring Principle (from the ALLSAFE era)**
> A Certify job must never be allowed to appear successful if any audited file contains a violation. This principle must be enforced in the new per-file + job folder model.

---

### Staged Implementation Plan (New Path)

#### Stage 1: ~RAA-CONTROL-Manifest (First Stage — Current Focus)
- On "Start Certification" or "Select ZIP Archive" click:
  - Immediately create the dated job folder in the vault.
  - As the very first action, generate and write a `~RAA-CONTROL-Manifest.txt` (or similarly `~`-prefixed file) inside it.
  - The manifest must capture the complete inventory + full hierarchy of every file that will be considered for audit (respecting allowed extensions and junk filters).
  - This file becomes the permanent "audit control sheet" / scope declaration for that job.
  - Use the `~` prefix convention so the control manifest always sorts to the very top of the job folder when viewed in Finder / file explorers.
- This stage establishes the job folder as the atomic unit and gives every later artifact a stable home.

#### Stage 2: Real-Time Right Pane — "What I Just Did" Comfort Feed
- Repurpose the current right pane (previously "Coming Soon" placeholder) to display .raa files in real time as they are created and written during a job.
- The pane acts as a live emission log for user comfort during long-running Certify or Archive operations.
- Left pane continues to show files currently being processed ("📡 Audited").
- Bottom bar continues to show the comma-separated skipped list (preserving all existing skipped logic).

#### Stage 3: Per-File .raa Writing Inside Job Folders (with Hierarchy Mirroring)
- Modify Certify (`generate_manifest`) and Archive (`scan_compressed_archive`) flows to emit individual `.raa` files instead of one aggregated job ledger.
- Write each per-file report directly into the job folder created in Stage 1.
- When possible, mirror the original source folder hierarchy inside the job folder (provides natural duplicate-name protection and familiar structure for after-action review).
- Update `log_to_raa` (or introduce a job-aware writer) to support directory creation and relative path mirroring.
- Each small `.raa` contains the full rich analysis block + DNA hash for exactly one file.

#### Stage 4: Archive Path Adaptation to New Model
- Ensure the in-memory ZIP scanning path still functions.
- Each qualifying file discovered inside an archive produces its own `.raa` inside the job folder (named after the ZIP + timestamp).
- Internal ZIP hierarchy can be mirrored inside the job folder when beneficial.
- Retain necessary special handling for DNA verification of container-origin files (📦 states, etc.) while the rest of the system moves to per-file granularity.

#### Stage 5: Ledger Browser Evolution for Job Folders
- Update `list_ledger_files` and the Svelte ledger UI to understand and present job folders as first-class containers.
- Users can browse by job, then drill into individual per-file reports.
- The `~RAA-CONTROL-Manifest` should be prominently surfaced when a job folder is selected.

**Status:** Explicitly tabled for now. The ledger browser remains flat (vault root only) until the `~RAA-CONTROL-Manifest.log` visual design and report writing inside job folders are stable and satisfactory to the user. See the detailed TODO in `src-tauri/src/lib.rs` (list_ledger_files) and RAA-NEWPATH-FORWARD.txt.

#### Stage 6+: Future Evolutions (Parked for Later)
- Right pane becomes optionally clickable / shows live ledger content ("YET").
- Move skipped-files display + reasons (failed, extension filter, junk, etc.) into the right pane dynamically.
- New dedicated "Reports" section capable of generating human-readable summaries (Markdown, and eventually PDF) across an entire job folder using the control manifest + individual .raa files as source material.
- Any additional polish around vault visualization, job-level metadata, export, etc.

---

*"Trust, then Certify."*