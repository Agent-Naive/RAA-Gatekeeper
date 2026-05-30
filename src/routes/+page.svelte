<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, tick } from "svelte";

  let activeTab = $state("welcome");

  let startTime = $state(0);
  let handoffTime = $state(0); // This is your "Lap"
  let totalTime = $state(0);
  let handoffTimerId = $state<NodeJS.Timeout | number | null>(null);
  let totalTimerId = $state<NodeJS.Timeout | number | null>(null);

  function startTimers() {
    startTime = Date.now();
    handoffTime = 0;
    totalTime = 0;
    // Start real-time updates for handoff and total timers
    handoffTimerId = setInterval(() => {
      handoffTime = Date.now() - startTime;
    }, 1);
    totalTimerId = setInterval(() => {
      totalTime = Date.now() - startTime;
    }, 1);
  }

  function stopHandoffTimer() {
    if (handoffTimerId !== null) {
      clearInterval(handoffTimerId);
      handoffTimerId = null;
      handoffTime = Date.now() - startTime; // Finalize the value
    }
  }

  function stopTotalTimer() {
    if (totalTimerId !== null) {
      clearInterval(totalTimerId);
      totalTimerId = null;
      totalTime = Date.now() - startTime; // Finalize the value
    }
  }

  let watcherEnabled = $state(
    localStorage.getItem("raa_watcher_enabled") === "true",
  );
  let watcherFolders = $state<string[]>(
    JSON.parse(localStorage.getItem("raa_watcher_folders") || "[]"),
  );
  let watcherDepth = $state(
    parseInt(localStorage.getItem("raa_watcher_depth") || "3"),
  );
  let watcherHistory = $state<string[]>([]);
  let showHistoryList = $state(false);

  async function startAuditFromQueue(file: string) {
    activeTab = "analyze";

    commandInput = file;

    showHistoryList = false;

    watcherHistory = watcherHistory.filter((f) => f !== file);

    await tick();
    handleAudit();
  }

  $effect(() => {
    localStorage.setItem("raa_watcher_enabled", watcherEnabled.toString());
    localStorage.setItem("raa_watcher_folders", JSON.stringify(watcherFolders));
    localStorage.setItem("raa_watcher_depth", watcherDepth.toString());
    invoke("toggle_watcher", {
      enabled: watcherEnabled,
      folders: watcherFolders,
      depth: watcherDepth,
    })
      .then(() => console.log("🕵️ UI: Watcher Handshake SUCCESS"))
      .catch((e) => console.error("🚨 UI: Watcher Handshake FAILED", e));
  });

  let lastWatchedFile = $state("");
  let showWatcherAlert = $state(false);

  $effect(() => {
    let unlisten: any;
    async function startListening() {
      unlisten = await listen("watcher-event", (event: any) => {
        const file = event.payload;

        console.log("👂 UI HEARD SPARK:", file);
        lastWatchedFile = file;
        showWatcherAlert = true;

        if (!watcherHistory.includes(file)) {
          watcherHistory = [file, ...watcherHistory].slice(0, 10);
        }

        setTimeout(() => {
          showWatcherAlert = false;
        }, 8000);
      });
    }
    startListening();
    return () => {
      if (unlisten) unlisten();
    };
  });

  let baseUrl = $state(localStorage.getItem("raa_base_url") || "");
  let modelName = $state(localStorage.getItem("raa_model_name") || "");

  // Centralized normalization helper - always returns a clean parent path or "" for default
  function normalizeVaultPath(input: string): string {
    if (!input) return "";
    let p = input.trim();
    p = p.replace(/[\\/]RAA_Vault\/?$/, '');
    return p;
  }

  const initialVault = normalizeVaultPath(localStorage.getItem("raa_vault_root_path") || "");
  let vaultRootPath = $state(initialVault);

  // One-time flag for first-run default vault creation notification
  let defaultVaultInitializedThisSession = $state(false);

  let displayVaultPath = $derived(
    vaultRootPath ? `${vaultRootPath}/RAA_Vault` : "~/Documents/RAA_Vault"
  );

  let isConfigured = $derived(
    baseUrl.trim().length > 0 && modelName.trim().length > 0,
  );
  let isDev = $state(false);

  // First-run initialization: create and store the real default vault path
  $effect(() => {
    const hasStoredVault = localStorage.getItem("raa_vault_root_path");

    if (!hasStoredVault && !vaultRootPath) {
      initializeDefaultVaultOnFirstRun();
    }
  });

  async function initializeDefaultVaultOnFirstRun() {
    try {
      const defaultPath: string = await invoke("get_default_vault_path");
      await invoke("create_vault_directory", { rootPath: defaultPath });

      const parent = normalizeVaultPath(defaultPath);
      vaultRootPath = parent;

      // Persist immediately
      localStorage.setItem("raa_vault_root_path", parent);

      defaultVaultInitializedThisSession = true;
      console.log("Default vault auto-created on first run:", parent);
    } catch (err) {
      console.error("Failed to auto-create default vault on first run:", err);
    }
  }

  $effect(() => {
    localStorage.setItem("raa_base_url", baseUrl);
    localStorage.setItem("raa_model_name", modelName);

    // Persist using the same normalization
    const cleanRoot = normalizeVaultPath(vaultRootPath || "");
    localStorage.setItem("raa_vault_root_path", cleanRoot);
  });

  async function selectVaultRootPath() {
    const selected = await open({ directory: true, multiple: false });
    if (selected && !Array.isArray(selected)) {
      // Always normalize through the central function
      vaultRootPath = normalizeVaultPath(selected);
    }
  }

  async function setDefaultVault() {
    try {
      const defaultPath: string = await invoke("get_default_vault_path");
      await invoke("create_vault_directory", { rootPath: defaultPath });

      const parent = normalizeVaultPath(defaultPath);
      vaultRootPath = parent;

      console.log("Default vault location reset to:", parent);
    } catch (err) {
      console.error("Failed to reset to default vault:", err);
      vaultRootPath = "";
    }
  }

  let isProcessing = $state(false);
  let currentReport = $state({
    verdict: "",
    reasoning: "",
    target_name: "",
    is_error: false,
  });
  let certMsg = $state("");
  let lastCertifySuccess = $state(true);
  let commandInput = $state("");
  let ledgerContent = $state(""); // legacy raw view (kept for now)
  let ledgerFiles = $state<any[]>([]);
  let selectedLedgerPath = $state("");
  let selectedLedgerContent = $state("");
  let recordedHashes = $state<RecordedHash[]>([]);

  let ledgerSearch = $state("");
  let isLoadingLedger = $state(false);
  let integrityReport = $state<any>(null);

  // Delete confirmation state
  let deleteConfirmPath = $state<string | null>(null);
  let deleteConfirmName = $state<string | null>(null);

  let allowedExts = $state([".md", ".js", ".yml", ".zip", ".env", ".txt"]);
  let activeFiles = $state<string[]>([]);
  let skippedFiles = $state<string[]>([]);
  let activeScrollContainer: HTMLElement | undefined = $state();
  let skippedScrollContainer: HTMLElement | undefined = $state();

  async function scrollToBottom(el: HTMLElement | undefined) {
    if (el) {
      await tick();
      el.scrollTop = el.scrollHeight;
    }
  }

  onMount(() => {
    isDev = window.location.hostname === "localhost";
    let unlisten: any;
    async function setupListener() {
      unlisten = await listen("scan-event", (event: any) => {
        const { path, status } = event.payload;
        if (status === "Active") {
          activeFiles = [...activeFiles, path];
          scrollToBottom(activeScrollContainer);
        } else {
          skippedFiles = [...skippedFiles, path];
          scrollToBottom(skippedScrollContainer);
        }
      });
    }
    setupListener();
    return () => {
      if (unlisten) unlisten();
    };
  });

  function resetResults() {
    currentReport = {
      verdict: "",
      reasoning: "",
      target_name: "",
      is_error: false,
    };
    certMsg = "";
    lastCertifySuccess = true;
    activeFiles = [];
    skippedFiles = [];
  }

  function getReportSegments(text: string) {
    if (!text) return [];
    let segments = text
      .split(/(?:\n|^)(?=\d+\.|\*\*Item|Item\s\d+:|---\n)/g)
      .filter((s) => s.trim().length > 5);

    if (segments.length === 0 && text.trim().length > 0) {
      segments = [text];
    }
    console.log("Segments from reasoning:", segments);
    return segments;
  }

  function highlightSegment(text: string) {
    if (!text) return "";
    return text
      .replace(
        /([\/\w\-_.]+\.(?:md|rs|ts|js|py|yml|zip|toml|json|txt|sh))/gi,
        '<span class="path-text">$1</span>',
      )
      .replace(
        /(?<![A-Z])(SAFE|CERTIFIED|CLEAN|ALL SAFE)(?![A-Z])/g,
        '<span class="text-success">$1</span>',
      )
      .replace(
        /(?<![A-Z])(VIOLATION|THREAT|DANGER|MALICIOUS|DETECTED)(?![A-Z])/g,
        '<span class="text-danger">$1</span>',
      );
  }

  type VerificationStatus = 'pending' | 'match' | 'mismatch' | 'not_found' | 'error';

  type RecordedHash = {
    file: string;
    hash: string;
    status?: VerificationStatus;
    fromArchive?: boolean;
  };

  // Slice 5: transient copy feedback state
  let copiedHash = $state<string | null>(null);
  let copyTimeout: ReturnType<typeof setTimeout> | null = null;

  function extractRecordedHashes(text: string): RecordedHash[] {
    if (!text) return [];

    const matches: RecordedHash[] = [];

    // Support old flat format: File: ... | Hash: ...
    const flatRegex = /File:\s*(.+?)\s*\|\s*Hash:\s*([a-f0-9]{64})/gi;
    let match;
    while ((match = flatRegex.exec(text)) !== null) {
      matches.push({
        file: match[1].trim(),
        hash: match[2],
      });
    }

    // Support new rich format (File: on one line, Hash: on next line)
    const richRegex = /File:\s*(.+?)\s*\n\s*Hash:\s*([a-f0-9]{64})/gi;
    while ((match = richRegex.exec(text)) !== null) {
      matches.push({
        file: match[1].trim(),
        hash: match[2],
      });
    }

    return matches;
  }

  function getDnaSummary(hashes: RecordedHash[]) {
    const total = hashes.length;
    const matches = hashes.filter(h => h.status === 'match').length;
    const mismatches = hashes.filter(h => h.status === 'mismatch').length;
    const missing = hashes.filter(h => h.status === 'not_found').length;
    const errors = hashes.filter(h => h.status === 'error').length;
    const pending = hashes.filter(h => h.status === 'pending').length;
    return { total, matches, mismatches, missing, errors, pending };
  }

  async function verifyRecordedHashes() {
    for (let i = 0; i < recordedHashes.length; i++) {
      const entry = recordedHashes[i];
      recordedHashes[i] = { ...entry, status: 'pending' };
      // Force reactivity
      recordedHashes = [...recordedHashes];

      try {
        const currentHash: string = await invoke("hash_file", { path: entry.file });
        const newStatus: VerificationStatus = currentHash === entry.hash ? 'match' : 'mismatch';
        recordedHashes[i] = { ...entry, status: newStatus };
      } catch (e) {
        // File probably doesn't exist or can't be read
        recordedHashes[i] = { ...entry, status: 'not_found' };
      }
      recordedHashes = [...recordedHashes];
    }
  }

  async function verifySingleHash(index: number) {
    if (index < 0 || index >= recordedHashes.length) return;

    const entry = recordedHashes[index];
    recordedHashes[index] = { ...entry, status: 'pending' };
    recordedHashes = [...recordedHashes];

    try {
      const currentHash: string = await invoke("hash_file", { path: entry.file });
      const newStatus: VerificationStatus = currentHash === entry.hash ? 'match' : 'mismatch';
      recordedHashes[index] = { ...entry, status: newStatus };
    } catch (e) {
      recordedHashes[index] = { ...entry, status: 'not_found' };
    }
    recordedHashes = [...recordedHashes];
  }

  function copyHash(hash: string) {
    navigator.clipboard.writeText(hash).then(() => {
      if (copyTimeout) clearTimeout(copyTimeout);
      copiedHash = hash;
      copyTimeout = setTimeout(() => {
        copiedHash = null;
      }, 1200);
    }).catch(() => {
      // Fallback for older environments
      alert('Copied: ' + hash);
    });
  }

  async function addWatcherFolder() {
    if (watcherFolders.length >= 5) return;
    const selected = await open({ directory: true, multiple: false });
    if (selected && !Array.isArray(selected)) {
      watcherFolders = [...watcherFolders, selected];
    }
  }

  function removeWatcherFolder(index: number) {
    watcherFolders = watcherFolders.filter((_, i) => i !== index);
  }

  async function ensureVault() {
    // Ensure the vault directory exists.
    // We now prefer having a real path, but still support the empty string for default.
    try {
      await invoke("create_vault_directory", { rootPath: vaultRootPath });
    } catch (err) {
      console.error("Failed to ensure vault directory:", err);
    }
  }

  async function handleAudit(e?: Event) {
    if (e) e.preventDefault();
    if (!commandInput.trim()) return;
    resetResults();
    
    await ensureVault();
    
    // 1. Mark the absolute start and start real-time timers
    startTimers();
    
    isProcessing = true;
    try {
      // 2. LAP TICK: Time to prepare the job and hit the Mac Mini's Rust bridge
      stopHandoffTimer();

      const report = await invoke<any>("audit_command", {
        commandStr: commandInput,
        baseUrl,
        modelName,
        vaultRootPath
      });
      
      // 3. COMPLETION: The Oracle has spoken
      stopTotalTimer();

      currentReport = report;
      commandInput = ""; 

      await tick();
      console.log("Updated currentReport:", currentReport);
    } catch (err) {
      stopHandoffTimer();
      stopTotalTimer();
      currentReport = {
        verdict: "Error",
        reasoning: String(err),
        target_name: "Audit",
        is_error: true,
      };
      await tick();
    } finally {
      isProcessing = false;
    }
  }

  async function handleBrowseFile() {
    resetResults();
    try {
      await ensureVault();

      // 1. Mark the absolute start and start real-time timers
      startTimers();

      const selected = await open({
        multiple: false,
        directory: false,
        filters: [
          {
            name: "Forensic Target",
            extensions: ["env", "ipynb", "js", "json", "jsonl", "md", "py", "rs", "sh", "toml", "ts", "txt", "yml"],
          },
        ],
      });

      if (selected && typeof selected === "string") {
        // 2. LAP TICK: Time to prepare the job
        stopHandoffTimer();
        isProcessing = true;
        currentReport = await invoke("scan_file_integrity", {
          filePath: selected,
          baseUrl,
          modelName,
          vaultRootPath
        });
        // 3. COMPLETION: The Oracle has spoken
        stopTotalTimer();
      }
    } catch (err) {
      stopHandoffTimer();
      stopTotalTimer();
      currentReport = {
        verdict: "Error",
        reasoning: String(err),
        target_name: "Files",
        is_error: true,
      };
    } finally {
      isProcessing = false;
    }
  }

  async function handleBrowseArchive() {
    resetResults();
    try {
      await ensureVault();

      // 1. Mark the absolute start and start real-time timers
      startTimers();

      const selected = await open({
        multiple: false,
        filters: [{ name: "Archives", extensions: ["zip"] }],
      });
      if (selected && !Array.isArray(selected)) {
        // 2. LAP TICK: Time to prepare the job
        stopHandoffTimer();
        isProcessing = true;
        currentReport = await invoke("scan_compressed_archive", {
          zipPath: selected,
          allowedExtensions: allowedExts,
          baseUrl,
          modelName,
          vaultRootPath
        });
        // 3. COMPLETION: The Oracle has spoken
        stopTotalTimer();
      }
    } catch (err) {
      stopHandoffTimer();
      stopTotalTimer();
      currentReport = {
        verdict: "Error",
        reasoning: String(err),
        target_name: "Archive",
        is_error: true,
      };
    } finally {
      isProcessing = false;
    }
  }

  async function handleCertifyFolder() {
    resetResults();
    try {
      await ensureVault();

      // 1. Mark the absolute start and start real-time timers
      startTimers();

      const selectedFolder = await open({ directory: true, multiple: false });
      if (selectedFolder) {
        // 2. LAP TICK: Time to prepare the job
        stopHandoffTimer();
        isProcessing = true;
        const certifyResult = await invoke<any>("generate_manifest", {
          folderPath: selectedFolder,
          allowedExtensions: allowedExts,
          baseUrl,
          modelName,
          vaultRootPath
        });

        // Handle the new richer return type
        lastCertifySuccess = !certifyResult.is_error;

        if (certifyResult.is_error) {
          certMsg = `UNCERTIFIED: ${certifyResult.verdict}`;
        } else {
          certMsg = certifyResult.verdict || "CERTIFIED";
        }
        // 3. COMPLETION: The Oracle has spoken
        stopTotalTimer();
      }
    } catch (err) {
      stopHandoffTimer();
      stopTotalTimer();
      certMsg = String(err);
    } finally {
      isProcessing = false;
    }
  }

  async function loadLedgerData() {
    isLoadingLedger = true;
    try {
      // Ensure the vault directory exists before listing (important for default vault case)
      await ensureVault();

      ledgerFiles = await invoke("list_ledger_files", { vaultRootPath });
      // Clear selection when loading fresh data
      selectedLedgerPath = "";
      selectedLedgerContent = "";
      recordedHashes = [];
      copiedHash = null;
    } catch (e) {
      ledgerFiles = [];
      console.error("Failed to list ledger files:", e);
    } finally {
      isLoadingLedger = false;
    }
  }

  async function goToLedger() {
    activeTab = "ledger";
    await loadLedgerData();
  }

  async function selectLedgerFile(filePath: string) {
    selectedLedgerPath = filePath;
    try {
      selectedLedgerContent = await invoke("read_single_ledger_file", { fullPath: filePath });
      copiedHash = null;

      // Detect origin so we can show honest icons for ZIP vs real disk files
      const isArchiveLedger = /Type:\s*archive/i.test(selectedLedgerContent || "");

      // Populate recorded hashes for DNA verification
      recordedHashes = extractRecordedHashes(selectedLedgerContent).map(h => ({
        ...h,
        status: undefined,
        fromArchive: isArchiveLedger,
      }));

      // Slice 4: Auto-verify if we have hashes that haven't been verified yet
      if (recordedHashes.length > 0 && !recordedHashes.some(h => h.status)) {
        // Fire and forget - user can still interact
        verifyRecordedHashes();
      }
    } catch (e) {
      selectedLedgerContent = `Error loading file: ${e}`;
      recordedHashes = [];
      copiedHash = null;
    }
  }

  // --- Delete Ledger File with Confirmation ---
  function requestDeleteLedger(file: any) {
    // Prevent the row click from also selecting the file
    deleteConfirmPath = file.path;
    deleteConfirmName = file.name;
  }

  async function confirmDeleteLedger() {
    if (!deleteConfirmPath) return;

    const pathToDelete = deleteConfirmPath;
    const wasSelected = selectedLedgerPath === pathToDelete;

    try {
      await invoke("delete_ledger_file", {
        fullPath: pathToDelete,
        vaultRootPath,
      });

      // Refresh the list
      await loadLedgerData();

      // If the deleted file was currently selected, clear the detail view
      if (wasSelected) {
        selectedLedgerPath = "";
        selectedLedgerContent = "";
        recordedHashes = [];
      }
    } catch (e) {
      // Simple error feedback
      alert(`Failed to delete report: ${e}`);
    } finally {
      deleteConfirmPath = null;
      deleteConfirmName = null;
    }
  }

  function cancelDeleteLedger() {
    deleteConfirmPath = null;
    deleteConfirmName = null;
  }

  function filteredLedgerFiles() {
    if (!ledgerSearch.trim()) return ledgerFiles;
    const q = ledgerSearch.toLowerCase();
    return ledgerFiles.filter((f) => f.name.toLowerCase().includes(q));
  }

  async function runIntegrityCheck() {
    activeTab = "integrity";
    integrityReport = await invoke("check_integrity", { vaultRootPath });
  }
</script>

<div class="app-layout" class:scanning={isProcessing}>
  <header class="top-bar">
    <button
      type="button"
      class="logo-btn"
      onclick={() => (activeTab = "welcome")}>🛡️ RAA GATEKEEPER</button
    >
    <div class="version-tag">v0.4.0-dev</div>
  </header>

  <nav class="nav-bar">
    <button
      class:active={activeTab === "audit"}
      onclick={() => {
        activeTab = "audit";
        resetResults();
      }}>📟 Audit</button
    >
    <button
      class:active={activeTab === "analyze"}
      onclick={() => {
        activeTab = "analyze";
        resetResults();
      }}>🔍 Analyze</button
    >
    <button
      class:active={activeTab === "archive"}
      onclick={() => {
        activeTab = "archive";
        resetResults();
      }}>📦 Archive</button
    >
    <button
      class:active={activeTab === "certify"}
      onclick={() => {
        activeTab = "certify";
        resetResults();
      }}>🔏 Certify</button
    >
    <button class:active={activeTab === "ledger"} onclick={goToLedger}
      >📜 Ledger</button
    >
    <button
      class:active={activeTab === "settings"}
      onclick={() => (activeTab = "settings")}>⚙️ Settings</button
    >
    {#if isDev}
      <button
        class="dev-tab"
        class:active={activeTab === "integrity"}
        onclick={runIntegrityCheck}>🛡️ Integrity</button
      >
    {/if}
    
    <div class="timing-metrics flex items-center text-12">
      <span>LOCAL: {handoffTime}ms | ORACLE: {(totalTime / 1000).toFixed(2)}s</span>
    </div>

    <button
      class="alert-hub-btn"
      onclick={() => (showHistoryList = !showHistoryList)}
    >
      🕵️
      {#if watcherHistory.length > 0}
        <span class="alert-badge">{watcherHistory.length}</span>
      {/if}
    </button>
  </nav>

  {#if isProcessing}<div class="progress-line"></div>{/if}

  <main class="content-pane">
    <div class="view-wrapper">
      {#if activeTab === "welcome"}
        <section class="tool-view">
          <div class="welcome-intro">
            <p>
              RAA-Gatekeeper is your on-demand guardian when working with files that interact with AI.
            </p>
            <p>
              It acts as a careful, read-only auditor that you fully control. It never runs in the background and only audits your files when you explicitly trigger it. You use your own AI LLM to perform the auditing. Once audited, it helps you share your files safely and confidently with any AI agent.
            </p>
            <p>
              Just like a trusted, well-documented building block in software, an RAA-Certified file gives AI clear, reliable context it can depend on.
            </p>
          </div>

          <hr class="welcome-divider" />

          <div class="shoutouts">
            <p class="shoutouts-label">With thanks to</p>
            <p class="shoutouts-names">
              <span style="color: #396cd8; font-weight: 600;">Agent-Naive</span>, 
              <span style="color: #ffab00; font-weight: 600;">Grok Build</span> & 
              <span class="google-sans" style="font-weight: 600;"><span style="color: #4285F4;">G</span><span style="color: #EA4335;">e</span><span style="color: #FBBC05;">m</span><span style="color: #4285F4;">i</span><span style="color: #34A853;">n</span><span style="color: #EA4335;">i</span></span>
            </p>
            <p class="shoutouts-text">
              for their tireless hard work while developing RAA Gatekeeper.
            </p>
          </div>
        </section>
      {:else if activeTab === "audit"}
        <section class="tool-view">
          <h2>Command Audit</h2>
          <p class="subtitle" title="Click to verify the command with AI">
            Validate terminal commands against AI security fingerprints before execution.
          </p>
          <form class="tool-box" onsubmit={handleAudit}>
            <input
              type="text"
              bind:value={commandInput}
              placeholder="e.g. ls -la"
              autocapitalize="off"
              autocorrect="off"
              spellcheck="false"
              autocomplete="off"
              class="terminal-input"
            />
            <button
              class="primary-btn"
              type="submit"
              disabled={isProcessing}
            >
              Audit
            </button>
          </form>
        </section>
      {:else if activeTab === "analyze"}
        <section class="tool-view">
          <h2>Analyze Files</h2>
          <p class="subtitle" title="Deep scan: Verifying integrity & AI analysis">
            Mathematical Hash + deep AI verdict for specific system files.
          </p>
          <button
            class="primary-btn"
            onclick={handleBrowseFile}
            disabled={isProcessing}>Browse & Scan Files</button
          >
        </section>
      {:else if activeTab === "archive"}
        <section class="tool-view">
          <h2>Deep Archive Audit</h2>
          <p class="subtitle" title="Secure AI-driven check of file contents without unpacking.">
            Audit zip contents without extraction to detect hidden payloads or obscured threats.
          </p>
          <button
            class="primary-btn"
            onclick={handleBrowseArchive}
            disabled={isProcessing}>Select ZIP Archive</button
          >
          <div class="dual-pane-monitor">
            <div class="pane">
              <h4>📡 Audited</h4>
              <div class="scroll-list" bind:this={activeScrollContainer}>
                {#each activeFiles as f}<div class="file-entry">{f}</div>{/each}
              </div>
            </div>
            <div class="pane">
              <h4>🚫 Skipped</h4>
              <div class="scroll-list" bind:this={skippedScrollContainer}>
                {#each skippedFiles as f}<div class="file-entry muted">
                    {f}
                  </div>{/each}
              </div>
            </div>
          </div>
        </section>
      {:else if activeTab === "certify"}
        <section class="tool-view">
          <h2>Certify Project</h2>
          <p class="subtitle" title="Generate a cryptographic audit manifest for all files within a project directory.">
            Use the RAA Gatekeeper to Certify a large Repository of files.
          </p>
          <button
            class="primary-btn"
            onclick={handleCertifyFolder}
            disabled={isProcessing}>Start Certification</button
          >
          <div class="dual-pane-monitor">
            <div class="pane">
              <h4>📡 Live</h4>
              <div class="scroll-list" bind:this={activeScrollContainer}>
                {#each activeFiles as f}<div class="file-entry">
                    {f.split("/").pop()}
                  </div>{/each}
              </div>
            </div>
            <div class="pane">
              <h4>🚫 Skipped</h4>
              <div class="scroll-list" bind:this={skippedScrollContainer}>
                {#each skippedFiles as f}<div class="file-entry muted">
                    {f.split("/").pop()}
                  </div>{/each}
              </div>
            </div>
          </div>
        </section>
      {:else if activeTab === "integrity"}
        <section class="tool-view">
          <h2>Integrity Guard</h2>
          <div class="integrity-container">
            {#if integrityReport}
              <div class="integrity-grid">
                <div class="check-item">
                  <span>🏎️ Parallel Hashing:</span>
                  <span class="check"
                    >{integrityReport.parallel_hashing ? "✅" : "❌"}</span
                  >
                </div>
                <div class="check-item">
                  <span>🪣 Bucket Traversal:</span>
                  <span class="check"
                    >{integrityReport.bucket_traversal ? "✅" : "❌"}</span
                  >
                </div>
                <div class="check-item">
                  <span>📡 Reasoning:</span>
                  <span class="check"
                    >{integrityReport.ai_reasoning ? "✅" : "❌"}</span
                  >
                </div>
                <div class="check-item">
                  <span>🔐 Input Lock:</span>
                  <span class="check"
                    >{integrityReport.terminal_input_lock ? "✅" : "❌"}</span
                  >
                </div>
                <div class="check-item">
                  <span>📦 ZIP Safety:</span>
                  <span class="check"
                    >{integrityReport.zip_safety ? "✅" : "❌"}</span
                  >
                </div>
                <div class="check-item">
                  <span>📁 Hidden Vault:</span>
                  <span class="check"
                    >{integrityReport.vault_path ? "✅" : "❌"}</span
                  >
                </div>
                <div class="check-item">
                  <span>💾 Disk-First:</span>
                  <span class="check"
                    >{integrityReport.disk_first_verification
                      ? "✅"
                      : "❌"}</span
                  >
                </div>
              </div>
            {:else}
              <p class="text-11 muted">
                Establishing secure hardware link...
              </p>
            {/if}
          </div>
        </section>
      {:else if activeTab === "settings"}
        <section class="tool-view">
          <h2>Global Settings</h2>
          <div class="settings-box">
            <div class="settings-group-header">
              <h4 class="filter-title">🧠 AI Core Configuration</h4>
            </div>
            <label class="block mb-8">
              Model Name
              <input type="text" bind:value={modelName} class="w-280" />
            </label>
            <label class="block">
              Base URL
              <input type="text" bind:value={baseUrl} class="w-420 text-12" />
            </label>

            <div class="filter-logic-zone">
              <h4 class="filter-title">🔍 Audit Filter Logic</h4>
              <p class="filter-hint">
                Targeted extensions for Finder & LLM scan:
              </p>

              <div class="extension-grid">
                {#each [".env", ".ipynb", ".js", ".json", ".jsonl", ".md", ".py", ".rs", ".sh", ".toml", ".ts", ".txt", ".yml", ".zip"] as ext}
                  <button
                    type="button"
                    class="ext-chip"
                    class:active={allowedExts.includes(ext)}
                    onclick={() => {
                      if (allowedExts.includes(ext)) {
                        allowedExts = allowedExts.filter((e) => e !== ext);
                      } else {
                        allowedExts = [...allowedExts, ext];
                      }
                    }}
                  >
                    {ext}
                  </button>
                {/each}
              </div>
            </div>

            <div class="filter-logic-zone">
              <h4 class="filter-title">📁 RAA Vault Location</h4>
              <p class="filter-hint">
                The vault is always stored inside a folder named <strong>RAA_Vault</strong>. 
                When no custom root is selected, it uses <code>~/Documents/RAA_Vault</code> by default (created automatically on first use).
              </p>
              <div class="flex-col gap-8">
                <!-- Current Vault Status -->
                <div class="folder-slot">
                  {#if vaultRootPath && vaultRootPath !== "~/Documents"}
                    <span class="path-text text-11 text-ellipsis">{displayVaultPath}</span>
                    <button class="remove-btn" onclick={() => vaultRootPath = ""}>×</button>
                  {:else}
                    <span class="path-text text-11 default-vault-label">
                      ~/Documents/RAA_Vault <span class="text-10 muted">(default)</span>
                    </span>
                  {/if}
                </div>

                <button class="add-slot-btn" onclick={selectVaultRootPath}>
                  + Select Root Directory for RAA_Vault
                </button>

                <button class="add-slot-btn mt-6" onclick={setDefaultVault}>
                  Set Default to ~/Documents/RAA_Vault
                </button>
              </div>

              {#if defaultVaultInitializedThisSession}
                <p class="text-11 text-success mt-2">
                  ✓ Default vault folder was created automatically.
                </p>
              {/if}
            </div>

            <div class="filter-logic-zone">
              <h4 class="filter-title">🕵️ Silent Watcher (Phase 4)</h4>

              <div class="watcher-controls flex gap-20 items-center mb-20">
                <label class="toggle-label flex items-center gap-8 cursor-pointer">
                  <input type="checkbox" bind:checked={watcherEnabled} />
                  Watcher Status:
                  <span class={watcherEnabled ? "text-success" : "text-danger"}>
                    {watcherEnabled ? "ARMED" : "OFF"}
                  </span>
                </label>

                <label class="text-11 muted">
                  Depth Limit:
                  <input
                    type="number"
                    min="1"
                    max="5"
                    bind:value={watcherDepth}
                    class="input-sm w-50"
                  />
                </label>
              </div>

              <div class="folder-slots">
                <p class="filter-hint">
                  Monitored Folder Slots ({watcherFolders.length}/5):
                </p>
                <div class="flex-col gap-8">
                  {#each watcherFolders as folder, i}
                    <div class="folder-slot">
                      <span class="path-text text-11 text-ellipsis">{folder}</span>
                      <button class="remove-btn" onclick={() => removeWatcherFolder(i)}>×</button>
                    </div>
                  {/each}

                  {#if watcherFolders.length < 5}
                    <button class="add-slot-btn" onclick={addWatcherFolder}>
                      + Click to Add Target Folder Slot
                    </button>
                  {/if}
                </div>
              </div>
            </div>
          </div>
        </section>
        {:else if activeTab === "ledger"}
        <section class="tool-view">
          <div class="mb-8">
            <h2 class="ledger-header-title">📜 Forensic Ledger</h2>
            <p class="subtitle ledger-count">{ledgerFiles.length} reports in vault</p>
          </div>

          <div class="flex gap-8 mt-10">
            <!-- File List -->
            <div class="ledger-panel ledger-panel-fixed">
              <div class="ledger-header">
                <input
                  type="text"
                  placeholder="Filter reports..."
                  bind:value={ledgerSearch}
                  class="w-full text-12 ledger-search-input"
                />
              </div>

              <div class="ledger-list-container">
                {#if filteredLedgerFiles().length === 0}
                  <div class="ledger-empty">
                    No .raa reports found.
                  </div>
                {:else}
                  {#each filteredLedgerFiles() as file}
                    <div
                      class="ledger-row"
                      class:selected={selectedLedgerPath === file.path}
                      onclick={() => selectLedgerFile(file.path)}
                      onkeydown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          selectLedgerFile(file.path);
                        }
                      }}
                      role="button"
                      tabindex="0"
                    >
                      <!-- Top line: icon + filename (max room for long names) -->
                      <div class="flex items-center gap-4" style="padding-right: 8px;">
                        <span class="text-12" style="color: {file.has_violation ? '#f87171' : '#4ade80'};">
                          {file.has_violation ? "🚨" : "🛡️"}
                        </span>
                        <span class="flex-1 text-left text-11 monospace text-ellipsis ledger-item-name">
                          {file.name}
                        </span>
                      </div>

                      <!-- Bottom line: date (left) + trashcan (right) -->
                      <div class="ledger-item-date">
                        <span>{file.modified}</span>
                        <button
                          class="ledger-delete-btn"
                          onclick={(e) => { e.stopPropagation(); requestDeleteLedger(file); }}
                          title="Delete this report"
                        >
                          🗑
                        </button>
                      </div>
                    </div>
                  {/each}
                {/if}
              </div>
            </div>

            <!-- Detail Pane -->
            <div class="ledger-detail ledger-panel">
              {#if !selectedLedgerPath}
                <div class="ledger-empty">
                  Select a report from the left to view its forensic details.
                </div>
              {:else}
                <div class="ledger-meta">
                  <strong>{selectedLedgerPath.split('/').pop()}</strong>
                </div>

                {#if selectedLedgerContent}
                  {#each getReportSegments(selectedLedgerContent) as segment}
                    <div class="ledger-incident-card">
                      <pre class="raw-forensics raw-forensics-no-margin">{@html highlightSegment(segment)}</pre>
                    </div>
                  {/each}

                  {#if recordedHashes.length > 0}
                    {@const summary = getDnaSummary(recordedHashes)}
                    <div class="dna-section">
                      <div class="dna-header">
                        <span>Recorded DNA Hashes</span>
                        <span class="dna-count">
                          {summary.total} hashes
                          {#if summary.pending > 0}
                            · verifying…
                          {:else}
                            · {summary.matches} ✅ · {summary.mismatches} ❌ · {summary.missing} ⚠️
                            {#if summary.errors > 0}· {summary.errors} error{/if}
                          {/if}
                        </span>
                      </div>

                      <div class="dna-list">
                        {#each recordedHashes as entry, i}
                          <div class="dna-entry">
                            <span class="dna-file text-ellipsis">{entry.file}</span>
                            <span class="dna-hash">{entry.hash.slice(0, 12)}…</span>

                            <div class="dna-actions">
                              {#if entry.status === 'pending'}
                                <span class="dna-status pending" title="Computing SHA-256 of file on disk right now...">⏳</span>
                              {:else if entry.status === 'match'}
                                <span class="dna-status match" title="File on disk matches the exact hash recorded in this ledger entry">✅</span>
                              {:else if entry.status === 'mismatch'}
                                <span class="dna-status mismatch" title="Current file content on disk does NOT match the hash recorded here — possible tampering, edit, or different version">❌</span>
                              {:else if entry.status === 'not_found'}
                                {#if entry.fromArchive}
                                  <span class="dna-status not-found" title="Recorded inside a ZIP archive. Individual files inside archives cannot be re-verified as loose disk paths (container support pending).">📦</span>
                                {:else}
                                  <span class="dna-status not-found" title="File path no longer exists on disk or cannot be read">⚠️</span>
                                {/if}
                              {:else if entry.status === 'error'}
                                {#if entry.fromArchive}
                                  <span class="dna-status not-found" title="Recorded inside a ZIP archive. Individual files inside archives cannot be re-verified as loose disk paths (container support pending).">📦</span>
                                {:else}
                                  <span class="dna-status not-found" title="Verification failed due to an unexpected error reading the file">⚠️</span>
                                {/if}
                              {/if}

                              <button
                                class="dna-copy-btn"
                                class:copied={copiedHash === entry.hash}
                                onclick={() => copyHash(entry.hash)}
                                title="Copy full 64-char SHA-256 hash to clipboard"
                              >
                                {copiedHash === entry.hash ? '✓' : '📋'}
                              </button>

                              {#if !entry.status || entry.status === 'not_found' || entry.status === 'error'}
                                <button class="dna-verify-single" onclick={() => verifySingleHash(i)} title="Re-compute SHA-256 of this file now and compare against the ledger record">
                                  Verify
                                </button>
                              {:else}
                                <button class="dna-verify-single" onclick={() => verifySingleHash(i)} title="Re-verify this file against current disk contents">
                                  ⟳
                                </button>
                              {/if}
                            </div>
                          </div>
                        {/each}
                      </div>

                      <button class="dna-verify-btn" onclick={verifyRecordedHashes} disabled={recordedHashes.some(h => h.status === 'pending')}>
                        {recordedHashes.some(h => h.status === 'pending') ? 'Verifying...' : 'Verify All'}
                      </button>
                    </div>
                  {/if}
                {:else}
                  <div class="text-11 loading-text">Loading report...</div>
                {/if}
              {/if}
            </div>
          </div>
        </section>
      {/if}
      
      {#if currentReport.verdict}
        <div class="glass-vault">
          <div class="vault-header" class:error={currentReport.is_error}>
            <span class="v-badge"
              >{currentReport.is_error
                ? "🚨 RAA VIOLATION"
                : "🛡️ CERTIFIED"}</span
            >
            <span class="v-target">TARGET: {currentReport.target_name}</span>
          </div>
      
          <div class="vault-body">
            <pre class="raw-forensics">{@html highlightSegment(
                currentReport.reasoning,
              )}</pre>
          </div>
      
          <button class="vault-close" onclick={resetResults}
            >X CLOSE VAULT</button
          >
        </div>
      {/if}
      
      {#if certMsg}
        <div class="forensic-status-overlay">
          <div class="mission-success-toast" class:error={!lastCertifySuccess}>
            <span>{certMsg}</span>
            <button class="toast-close" onclick={() => { certMsg = ""; lastCertifySuccess = true; }}>×</button
            >
          </div>
        </div>
      {/if}

      <!-- Delete Confirmation Modal -->
      {#if deleteConfirmPath}
        <div class="delete-confirm-overlay">
          <div class="delete-confirm-dialog">
            <div class="delete-confirm-title">Delete Report?</div>
            <div class="delete-confirm-message">
              Are you sure you want to permanently delete<br />
              <strong>{deleteConfirmName}</strong>?<br />
              <span class="delete-warning">This action cannot be undone.</span>
            </div>
            <div class="delete-confirm-actions">
              <button class="delete-btn cancel" onclick={cancelDeleteLedger}>
                Cancel
              </button>
              <button class="delete-btn confirm" onclick={confirmDeleteLedger}>
                Yes, Delete
              </button>
            </div>
          </div>
        </div>
      {/if}
      </div>
      
      {#if showWatcherAlert}
        <div class="watcher-toast">
          <span class="toast-icon">🕵️</span>
          <div class="toast-body">
            <div class="toast-title">DNA Change Detected</div>
            <div class="toast-path">{lastWatchedFile.split("/").pop()}</div>
          </div>
        </div>
      {/if}
      
      {#if showHistoryList && watcherHistory.length > 0}
        <div class="alert-dropdown shadow-vault">
          <div class="dropdown-header">
            <h4>DNA Forensic Queue</h4>
            <button class="close-x" onclick={() => (showHistoryList = false)}
              >×</button
            >
          </div>
      
          <div class="alert-list">
            {#each watcherHistory as file}
              <div class="alert-item">
                <span class="file-name">{file.split("/").pop()}</span>
                <button
                  class="audit-link"
                  onclick={() => startAuditFromQueue(file)}>Audit</button
                >
              </div>
            {/each}
          </div>
      
          <button class="clear-btn" onclick={() => (watcherHistory = [])}
            >Clear All Alerts</button
          >
        </div>
      {/if}
  </main>

  <footer class="app-footer">
    <div class="footer-left">
      <span class="stat-item">© Agent-Naive 2026</span>
    </div>

    <div class="footer-stats">
      <span class="stat-item"
        >LLM: <span class="brand-text">{modelName || "None"}</span></span
      >
      <span class="stat-divider">|</span>
      <span class="stat-item"
        >Status: <span class={isConfigured ? "text-success" : "text-danger"}
          >{isConfigured ? "Armed" : "Unarmed"}</span
        ></span
      >
    </div>
  </footer>
</div>

<style>
  /* 
    Page-specific styles only.
    Most global + reusable styles have been moved to src/app.css
    for better maintainability and to reduce bloat.
  */
  .welcome-intro {
    max-width: 700px;
    margin: 0 auto 24px;
    line-height: 1.65;
    font-size: 17px;
    opacity: 0.92;
    text-align: center;
  }

  .welcome-intro p {
    margin-bottom: 14px;
  }

  .welcome-divider {
    border: none;
    border-top: 1px solid var(--border);
    margin: 40px auto;
    width: 60%;
    max-width: 400px;
  }

  .shoutouts {
    text-align: center;
    margin-top: 20px;
    opacity: 0.7;
    line-height: 1.5;
  }

  .shoutouts-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 4px;
    opacity: 0.6;
  }

  .shoutouts-names {
    font-size: 13px;
    margin-bottom: 2px;
  }

  .shoutouts-text {
    font-size: 11px;
  }

  .google-sans {
    font-family: "Google Sans", "Product Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px; /* slightly larger to compensate for the font */
  }

  .tool-box {
    display: flex;
    gap: 10px;
    margin-top: 20px;
  }
  .tool-box input {
    flex: 1;
    background: #1a1a1a;
    border: 1px solid #333;
    color: #fff;
    padding: 12px;
    border-radius: 6px;
    font-family: monospace;
  }






  .dna-section {
    margin-top: 16px;
    border-top: 1px solid #222;
    padding-top: 12px;
  }

  .dna-list {
    font-size: 11px;
    font-family: monospace;
  }

  .dna-entry {
    display: flex;
    justify-content: space-between;
    padding: 3px 0;
    border-bottom: 1px solid #1a1a1a;
  }

  .dna-file {
    flex: 1;
    min-width: 0;
    color: #ccc;
  }

  .dna-hash {
    color: #666;
    flex-shrink: 0;
    padding-left: 12px;
  }

  .dna-status {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 4px;
    margin-left: 8px;
    flex-shrink: 0;
  }

  .dna-status.match {
    background: #052e16;
    color: #4ade80;
  }

  .dna-status.mismatch {
    background: #450a0a;
    color: #f87171;
  }

  .dna-status.not-found {
    background: #3f2e00;
    color: #fbbf24;
  }

  .dna-verify-btn {
    margin-top: 10px;
    background: transparent;
    border: 1px solid #444;
    color: #aaa;
    padding: 6px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 11px;
    width: 100%;
  }

  .dna-verify-btn:hover:not(:disabled) {
    border-color: #666;
    color: #ddd;
  }

  .dna-verify-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .dna-verify-single {
    background: transparent;
    border: 1px solid #444;
    color: #888;
    font-size: 9px;
    padding: 1px 6px;
    border-radius: 3px;
    cursor: pointer;
    flex-shrink: 0;
  }

  .dna-verify-single:hover {
    border-color: #666;
    color: #ccc;
  }

  .dna-status.pending {
    background: #1f2937;
    color: #9ca3af;
  }

  .dna-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }

  .dna-copy-btn {
    background: transparent;
    border: 1px solid #444;
    color: #888;
    font-size: 10px;
    padding: 1px 5px;
    border-radius: 3px;
    cursor: pointer;
    line-height: 1;
  }

  .dna-copy-btn:hover {
    border-color: #666;
    color: #ccc;
  }

  .dna-copy-btn.copied {
    color: #4ade80;
    border-color: #4ade80;
  }
</style>
