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
  let vaultRootPath = $state(localStorage.getItem("raa_vault_root_path") || "");

  // Normalize any previously stored value that accidentally included /RAA_Vault
  if (vaultRootPath.endsWith('/RAA_Vault') || vaultRootPath.endsWith('\\RAA_Vault')) {
    vaultRootPath = vaultRootPath.replace(/[\\/]RAA_Vault\/?$/, '');
  }

  let displayVaultPath = $derived(
    vaultRootPath ? `${vaultRootPath}/RAA_Vault` : "~/Documents/RAA_Vault"
  );

  let isConfigured = $derived(
    baseUrl.trim().length > 0 && modelName.trim().length > 0,
  );
  let isDev = $state(false);

  $effect(() => {
    localStorage.setItem("raa_base_url", baseUrl);
    localStorage.setItem("raa_model_name", modelName);

    // Always persist a clean parent path (never with /RAA_Vault suffix)
    const cleanRoot = (vaultRootPath || "").replace(/[\\/]RAA_Vault\/?$/, "");
    localStorage.setItem("raa_vault_root_path", cleanRoot);
  });

  async function selectVaultRootPath() {
    const selected = await open({ directory: true, multiple: false });
    if (selected && !Array.isArray(selected)) {
      vaultRootPath = selected;
    }
  }

  async function setDefaultVault() {
    try {
      // Explicitly ensure the true default location ~/Documents/RAA_Vault is created
      await invoke("create_vault_directory", { rootPath: "" });
      // Keep vaultRootPath empty to represent "using the built-in default"
      vaultRootPath = "";
      console.log("Default vault location activated: ~/Documents/RAA_Vault");
    } catch (err) {
      console.error("Failed to create default vault:", err);
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
  let commandInput = $state("");
  let ledgerContent = $state(""); // legacy raw view (kept for now)
  let ledgerFiles = $state<any[]>([]);
  let selectedLedgerPath = $state("");
  let selectedLedgerContent = $state("");
  let ledgerSearch = $state("");
  let isLoadingLedger = $state(false);
  let integrityReport = $state<any>(null);

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
        /(SAFE|CERTIFIED|CLEAN|ALL SAFE)/g,
        '<span class="text-success">$1</span>',
      )
      .replace(
        /(VIOLATION|THREAT|DANGER|MALICIOUS|DETECTED)/g,
        '<span class="text-danger">$1</span>',
      );
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
    // Only ensure directory creation if the user has explicitly set a custom root.
    // On first run (empty), leave vaultRootPath empty — the default ~/Documents/RAA_Vault
    // will be used and created automatically inside the Rust logging functions.
    if (vaultRootPath && vaultRootPath !== "~/Documents") {
      try {
        await invoke("create_vault_directory", { rootPath: vaultRootPath });
      } catch (err) {
        console.error("Failed to ensure custom vault directory:", err);
      }
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
        certMsg = await invoke("generate_manifest", {
          folderPath: selectedFolder,
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
      certMsg = String(err);
    } finally {
      isProcessing = false;
    }
  }

  async function loadLedgerData() {
    isLoadingLedger = true;
    try {
      ledgerFiles = await invoke("list_ledger_files", { vaultRootPath });
      // Clear selection when loading fresh data
      selectedLedgerPath = "";
      selectedLedgerContent = "";
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
    } catch (e) {
      selectedLedgerContent = `Error loading file: ${e}`;
    }
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
    
    <div class="timing-metrics" style="margin-left: auto; display: flex; align-items: center; font-size: 12px; color: #666; padding: 0 15px;">
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
          <h2>System Status: {isConfigured ? "ONLINE" : "STANDBY"}</h2>
          <div class="welcome-card">
          <p class="subtitle">
            Forensic protocols armed. Logs in {displayVaultPath}
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
          <div class="welcome-card">
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
              <p style="color: #666; font-size: 11px; padding: 20px;">
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
            <label style="display: block; margin-bottom: 12px;">
              Model Name
              <input type="text" bind:value={modelName} style="width: 280px;" />
            </label>
            <label style="display: block;">
              Base URL
              <input type="text" bind:value={baseUrl} style="width: 420px; font-size: 12px;" />
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

            <div
              class="filter-logic-zone"
              style="margin-top: 30px; border-top: 1px solid #222; padding-top: 20px;"
            >
              <h4 class="filter-title">📁 RAA Vault Location</h4>
              <p class="filter-hint">
                The vault is always stored inside a folder named <strong>RAA_Vault</strong>. 
                When no custom root is selected, it uses <code>~/Documents/RAA_Vault</code> by default (created automatically on first use).
              </p>
              <div style="display: flex; flex-direction: column; gap: 8px;">
                <!-- Current Vault Status -->
                <div
                  class="folder-slot"
                  style="background: #111; border: 1px solid #222; padding: 8px 12px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;"
                >
                  {#if vaultRootPath && vaultRootPath !== "~/Documents"}
                    <span
                      class="path-text"
                      style="font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"
                    >{displayVaultPath}</span>
                    <button
                      class="remove-btn"
                      style="background: none; border: none; color: #ef4444; cursor: pointer; font-size: 16px; line-height: 1;"
                      onclick={() => vaultRootPath = ""}
                    >×</button>
                  {:else}
                    <span
                      class="path-text"
                      style="font-size: 11px; color: #4ade80;"
                    >~/Documents/RAA_Vault <span style="color:#666; font-size:10px;">(default)</span></span>
                  {/if}
                </div>

                <button
                  class="add-slot-btn"
                  style="margin-top: 10px; background: transparent; border: 1px dashed #444; color: #888; padding: 12px; border-radius: 4px; cursor: pointer; font-size: 11px; transition: border-color 0.2s;"
                  onclick={selectVaultRootPath}
                >
                  + Select Root Directory for RAA_Vault
                </button>

                <button
                  class="add-slot-btn"
                  style="margin-top: 6px; background: transparent; border: 1px dashed #555; color: #777; padding: 10px; border-radius: 4px; cursor: pointer; font-size: 11px; transition: border-color 0.2s;"
                  onclick={setDefaultVault}
                >
                  Set Default to ~/Documents/RAA_Vault
                </button>
              </div>
            </div>

            <div
              class="filter-logic-zone"
              style="margin-top: 30px; border-top: 1px solid #222; padding-top: 20px;"
            >
              <h4 class="filter-title">🕵️ Silent Watcher (Phase 4)</h4>

              <div
                class="watcher-controls"
                style="display: flex; gap: 20px; align-items: center; margin-bottom: 20px;"
              >
                <label
                  class="toggle-label"
                  style="display: flex; align-items: center; gap: 10px; cursor: pointer;"
                >
                  <input type="checkbox" bind:checked={watcherEnabled} />
                  Watcher Status:
                  <span class={watcherEnabled ? "text-success" : "text-danger"}
                    >{watcherEnabled ? "ARMED" : "OFF"}</span
                  >
                </label>

                <label style="font-size: 11px; color: #666;">
                  Depth Limit:
                  <input
                    type="number"
                    min="1"
                    max="5"
                    bind:value={watcherDepth}
                    style="width: 50px; background: #111; border: 1px solid #333; color: white; margin-left: 5px; padding: 2px 5px;"
                  />
                </label>
              </div>

              <div class="folder-slots">
                <p class="filter-hint">
                  Monitored Folder Slots ({watcherFolders.length}/5):
                </p>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                  {#each watcherFolders as folder, i}
                    <div
                      class="folder-slot"
                      style="background: #111; border: 1px solid #222; padding: 8px 12px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;"
                    >
                      <span
                        class="path-text"
                        style="font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"
                        >{folder}</span
                      >
                      <button
                        class="remove-btn"
                        style="background: none; border: none; color: #ef4444; cursor: pointer; font-size: 16px; line-height: 1;"
                        onclick={() => removeWatcherFolder(i)}>×</button
                      >
                    </div>
                  {/each}

                  {#if watcherFolders.length < 5}
                    <button
                      class="add-slot-btn"
                      style="margin-top: 10px; background: transparent; border: 1px dashed #444; color: #888; padding: 12px; border-radius: 4px; cursor: pointer; font-size: 11px; transition: border-color 0.2s;"
                      onclick={addWatcherFolder}
                    >
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
          <div style="margin-bottom: 8px;">
            <h2 style="margin: 0;">📜 Forensic Ledger</h2>
            <p class="subtitle" style="margin: 4px 0 0;">{ledgerFiles.length} reports in vault</p>
          </div>

          <div style="display: flex; gap: 12px; margin-top: 12px;">
            <!-- File List -->
            <div style="flex: 0 0 320px; border: 1px solid #222; border-radius: 6px; background: #111; overflow: hidden; display: flex; flex-direction: column;">
              <div style="padding: 8px 10px; border-bottom: 1px solid #222; background: #1a1a1a;">
                <input
                  type="text"
                  placeholder="Filter reports..."
                  bind:value={ledgerSearch}
                  style="width: 100%; background: #222; border: 1px solid #333; color: #ddd; padding: 6px 8px; font-size: 12px; border-radius: 4px;"
                />
              </div>

              <div style="flex: 1; overflow-y: auto; max-height: 420px;">
                {#if filteredLedgerFiles().length === 0}
                  <div style="padding: 20px; color: #666; font-size: 12px; text-align: center;">
                    No .raa reports found.
                  </div>
                {:else}
                  {#each filteredLedgerFiles() as file}
                    <button
                      class="ledger-row"
                      class:selected={selectedLedgerPath === file.path}
                      onclick={() => selectLedgerFile(file.path)}
                    >
                      <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                        <span style="font-size: 12px; color: {file.has_violation ? '#f87171' : '#4ade80'};">
                          {file.has_violation ? "🚨" : "🛡️"}
                        </span>
                        <span style="flex: 1; text-align: left; font-size: 11px; font-family: monospace; color: #ddd; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                          {file.name}
                        </span>
                      </div>
                      <div style="font-size: 10px; color: #666; text-align: right; margin-top: 2px;">
                        {file.modified}
                      </div>
                    </button>
                  {/each}
                {/if}
              </div>
            </div>

            <!-- Detail Pane -->
            <div style="flex: 1; border: 1px solid #222; border-radius: 6px; background: #111; padding: 12px; min-height: 420px; overflow-y: auto; font-size: 12px;">
              {#if !selectedLedgerPath}
                <div style="color: #666; padding: 20px; text-align: center; font-style: italic;">
                  Select a report from the left to view its forensic details.
                </div>
              {:else}
                <div style="margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid #222; font-size: 11px; color: #888;">
                  <strong>{selectedLedgerPath.split('/').pop()}</strong>
                </div>

                {#if selectedLedgerContent}
                  {#each getReportSegments(selectedLedgerContent) as segment}
                    <div class="ledger-incident-card">
                      <pre class="raw-forensics" style="margin: 0;">{@html highlightSegment(segment)}</pre>
                    </div>
                  {/each}
                {:else}
                  <div style="color: #666;">Loading report...</div>
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
          <div class="mission-success-toast">
            <span>{certMsg}</span>
            <button class="toast-close" onclick={() => (certMsg = "")}>×</button
            >
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
    <div class="footer-stats">
      <span class="stat-item"
        >LLM: <span class="brand-text">{modelName || "None"}</span></span
      >
      <span class="stat-divider">|</span>
      <span class="stat-item"
        >Status: <span class={isConfigured ? "text-success" : "text-danger"}
          >{isConfigured ? "Armed" : "Standby"}</span
        ></span
      >
    </div>
  </footer>
</div>

<style>
  :root {
    font-family: "Inter", sans-serif;
    --primary: #396cd8;
    --bg: #0a0a0a;
    --nav: #161616;
    --border: #262626;
  }
  .app-layout {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: var(--bg);
    color: #f4f4f4;
    overflow: hidden;
  }
  .top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 15px 30px;
    background: #000;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .logo-btn {
    background: none;
    border: none;
    color: var(--primary);
    font-weight: 900;
    font-size: 14px;
    letter-spacing: 2px;
    cursor: pointer;
    text-align: left;
  }
  .nav-bar {
    display: flex;
    gap: 8px;
    padding: 8px 25px;
    background: var(--nav);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .nav-bar button {
    background: transparent;
    border: none;
    color: #888;
    padding: 8px 16px;
    font-size: 12px;
    cursor: pointer;
  }
  .nav-bar button.active {
    color: var(--primary);
    background: #222;
    border-radius: 4px;
  }
  .dev-tab {
    border: 1px solid #333 !important;
    color: #ffab00 !important;
  }
  .progress-line {
    height: 2px;
    width: 100%;
    position: relative;
    overflow: hidden;
    background: #222;
    flex-shrink: 0;
  }
  .progress-line::after {
    content: "";
    position: absolute;
    left: -50%;
    height: 100%;
    width: 50%;
    background: var(--primary);
    animation: slide 1.5s infinite;
  }
  @keyframes slide {
    from {
      left: -50%;
    }
    to {
      left: 100%;
    }
  }
  .content-pane {
    flex: 1;
    padding: 40px;
    overflow-y: auto;
    position: relative;
  }
  .view-wrapper {
    max-width: 1000px;
    margin: 0 auto;
    width: 100%;
    display: flex;
    flex-direction: column;
    min-height: 100%;
    padding-bottom: 150px;
  }
  .welcome-card {
    background: #161616;
    padding: 30px;
    border-radius: 12px;
    border: 1px solid var(--border);
    margin-top: 20px;
    text-align: left;
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
  .primary-btn {
    background: var(--primary);
    color: #fff;
    border: none;
    padding: 12px 24px;
    font-weight: 700;
    border-radius: 6px;
    cursor: pointer;
  }
  .dual-pane-monitor {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-top: 20px;
    height: 300px;
  }
  .pane {
    background: #161616;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    text-align: left;
  }
  h4 {
    font-size: 10px;
    color: #555;
    text-transform: uppercase;
    margin-bottom: 10px;
  }
  .scroll-list {
    overflow-y: auto;
    flex: 1;
    font-family: monospace;
    font-size: 11px;
  }
  .file-entry {
    padding: 4px 0;
    border-bottom: 1px solid #222;
  }

  .glass-vault {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 90%;
    max-width: 850px;
    max-height: 80vh;
    background: #050505;
    border: 2px solid #333;
    box-shadow: 0 0 100px #000;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    border-radius: 8px;
  }
  .vault-header {
    padding: 20px;
    background: #000;
    border-bottom: 1px solid #222;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-family: monospace;
  }
  .vault-header.error {
    border-bottom: 2px solid #ef4444;
  }
  .v-badge {
    color: #396cd8;
    font-weight: bold;
  }
  .v-target {
    opacity: 0.6;
    font-size: 12px;
  }
  .vault-body {
    flex: 1;
    overflow-y: auto;
    padding: 30px;
    background: #080808;
    text-align: left;
  }
  .raw-forensics {
    color: #ffffff !important;
    white-space: pre-wrap;
    font-size: 14px;
    line-height: 1.7;
    margin: 0;
    font-family: "Courier New", monospace;
  }
  .vault-close {
    background: #111;
    color: #444;
    border: none;
    padding: 15px;
    cursor: pointer;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .vault-close:hover {
    color: #fff;
    background: #222;
  }

  .forensic-status-overlay {
    position: fixed;
    bottom: 60px;
    left: 50%;
    transform: translateX(-50%);
    width: 100%;
    max-width: 800px;
    z-index: 1000;
    pointer-events: none;
  }
  :global(.report-card),
  .mission-success-toast {
    pointer-events: auto;
    background: #1a1a1a;
    border: 1px solid var(--border);
    border-radius: 12px;
    text-align: left;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.8);
  }
  :global(.report-card.error) {
    border-left: 4px solid #ef4444;
  }
  :global(.badge) {
    background: #333;
    color: #fff;
    padding: 8px 16px;
    font-size: 10px;
    font-weight: 800;
    display: flex;
    align-items: center;
  }
  :global(.target-label) {
    margin-left: 10px;
    opacity: 0.7;
    font-weight: 400;
    text-transform: none;
  }
  :global(.reasoning-container) {
    max-height: 450px;
    overflow-y: auto;
    padding: 10px;
  }
  :global(.segment-card) {
    background: #111;
    margin-bottom: 10px;
    padding: 15px;
    border-radius: 6px;
    border-left: 3px solid #10b981;
  }
  :global(.segment-card.segment-error) {
    border-left-color: #ef4444;
  }
  :global(.segment-content) {
    white-space: pre-wrap;
    font-size: 12px;
    color: #ccc;
    margin: 0;
    line-height: 1.5;
    font-family: monospace;
  }
  :global(.clear-btn) {
    background: transparent;
    border: 1px solid #333;
    color: #666;
    padding: 8px 16px;
    margin: 0 20px 20px;
    border-radius: 4px;
    cursor: pointer;
  }

  .mission-success-toast {
    background: #000;
    border: 1px solid var(--primary);
    color: var(--primary);
    padding: 15px 25px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .integrity-grid {
    display: grid;
    gap: 15px;
  }
  .check-item {
    display: flex;
    justify-content: space-between;
    border-bottom: 1px solid #222;
    padding-bottom: 10px;
  }
  .app-footer {
    padding: 12px 30px;
    background: #000;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: flex-end;
    font-size: 10px;
    color: #444;
    flex-shrink: 0;
  }
  .footer-stats {
    display: flex;
    align-items: center;
    gap: 15px;
  }
  .stat-divider {
    opacity: 0.2;
  }
  .brand-text {
    color: var(--primary);
    font-weight: bold;
  }
  .terminal-input {
    text-transform: none !important;
    font-family: monospace;
  }
  .version-tag {
    font-size: 10px;
    opacity: 0.4;
  }
  .muted {
    opacity: 0.4;
  }
  .subtitle {
    font-size: 14px;
    opacity: 0.6;
  }

  :global(.path-text) {
    color: #396cd8;
    font-weight: bold;
  }
  :global(.text-success) {
    color: #10b981 !important;
    font-weight: bold;
  }
  :global(.text-danger) {
    color: #ef4444 !important;
    font-weight: bold;
  }

  .filter-logic-zone {
    margin-top: 30px;
    border-top: 1px solid var(--border);
    padding-top: 20px;
  }
  .filter-title {
    margin-bottom: 10px;
    color: var(--primary);
    font-size: 12px;
    text-transform: uppercase;
  }
  .filter-hint {
    font-size: 11px;
    opacity: 0.5;
    margin-bottom: 15px;
  }
  .extension-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .ext-chip {
    background: #161616;
    color: #555;
    border: 1px solid #333;
    padding: 6px 12px;
    border-radius: 4px;
    font-family: monospace;
    font-size: 11px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .ext-chip.active {
    background: var(--primary);
    color: #fff;
    border-color: var(--primary);
  }

  .settings-group-header {
    margin-bottom: 15px;
    border-bottom: 1px solid #222;
    padding-bottom: 10px;
  }

  .watcher-toast {
    position: fixed;
    bottom: 30px;
    right: 30px;
    background: #000;
    border: 1px solid var(--primary);
    border-radius: 8px;
    padding: 15px;
    display: flex;
    align-items: center;
    gap: 15px;
    z-index: 10000;
    box-shadow: 0 0 20px rgba(57, 108, 216, 0.4);
    animation: slide-in 0.3s ease-out;
  }
  .toast-icon {
    font-size: 24px;
  }
  .toast-title {
    font-size: 11px;
    font-weight: bold;
    color: var(--primary);
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .toast-path {
    font-size: 13px;
    color: #fff;
    margin-top: 2px;
  }

  .alert-hub-btn {
    position: relative;
    margin-left: auto;
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1.2rem;
    padding: 5px 10px;
  }

  .alert-badge {
    position: absolute;
    top: -2px;
    right: -2px;
    background: #ef4444;
    color: white;
    font-size: 9px;
    font-weight: bold;
    padding: 2px 5px;
    border-radius: 10px;
    line-height: 1;
    box-shadow: 0 0 8px rgba(239, 68, 68, 0.6);
    pointer-events: none;
  }

  .alert-dropdown {
    position: fixed;
    top: 65px;
    right: 20px;
    width: 300px;
    background: #000;
    border: 1px solid var(--primary);
    border-radius: 8px;
    padding: 15px;
    z-index: 10000;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.9);
  }
  .dropdown-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
  }
  .dropdown-header h4 {
    margin: 0;
    font-size: 11px;
    color: var(--primary);
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .close-x {
    background: none;
    border: none;
    color: #444;
    cursor: pointer;
    font-size: 18px;
  }
  .alert-list {
    max-height: 300px;
    overflow-y: auto;
  }
  .alert-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid #111;
  }
  .file-name {
    font-size: 11px;
    color: #fff;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 190px;
  }
  .audit-link {
    background: var(--primary);
    border: none;
    color: white;
    font-size: 10px;
    padding: 4px 10px;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
  }
  .clear-btn {
    width: 100%;
    margin-top: 15px;
    background: #111;
    border: 1px solid #222;
    color: #666;
    font-size: 10px;
    padding: 6px;
    cursor: pointer;
    border-radius: 4px;
  }
  .clear-btn:hover {
    color: #ef4444;
    border-color: #ef4444;
  }
  .subtitle {
    font-size: 14px;
    opacity: 0.6;
    position: relative;
    display: inline-block;
  }

  /* === New Ledger Browser Styles === */
  .ledger-row {
    width: 100%;
    text-align: left;
    background: transparent;
    border: none;
    border-bottom: 1px solid #1f1f1f;
    padding: 8px 10px;
    cursor: pointer;
    transition: background 0.1s;
  }
  .ledger-row:hover {
    background: #1a1a1a;
  }
  .ledger-row.selected {
    background: #222;
    border-left: 3px solid var(--primary);
  }
  .ledger-incident-card {
    background: #1a1a1a;
    border: 1px solid #222;
    border-radius: 4px;
    padding: 10px;
    margin-bottom: 10px;
  }
</style>

// End of File
