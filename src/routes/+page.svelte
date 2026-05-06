<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, tick } from "svelte";

  let baseUrl = $state(localStorage.getItem("raa_base_url") || ""); 
  let modelName = $state(localStorage.getItem("raa_model_name") || "");
  let isConfigured = $derived(baseUrl.trim().length > 0 && modelName.trim().length > 0);
  let isDev = $state(false);

  $effect(() => {
    localStorage.setItem("raa_base_url", baseUrl);
    localStorage.setItem("raa_model_name", modelName);
  });

  let activeTab = $state("welcome"); 
  let isProcessing = $state(false); 
  let currentReport = $state({ verdict: "", reasoning: "", is_error: false });
  let certMsg = $state("");
  let commandInput = $state("");
  let ledgerContent = $state("");
  let integrityReport = $state<any>(null);

  let allowedExts = $state([".rs", ".ts", ".js", ".py", ".yml", ".zip"]); 
  const availableExts = [".rs", ".ts", ".js", ".py", ".yml", ".json", ".md", ".toml", ".sh", ".zip"];
  let activeFiles = $state<string[]>([]);
  let skippedFiles = $state<string[]>([]);
  let activeScrollContainer: HTMLElement | undefined = $state();
  let skippedScrollContainer: HTMLElement | undefined = $state();

  async function scrollToBottom(el: HTMLElement | undefined) {
    if (el) { await tick(); el.scrollTop = el.scrollHeight; }
  }

  onMount(() => {
    // 1. Sync check for dev mode
    isDev = window.location.hostname === 'localhost';
    
    // 2. Wrap the async listener setup
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

    // 3. Return the cleanup function correctly
    return () => { 
      if (unlisten) unlisten(); 
    };
  });


  async function runIntegrityCheck() {
    activeTab = 'integrity';
    integrityReport = await invoke("check_integrity");
  }

  function resetResults() {
    currentReport = { verdict: "", reasoning: "", is_error: false };
    certMsg = ""; activeFiles = []; skippedFiles = [];
  }

  async function handleAudit(e?: Event) {
    if (e) e.preventDefault();
    resetResults(); isProcessing = true;
    try { currentReport = await invoke("audit_command", { commandStr: commandInput, baseUrl, modelName }); } 
    catch (err) { currentReport = { verdict: "Error", reasoning: String(err), is_error: true }; }
    finally { isProcessing = false; }
  }

  async function handleBrowseFile() {
    resetResults();
    try {
      const selected = await open({ multiple: true });
      if (selected) {
        isProcessing = true;
        const paths = Array.isArray(selected) ? selected : [selected];
        currentReport = await invoke("scan_file_integrity", { filePaths: paths, baseUrl, modelName });
      }
    } catch (err) { currentReport = { verdict: "Error", reasoning: String(err), is_error: true }; }
    finally { isProcessing = false; }
  }

  async function handleBrowseArchive() {
    resetResults();
    try {
      const selected = await open({ multiple: false, filters: [{ name: 'Archives', extensions: ['zip'] }] });
      if (selected && !Array.isArray(selected)) {
        isProcessing = true;
        currentReport = await invoke("scan_compressed_archive", { zipPath: selected, allowedExtensions: allowedExts, baseUrl, modelName });
      }
    } catch (err) { currentReport = { verdict: "Error", reasoning: String(err), is_error: true }; }
    finally { isProcessing = false; }
  }

  async function handleCertifyFolder() {
    resetResults();
    try {
      const selectedFolder = await open({ directory: true, multiple: false });
      if (selectedFolder) {
        isProcessing = true;
        certMsg = await invoke("generate_manifest", { folderPath: selectedFolder, allowedExtensions: allowedExts, baseUrl, modelName });
      }
    } catch (err) { certMsg = String(err); } 
    finally { isProcessing = false; }
  }

  async function loadLedger() {
    activeTab = 'ledger';
    ledgerContent = await invoke("read_ledger");
  }
</script>

<div class="app-layout" class:scanning={isProcessing}>
  <header class="top-bar">
    <button type="button" class="logo-btn" onclick={() => activeTab = 'welcome'}>🛡️ RAA GATEKEEPER</button>
    <div class="version-tag">v0.3.0-PHASE-3</div>
  </header>

  <nav class="nav-bar">
    <button class:active={activeTab === 'audit'} onclick={() => {activeTab = 'audit'; resetResults();}}>📟 Audit</button>
    <button class:active={activeTab === 'analyze'} onclick={() => {activeTab = 'analyze'; resetResults();}}>🔍 Analyze</button>
    <button class:active={activeTab === 'archive'} onclick={() => {activeTab = 'archive'; resetResults();}}>📦 Archive</button>
    <button class:active={activeTab === 'certify'} onclick={() => {activeTab = 'certify'; resetResults();}}>🔏 Certify</button>
    <button class:active={activeTab === 'ledger'} onclick={loadLedger}>📜 Ledger</button>
    <button class:active={activeTab === 'settings'} onclick={() => activeTab = 'settings'}>⚙️ Settings</button>
    {#if isDev}
      <button class="dev-tab" class:active={activeTab === 'integrity'} onclick={runIntegrityCheck}>🛡️ Integrity</button>
    {/if}
  </nav>

  {#if isProcessing}<div class="progress-line"></div>{/if}

  <main class="content-pane">
    <div class="view-wrapper">
      {#if activeTab === 'welcome'}
        <section class="tool-view">
          <h2>System Status: {isConfigured ? 'ONLINE' : 'STANDBY'}</h2>
          <div class="welcome-card"><p class="subtitle">Forensic protocols armed. Logs in ~/.RAA_Audits</p></div>
        </section>

      {:else if activeTab === 'audit'}
        <section class="tool-view">
          <h2>Command Audit</h2>
          <form class="tool-box" onsubmit={handleAudit}>
            <input type="text" bind:value={commandInput} placeholder="e.g. ls -la" autocapitalize="none" autocorrect="off" spellcheck="false" autocomplete="off" />
            <button class="primary-btn" type="submit" disabled={isProcessing}>Audit</button>
          </form>
        </section>

      {:else if activeTab === 'analyze'}
        <section class="tool-view">
          <h2>Analyze Files</h2>
          <button class="primary-btn" onclick={handleBrowseFile} disabled={isProcessing}>Browse & Scan Files</button>
        </section>

      {:else if activeTab === 'archive'}
        <section class="tool-view">
          <h2>Deep Archive Audit</h2>
          <button class="primary-btn" onclick={handleBrowseArchive} disabled={isProcessing}>Select ZIP Archive</button>
          <div class="dual-pane-monitor">
            <div class="pane"><h4>📡 Internal Files Audited</h4><div class="scroll-list" bind:this={activeScrollContainer}>{#each activeFiles as f}<div class="file-entry">{f}</div>{/each}</div></div>
            <div class="pane"><h4>🚫 Skipped</h4><div class="scroll-list" bind:this={skippedScrollContainer}>{#each skippedFiles as f}<div class="file-entry muted">{f}</div>{/each}</div></div>
          </div>
        </section>

      {:else if activeTab === 'certify'}
        <section class="tool-view">
          <h2>Certify Project</h2>
          <button class="primary-btn" onclick={handleCertifyFolder} disabled={isProcessing}>Start Certification</button>
          <div class="dual-pane-monitor">
            <div class="pane"><h4>📡 Live Audit</h4><div class="scroll-list" bind:this={activeScrollContainer}>{#each activeFiles as f}<div class="file-entry">{f.split('/').pop()}</div>{/each}</div></div>
            <div class="pane"><h4>🚫 Skipped</h4><div class="scroll-list" bind:this={skippedScrollContainer}>{#each skippedFiles as f}<div class="file-entry muted">{f.split('/').pop()}</div>{/each}</div></div>
          </div>
        </section>

      {:else if activeTab === 'ledger'}
        <section class="tool-view">
          <h2>Forensic Ledger</h2>
          <div class="ledger-viewer"><pre>{ledgerContent || "No logs found in ~/.RAA_Audits"}</pre></div>
        </section>

      {:else if activeTab === 'integrity'}
        <section class="tool-view">
          <h2>Integrity Guard</h2>
          <div class="welcome-card">
            {#if integrityReport}
              <div class="integrity-grid">
                <div class="check-item"><span>🏎️ Parallel Hashing:</span> <span class="check">{integrityReport.parallel_hashing ? '✅' : '❌'}</span></div>
                <div class="check-item"><span>📡 technical Reasoning:</span> <span class="check">{integrityReport.ai_reasoning ? '✅' : '❌'}</span></div>
                <div class="check-item"><span>🔐 Terminal Input Lock:</span> <span class="check">{integrityReport.terminal_input ? '✅' : '❌'}</span></div>
                <div class="check-item"><span>📦 ZIP Safety Valve:</span> <span class="check">{integrityReport.zip_safety ? '✅' : '❌'}</span></div>
                <div class="check-item"><span>📁 Hidden Vault Path:</span> <span class="check">{integrityReport.vault_path ? '✅' : '❌'}</span></div>
              </div>
            {/if}
          </div>
        </section>

      {:else if activeTab === 'settings'}
        <section class="tool-view">
          <h2>Global Settings</h2>
          <div class="settings-box">
             <label>Base URL <input type="text" bind:value={baseUrl} /></label>
             <label>Model Name <input type="text" bind:value={modelName} /></label>
          </div>
        </section>
      {/if}

      {#if currentReport.verdict || certMsg}
        <div class="forensic-status-overlay">
          {#if currentReport.verdict}
            <div class="report-card" class:error={currentReport.is_error}>
              <div class="badge">{currentReport.is_error ? '❌ VIOLATION' : '✅ CERTIFIED'}</div>
              <div class="verdict-text">{currentReport.verdict}</div>
              <div class="reasoning-text"><strong>FORENSIC CONTEXT:</strong><br/>{currentReport.reasoning}</div>
              <button class="clear-btn" onclick={resetResults}>Dismiss</button>
            </div>
          {/if}
          {#if certMsg}
            <div class="mission-success-toast"><span>{certMsg}</span><button class="toast-close" onclick={() => certMsg = ""}>×</button></div>
          {/if}
        </div>
      {/if}
    </div>
  </main>

  <!-- INSERT FOOTER HERE -->
  <footer class="app-footer">
    <div class="footer-stats">
      {#if activeFiles.length > 0}
        <span class="stat-item">Active Files: <strong>{activeFiles.length}</strong></span>
        <span class="stat-divider">|</span>
      {/if}
      <span class="stat-item">Active LLM: <span class="brand-text">{modelName || 'None'}</span></span>
      <span class="stat-divider">|</span>
      <span class="stat-item">Status: <span class={isConfigured ? 'text-success' : 'text-danger'}>{isConfigured ? 'Armed' : 'Standby'}</span></span>
    </div>
  </footer>
</div> <!-- This is the very last closing div of .app-layout -->

<style>
  :root { font-family: 'Inter', sans-serif; --primary: #396cd8; --bg: #0a0a0a; --nav: #161616; --border: #262626; }
  .app-layout { display: flex; flex-direction: column; height: 100vh; background: var(--bg); color: #f4f4f4; overflow: hidden; }
  .top-bar { display: flex; justify-content: space-between; align-items: center; padding: 15px 30px; background: #000; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .logo-btn { background: none; border: none; color: var(--primary); font-weight: 900; font-size: 14px; letter-spacing: 2px; cursor: pointer; text-align: left; }
  .nav-bar { display: flex; gap: 8px; padding: 8px 25px; background: var(--nav); border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .nav-bar button { background: transparent; border: none; color: #888; padding: 8px 16px; font-size: 12px; cursor: pointer; }
  .nav-bar button.active { color: var(--primary); background: #222; border-radius: 4px; }
  .dev-tab { border: 1px solid #333 !important; color: #ffab00 !important; }
  .progress-line { height: 2px; width: 100%; position: relative; overflow: hidden; background: #222; flex-shrink: 0; }
  .progress-line::after { content: ''; position: absolute; left: -50%; height: 100%; width: 50%; background: var(--primary); animation: slide 1.5s infinite; }
  @keyframes slide { from { left: -50%; } to { left: 100%; } }
  .content-pane { flex: 1; padding: 40px; overflow-y: auto; position: relative; }
  .view-wrapper { max-width: 1000px; margin: 0 auto; width: 100%; display: flex; flex-direction: column; min-height: 100%; padding-bottom: 150px; }
  .welcome-card { background: #161616; padding: 30px; border-radius: 12px; border: 1px solid var(--border); margin-top: 20px; text-align: left; }
  .tool-box { display: flex; gap: 10px; margin-top: 20px; }
  .tool-box input { flex: 1; background: #1a1a1a; border: 1px solid #333; color: #fff; padding: 12px; border-radius: 6px; font-family: monospace; }
  .primary-btn { background: var(--primary); color: #fff; border: none; padding: 12px 24px; font-weight: 700; border-radius: 6px; cursor: pointer; }
  .dual-pane-monitor { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; height: 350px; }
  .pane { background: #161616; border: 1px solid var(--border); border-radius: 8px; padding: 12px; display: flex; flex-direction: column; overflow: hidden; text-align: left; }
  h4 { font-size: 10px; color: #555; text-transform: uppercase; margin-bottom: 10px; }
  .scroll-list { overflow-y: auto; flex: 1; font-family: monospace; font-size: 11px; }
  .file-entry { padding: 4px 0; border-bottom: 1px solid #222; }
  .forensic-status-overlay { position: fixed; bottom: 60px; left: 50%; transform: translateX(-50%); width: 100%; max-width: 800px; z-index: 1000; pointer-events: none; }
  .report-card, .mission-success-toast { pointer-events: auto; background: #1a1a1a; border: 1px solid var(--border); border-radius: 12px; text-align: left; box-shadow: 0 10px 40px rgba(0,0,0,0.8); }
  .report-card.error { border-left: 4px solid #ef4444; }
  .badge { background: #333; color: #fff; padding: 8px 16px; font-size: 10px; font-weight: 800; }
  .verdict-text { padding: 15px 20px; font-weight: 800; font-family: monospace; border-bottom: 1px solid var(--border); }
  .reasoning-text { padding: 15px 20px; color: #888; font-size: 13px; white-space: pre-wrap; }
  .mission-success-toast { background: #000; border: 1px solid var(--primary); color: var(--primary); padding: 15px 25px; display: flex; justify-content: space-between; align-items: center; }
  .ledger-viewer { background: #111; padding: 20px; border: 1px solid #333; border-radius: 8px; font-family: monospace; height: 500px; overflow-y: auto; text-align: left; white-space: pre-wrap; }
  .integrity-grid { display: grid; gap: 15px; }
  .check-item { display: flex; justify-content: space-between; border-bottom: 1px solid #222; padding-bottom: 10px; }
  .clear-btn { background: transparent; border: 1px solid #333; color: #666; padding: 8px 16px; margin: 0 20px 20px; border-radius: 4px; cursor: pointer; }
  .subtitle { font-size: 14px; opacity: 0.6; }
  .version-tag { font-size: 10px; opacity: 0.4; }
  .app-footer {padding: 12px 30px; background: #000; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; font-size: 10px; color: #444; flex-shrink: 0; }
  .footer-stats { display: flex; align-items: center; gap: 15px; }
  .stat-divider { opacity: 0.2; }
  .brand-text { color: var(--primary); font-weight: bold; }
  .text-success { color: #10b981; }
  .text-danger { color: #ef4444; }

</style>
