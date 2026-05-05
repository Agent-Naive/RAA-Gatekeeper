<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { listen } from "@tauri-apps/api/event";
  import { onMount } from "svelte";

  // --- PERSISTENT SETTINGS ---
  let baseUrl = $state(localStorage.getItem("raa_base_url") || ""); 
  let modelName = $state(localStorage.getItem("raa_model_name") || "");
  let isConfigured = $derived(baseUrl.trim().length > 0 && modelName.trim().length > 0);

  $effect(() => {
    localStorage.setItem("raa_base_url", baseUrl);
    localStorage.setItem("raa_model_name", modelName);
  });

  // --- APP STATE ---
  let activeTab = $state("welcome"); 
  let isProcessing = $state(false); 
  let currentReport = $state({ verdict: "", reasoning: "", is_error: false });
  let commandInput = $state("");
  let certMsg = $state("");

  // --- RULES STATE ---
  let isLedger = $state(true);    
  let isSnapshot = $state(false); 
  let allowManualOverride = $state(true);
  let allowedExts = $state([".rs", ".ts", ".js", ".py", ".yml"]); 
  const availableExts = [".rs", ".ts", ".js", ".py", ".yml", ".json", ".md", ".toml", ".sh", ".dockerfile"];

  // --- MONITOR STATE ---
  let activeFiles = $state<string[]>([]);
  let skippedFiles = $state<string[]>([]);

  onMount(() => {
    const unlisten = listen("scan-event", (event: any) => {
      const { path, status } = event.payload;
      if (status === "Active") {
        activeFiles = [path, ...activeFiles].slice(0, 15);
      } else {
        skippedFiles = [path, ...skippedFiles].slice(0, 15);
      }
    });
    return () => { unlisten.then(f => f()); };
  });

  function resetResults() {
    currentReport = { verdict: "", reasoning: "", is_error: false };
    certMsg = "";
    activeFiles = [];
    skippedFiles = [];
  }

  function armSystem() {
    if (isConfigured) {
      activeTab = "welcome";
      resetResults();
    }
  }

  // --- COMMAND HANDLERS ---
  async function handleAudit(e?: Event) {
    if (e) e.preventDefault();
    if (!commandInput.trim() || isProcessing) return;
    resetResults(); isProcessing = true;
    try { 
        currentReport = await invoke("audit_command", { commandStr: commandInput, baseUrl, modelName }); 
    } catch (err) { currentReport = { verdict: "System Error", reasoning: String(err), is_error: true }; } 
    finally { isProcessing = false; }
  }

  async function handleBrowseFile() {
    resetResults();
    try {
      const selected = await open({ 
        multiple: true, 
        filters: [{ name: 'Allowed Files', extensions: ['md', 'txt', 'raa', 'json', 'toml', 'rs', 'ts', 'js', 'py', 'yml'] }] 
      });
      if (selected) {
        isProcessing = true;
        const paths = Array.isArray(selected) ? selected : [selected];
        let finalPaths = allowManualOverride ? paths : paths.filter(p => allowedExts.includes(`.${p.split('.').at(-1)?.toLowerCase()}`));
        if (finalPaths.length > 0) {
          currentReport = await invoke("scan_file_integrity", { filePaths: finalPaths, baseUrl, modelName });
        }
      }
    } catch (err) { currentReport = { verdict: "System Error", reasoning: String(err), is_error: true }; } 
    finally { isProcessing = false; }
  }

  async function handleCertifyFolder() {
    resetResults();
    try {
      const selectedFolder = await open({ directory: true, multiple: false });
      if (selectedFolder) {
        isProcessing = true;
        certMsg = await invoke("generate_manifest", { 
          folderPath: selectedFolder, appendMode: isLedger, allowedExtensions: allowedExts, baseUrl, modelName 
        });
      }
    } catch (err) { certMsg = String(err); } 
    finally { isProcessing = false; }
  }

  async function handleBrowseArchive() {
    resetResults();
    try {
      const selected = await open({ multiple: false, filters: [{ name: 'Archives', extensions: ['zip'] }] });
      if (selected && !Array.isArray(selected)) {
        isProcessing = true;
        currentReport = await invoke("scan_compressed_archive", { zipPath: selected, baseUrl, modelName });
      }
    } catch (err) { currentReport = { verdict: "System Error", reasoning: String(err), is_error: true }; } 
    finally { isProcessing = false; }
  }
</script>

<div class="app-layout" class:scanning={isProcessing}>
  <header class="top-bar">
    <button class="logo-btn" onclick={() => activeTab = 'welcome'}>🛡️ RAA GATEKEEPER</button>
    <div class="version-tag">v0.3.0-PHASE-2-ACTIVE</div>
  </header>

  <nav class="nav-bar">
    <button class:active={activeTab === 'audit'} onclick={() => {activeTab = 'audit'; resetResults();}}>📟 Audit</button>
    <button class:active={activeTab === 'analyze'} onclick={() => {activeTab = 'analyze'; resetResults();}}>🔍 Analyze</button>
    <button class:active={activeTab === 'archive'} onclick={() => {activeTab = 'archive'; resetResults();}}>📦 Archive</button>
    <button class:active={activeTab === 'certify'} onclick={() => {activeTab = 'certify'; resetResults();}}>🔏 Certify</button>
    <button class:active={activeTab === 'settings'} onclick={() => {activeTab = 'settings'; resetResults();}}>⚙️ Settings</button>
  </nav>

  {#if isProcessing}<div class="progress-line"></div>{/if}

  <main class="content-pane">
    <div class="view-wrapper">
      
      {#if activeTab === 'welcome'}
        <section class="tool-view welcome-view">
          <h2>System Status: {isConfigured ? 'ONLINE' : 'STANDBY'}</h2>
          {#if isConfigured}
            <p class="subtitle">Gatekeeper is active. Using <strong>{modelName}</strong> for all forensic operations.</p>
            <div class="welcome-card">
              <p>Ready to audit. Select a protocol from the navigation bar above to begin.</p>
              <button class="ghost-btn" onclick={() => activeTab = 'settings'}>Modify LLM Parameters</button>
            </div>
          {:else}
            <p class="subtitle">Security protocols are currently offline.</p>
            <div class="welcome-card warning">
              <p>To enable AI-driven forensics, you must first configure your LLM provider.</p>
              <button class="primary-btn" onclick={() => activeTab = 'settings'}>Go to Settings</button>
            </div>
          {/if}
        </section>

      {:else if activeTab === 'audit'}
        <section class="tool-view">
          <h2>Audit Command Line</h2>
          <p class="subtitle">Validate terminal commands against AI security fingerprints before execution.</p>
          <form class="tool-box" onsubmit={handleAudit}>
            <input type="text" bind:value={commandInput} placeholder="e.g. ls -la" />
            <button class="primary-btn" type="submit" disabled={isProcessing || !isConfigured}>Execute Audit</button>
          </form>
        </section>

      {:else if activeTab === 'analyze'}
        <section class="tool-view">
          <h2>Analyze File</h2>
          <p class="subtitle">Mathematical Hash + deep AI verdict for specific system files.</p>
          <div class="tool-box-vertical">
            <button class="primary-btn" onclick={handleBrowseFile} disabled={isProcessing || !isConfigured}>Browse & Scan Files</button>
            <p class="hint">💡 Pro Tip: Use <strong>Cmd + Click</strong> to cherry-pick files.</p>
          </div>
        </section>

      {:else if activeTab === 'archive'}
        <section class="tool-view">
          <h2>Analyze Compressed Archive</h2>
          <p class="subtitle">Audit zip contents without extraction to detect hidden payloads or obscured threats.</p>
          <button class="primary-btn" onclick={handleBrowseArchive} disabled={isProcessing || !isConfigured}>Open ZIP Archive</button>
        </section>

      {:else if activeTab === 'certify'}
        <section class="tool-view">
          <h2>Certify Project</h2>
          <p class="subtitle">Generate a cryptographic audit manifest for all files within a project directory.</p>
          <div class="cert-options">
            <div class="toggle-group">
                <label class="checkbox-label"><input type="checkbox" checked={isLedger} onchange={() => {isLedger=true;isSnapshot=false}} /> Append to Ledger (.raa)</label>
                <label class="checkbox-label"><input type="checkbox" checked={isSnapshot} onchange={() => {isLedger=false;isSnapshot=true}} /> Unique Snapshot</label>
            </div>
            <button class="primary-btn" onclick={handleCertifyFolder} disabled={isProcessing || !isConfigured}>Start Certification</button>
          </div>
          <div class="dual-pane-monitor">
            <div class="pane"><h4>📡 Live Audit</h4><div class="scroll-list">{#each activeFiles as f}<div class="file-entry">Analyzing: {f.split('/').pop()}</div>{/each}</div></div>
            <div class="pane"><h4>🚫 Skipped</h4><div class="scroll-list">{#each skippedFiles as f}<div class="file-entry muted">{f.split('/').pop()}</div>{/each}</div></div>
          </div>
        </section>

      {:else if activeTab === 'settings'}
        <section class="tool-view">
          <h2>Global Settings</h2>
          <div class="settings-box">
            <div class="field-grid">
              <label class="hint">API Key <input type="password" placeholder="Locked to .env" disabled /></label>
              <label class="hint">Base URL (Mandatory) <input type="text" bind:value={baseUrl} placeholder="https://x.ai" /></label>
              <label class="hint">
                Model Name (Mandatory)
                <div class="input-action-group">
                  <input type="text" bind:value={modelName} placeholder="grok-4.3" />
                  <button class="arm-btn" class:active={isConfigured} onclick={armSystem} disabled={!isConfigured}>
                    {isConfigured ? 'ARM SYSTEM' : 'STANDBY'}
                  </button>
                </div>
              </label>
            </div>
            <hr />
            <h3>📂 Rules</h3>
            <div class="ext-grid">
              {#each availableExts as ext}
                <label class="ext-chip" class:selected={allowedExts.includes(ext)}>
                  <input type="checkbox" checked={allowedExts.includes(ext)} onchange={(e) => {
                    const target = e.currentTarget as HTMLInputElement;
                    if (target.checked) allowedExts = [...allowedExts, ext];
                    else allowedExts = allowedExts.filter(i => i !== ext);
                  }} />{ext}
                </label>
              {#each [] as _}<!-- spacing fix -->{/each}
              {/each}
            </div>
            <hr />
            <div class="setting-row">
              <h3>🔍 Manual Override</h3>
              <label class="checkbox-label"><input type="checkbox" bind:checked={allowManualOverride} /> Always scan manually selected files</label>
            </div>
          </div>
        </section>
      {/if}

      {#if currentReport.verdict}
        <div class="report-card" class:error={currentReport.is_error} class:success={!currentReport.is_error}>
          <div class="badge">{currentReport.is_error ? '❌ VIOLATION' : '✅ CERTIFIED'}</div>
          <div class="verdict-text">{currentReport.verdict}</div>
          <div class="reasoning-text">{currentReport.reasoning}</div>
          <button class="clear-btn" onclick={resetResults}>Clear Dashboard</button>
        </div>
      {/if}
      {#if certMsg}<div class="result-bar">{certMsg}</div>{/if}
    </div>
  </main>

  <footer class="app-footer">
    <div class="footer-powered">
      Active LLM: <span class="brand-text">{modelName || 'None'}</span> | 
      Status: <span class={isConfigured ? 'text-success' : 'text-danger'}>{isConfigured ? 'Armed' : 'Standby'}</span>
    </div>
  </footer>
</div>

<style>
  :root { font-family: 'Inter', sans-serif; --primary: #396cd8; --bg: #0a0a0a; --nav: #161616; --border: #262626; }
  .app-layout { display: flex; flex-direction: column; height: 100vh; background: var(--bg); color: #f4f4f4; }
  
  .top-bar { display: flex; justify-content: space-between; align-items: center; padding: 15px 30px; background: #000; border-bottom: 1px solid var(--border); }
  .logo-btn { background: none; border: none; color: var(--primary); font-weight: 900; font-size: 14px; letter-spacing: 2px; cursor: pointer; }
  .version-tag { font-size: 10px; opacity: 0.4; }
  
  .nav-bar { display: flex; gap: 8px; padding: 8px 25px; background: var(--nav); border-bottom: 1px solid var(--border); }
  .nav-bar button { background: transparent; border: none; color: #888; padding: 8px 16px; font-size: 12px; cursor: pointer; }
  .nav-bar button.active { color: var(--primary); background: #222; border-radius: 4px; }
  
  .progress-line { height: 2px; width: 100%; position: relative; overflow: hidden; background: #222; }
  .progress-line::after { content: ''; position: absolute; left: -50%; height: 100%; width: 50%; background: var(--primary); animation: slide 1.5s infinite; }
  @keyframes slide { from { left: -50%; } to { left: 100%; } }
  
  .scanning .view-wrapper { pointer-events: none; opacity: 0.85; }
  .content-pane { flex: 1; padding: 40px; overflow-y: auto; }
  .view-wrapper { max-width: 950px; margin: 0 auto; width: 100%; }
  
  h2 { font-size: 24px; font-weight: 800; margin-bottom: 4px; }
  .subtitle { font-size: 14px; color: #666; margin-bottom: 30px; }
  
  .welcome-card { background: #161616; padding: 30px; border-radius: 12px; border: 1px solid var(--border); margin-top: 20px; text-align: left; }
  .welcome-card.warning { border-color: #991b1b33; }
  
  .tool-box { display: flex; gap: 10px; margin-top: 20px; }
  .tool-box input { flex: 1; background: #1a1a1a; border: 1px solid #333; color: #fff; padding: 12px; border-radius: 6px; }
  
  .primary-btn { background: var(--primary); color: #fff; border: none; padding: 12px 24px; font-weight: 700; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
  .primary-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .ghost-btn { background: transparent; border: 1px solid #333; color: #888; padding: 10px 20px; border-radius: 6px; cursor: pointer; margin-top: 15px; }

  .input-action-group { display: flex; gap: 10px; align-items: center; margin-top: 5px; }
  .arm-btn { background: #1a1a1a; border: 1px solid #333; color: #555; padding: 10px 20px; border-radius: 4px; font-size: 11px; font-weight: 800; cursor: not-allowed; transition: all 0.3s; white-space: nowrap; }
  .arm-btn.active { background: var(--primary); border-color: var(--primary); color: #fff; cursor: pointer; box-shadow: 0 0 15px rgba(57, 108, 216, 0.3); }

  .dual-pane-monitor { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; height: 260px; }
  .pane { background: #161616; border: 1px solid var(--border); border-radius: 8px; padding: 12px; display: flex; flex-direction: column; text-align: left; }
  h4 { font-size: 10px; color: #555; text-transform: uppercase; margin-bottom: 10px; }
  .scroll-list { overflow-y: auto; flex: 1; font-family: monospace; font-size: 11px; }
  .file-entry { padding: 4px 0; border-bottom: 1px solid #222; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .report-card { margin-top: 40px; background: #161616; border: 1px solid var(--border); border-radius: 12px; overflow: hidden; text-align: left; }
  .report-card.success { border-left: 4px solid #10b981; }
  .report-card.error { border-left: 4px solid #ef4444; }
  .badge { background: #333; color: #fff; padding: 8px 16px; font-size: 10px; font-weight: 800; }
  .verdict-text { padding: 20px; font-weight: 800; font-family: monospace; border-bottom: 1px solid var(--border); }
  .reasoning-text { padding: 20px; color: #888; font-size: 14px; white-space: pre-wrap; }
  
  .settings-box { background: #161616; padding: 25px; border-radius: 12px; border: 1px solid var(--border); text-align: left; }
  .field-grid { display: grid; grid-template-columns: 1fr; gap: 15px; }
  .field-grid input { background: #1a1a1a; border: 1px solid #333; color: #fff; padding: 12px; border-radius: 4px; width: 100%; }
  
  .ext-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 10px; margin-top: 15px; }
  .ext-chip { border: 1px solid #333; padding: 8px; border-radius: 6px; font-size: 12px; cursor: pointer; text-align: center; }
  .ext-chip.selected { border-color: var(--primary); color: var(--primary); background: #1e3a8a33; }
  .ext-chip input { display: none; }
  
  hr { border: 0; border-top: 1px solid var(--border); margin: 25px 0; }
  .app-footer { padding: 12px 30px; background: #000; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; font-size: 10px; color: #444; }
  .brand-text { color: var(--primary); font-weight: bold; }
  .text-success { color: #10b981; }
  .text-danger { color: #ef4444; }
  .clear-btn { background: transparent; border: 1px solid #333; color: #666; padding: 8px 16px; margin: 0 20px 20px; border-radius: 4px; cursor: pointer; }
  .hint { font-size: 12px; color: #666; margin-bottom: 5px; }
</style>
