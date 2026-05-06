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
    let currentReport = $state({ verdict: "", reasoning: "", target_name: "", is_error: false });
    let certMsg = $state("");
    let commandInput = $state("");
    let ledgerContent = $state("");
    let integrityReport = $state<any>(null);
  
    let allowedExts = $state([".rs", ".ts", ".js", ".py", ".yml", ".zip"]); 
    let activeFiles = $state<string[]>([]);
    let skippedFiles = $state<string[]>([]);
    let activeScrollContainer: HTMLElement | undefined = $state();
    let skippedScrollContainer: HTMLElement | undefined = $state();
  
    async function scrollToBottom(el: HTMLElement | undefined) {
      if (el) { await tick(); el.scrollTop = el.scrollHeight; }
    }
  
    onMount(() => {
      isDev = window.location.hostname === 'localhost';
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
      return () => { if (unlisten) unlisten(); };
    });
  
    function resetResults() {
      currentReport = { verdict: "", reasoning: "", target_name: "", is_error: false };
      certMsg = ""; activeFiles = []; skippedFiles = [];
    }
  
    function getReportSegments(text: string) {
      if (!text) return [];
      return text.split(/(?=\n\d+\.|\nItem\s\d+:|---\n)/g).filter(s => s.trim().length > 5);
    }
  
    function highlightSegment(text: string) {
      return text
        .replace(/([\/\w\-_.]+\.(?:md|rs|ts|js|py|yml|zip|toml|json|txt|sh))/gi, '<span class="path-text">$1</span>')
        .replace(/(SAFE|CERTIFIED|CLEAN)/g, '<span class="text-success">$1</span>')
        .replace(/(VIOLATION|THREAT|DANGER|MALICIOUS)/g, '<span class="text-danger">$1</span>');
    }
  
    async function handleAudit(e?: Event) {
      if (e) e.preventDefault();
      if (!commandInput.trim()) return;
      resetResults(); isProcessing = true;
      try { currentReport = await invoke("audit_command", { commandStr: commandInput, baseUrl, modelName }); } 
      catch (err) { currentReport = { verdict: "Error", reasoning: String(err), target_name: "Audit", is_error: true }; }
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
      } catch (err) { currentReport = { verdict: "Error", reasoning: String(err), target_name: "Files", is_error: true }; }
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
      } catch (err) { currentReport = { verdict: "Error", reasoning: String(err), target_name: "Archive", is_error: true }; }
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
  
    async function loadLedger() { activeTab = 'ledger'; ledgerContent = await invoke("read_ledger"); }
    async function runIntegrityCheck() { activeTab = 'integrity'; integrityReport = await invoke("check_integrity"); }
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
              <input type="text" bind:value={commandInput} placeholder="e.g. ls -la" autocapitalize="off" autocorrect="off" spellcheck="false" autocomplete="off" class="terminal-input" />
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
                  <div class="check-item"><span>📡 Technical Reasoning:</span> <span class="check">{integrityReport.ai_reasoning ? '✅' : '❌'}</span></div>
                  <div class="check-item"><span>🔐 Terminal Input Lock:</span> <span class="check">{integrityReport.terminal_input_lock ? '✅' : '❌'}</span></div>
                  <div class="check-item"><span>📦 ZIP Safety Valve:</span> <span class="check">{integrityReport.zip_safety ? '✅' : '❌'}</span></div>
                  <div class="check-item"><span>📁 Hidden Vault Path:</span> <span class="check">{integrityReport.vault_path ? '✅' : '❌'}</span></div>
                  <div class="check-item"><span>💾 Disk-First Verification:</span> <span class="check">{integrityReport.disk_first_verification ? '✅' : '❌'}</span></div>
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
  
        {#if currentReport.verdict}
          <div class="forensic-status-overlay">
            <div class="report-card" class:error={currentReport.is_error}>
              <div class="badge">
                {currentReport.is_error ? '❌ VIOLATION DETECTED' : '✅ CERTIFIED'}
                <span class="target-label">| TARGET: {currentReport.target_name}</span>
              </div>
              <div class="reasoning-container">
                {#each getReportSegments(currentReport.reasoning) as segment}
                  <div class="segment-card" class:segment-error={segment.toUpperCase().includes('VIOLATION')}>
                    <div class="segment-content">{@html highlightSegment(segment)}</div>
                  </div>
                {/each}
              </div>
              <button class="clear-btn" onclick={resetResults}>Dismiss Forensic Report</button>
            </div>
          </div>
        {/if}
  
        {#if certMsg}
          <div class="forensic-status-overlay">
            <div class="mission-success-toast"><span>{certMsg}</span><button class="toast-close" onclick={() => certMsg = ""}>×</button></div>
          </div>
        {/if}
      </div>
    </main>
  
    <footer class="app-footer">
      <div class="footer-stats">
        <span class="stat-item">LLM: <span class="brand-text">{modelName || 'None'}</span></span>
        <span class="stat-divider">|</span>
        <span class="stat-item">Status: <span class={isConfigured ? 'text-success' : 'text-danger'}>{isConfigured ? 'Armed' : 'Standby'}</span></span>
      </div>
    </footer>
  </div>
  
  <style>
    :root { font-family: 'Inter', sans-serif; --primary: #396cd8; --bg: #0a0a0a; --nav: #161616; --border: #262626; }
    .app-layout { display: flex; flex-direction: column; height: 100vh; background: var(--bg); color: #f4f4f4; overflow: hidden; }
    .top-bar { display: flex; justify-content: space-between; align-items: center; padding: 15px 30px; background: #000; border-bottom: 1px solid var(--border); flex-shrink: 0; }
    .logo-btn { background: none; border: none; color: var(--primary); font-weight: 900; font-size: 14px; letter-spacing: 2px; cursor: pointer; text-align: left; }
    .nav-bar { display: flex; gap: 8px; padding: 8px 25px; background: var(--nav); border-bottom: 1px solid var(--border); flex-shrink: 0; }
    .nav-bar button { background: transparent; border: none; color: #888; padding: 8px 16px; font-size: 12px; cursor: pointer; }
    .nav-bar button.active { color: var(--primary); background: #222; border-radius: 4px; }
    .progress-line { height: 2px; width: 100%; position: relative; overflow: hidden; background: #222; flex-shrink: 0; }
    .progress-line::after { content: ''; position: absolute; left: -50%; height: 100%; width: 50%; background: var(--primary); animation: slide 1.5s infinite; }
    @keyframes slide { from { left: -50%; } to { left: 100%; } }
    .content-pane { flex: 1; padding: 40px; overflow-y: auto; position: relative; }
    .view-wrapper { max-width: 1000px; margin: 0 auto; width: 100%; display: flex; flex-direction: column; min-height: 100%; padding-bottom: 150px; }
    .welcome-card { background: #161616; padding: 30px; border-radius: 12px; border: 1px solid var(--border); margin-top: 20px; text-align: left; }
    .tool-box { display: flex; gap: 10px; margin-top: 20px; }
    .tool-box input { flex: 1; background: #1a1a1a; border: 1px solid #333; color: #fff; padding: 12
  