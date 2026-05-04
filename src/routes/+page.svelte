<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let activeTab = $state("audit"); 
  let isProcessing = $state(false); 

  let currentReport = $state({ verdict: "", reasoning: "", is_error: false });
  let commandInput = $state("");
  let certMsg = $state("");
  let appendMode = $state(true);

  function resetResults() {
    currentReport = { verdict: "", reasoning: "", is_error: false };
    certMsg = "";
  }

  async function handleAudit(e?: Event) {
    if (e) e.preventDefault();
    if (!commandInput.trim() || isProcessing) return;
    resetResults();
    isProcessing = true;
    try {
      currentReport = await invoke("audit_command", { commandStr: commandInput });
    } catch (err) { 
      currentReport = { verdict: "System Error", reasoning: String(err), is_error: true };
    } finally { isProcessing = false; }
  }

  async function handleBrowseFile() {
    resetResults();
    try {
      const selected = await open({ 
        multiple: true, 
        directory: false,
        filters: [{ name: 'RAA-Files', extensions: ['md', 'txt', 'raa', 'json'] }]
      });

      if (selected) {
        isProcessing = true;
        // Ensure it's always an array for the Rust "file_paths: Vec<String>" command
        const paths = Array.isArray(selected) ? selected : [selected];
        currentReport = await invoke("scan_file_integrity", { filePaths: paths });
      }
    } catch (err) { 
      currentReport = { verdict: "System Error", reasoning: String(err), is_error: true };
    } finally { isProcessing = false; }
  }

  async function handleCertifyFolder() {
    resetResults();
    try {
      const selectedFolder = await open({ directory: true, multiple: false });
      if (selectedFolder) {
        isProcessing = true;
        certMsg = await invoke("generate_manifest", { folderPath: selectedFolder, appendMode: appendMode });
      }
    } catch (err) { certMsg = String(err); } finally { isProcessing = false; }
  }
</script>

<div class="app-layout">
  <header class="top-bar">
    <div class="logo">🛡️ RAA Gatekeeper</div>
  </header>

  <div class="main-container">
    <aside class="sidebar">
      <button class:active={activeTab === 'audit'} onclick={() => {activeTab = 'audit'; resetResults();}}>📟 Audit Command Line</button>
      <button class:active={activeTab === 'analyze'} onclick={() => {activeTab = 'analyze'; resetResults();}}>🔍 Analyze File/Folder</button>
      <button class:active={activeTab === 'certify'} onclick={() => {activeTab = 'certify'; resetResults();}}>🔏 Certify Project</button>
      <div class="version-seal">v0.1.0-ALPHA</div>
    </aside>

    <main class="content-pane">
      {#if isProcessing}
        <div class="loader-overlay"><div class="spinner"></div><p>RAA Analysis in Progress...</p></div>
      {/if}

      <div class="view-wrapper">
        {#if activeTab === 'audit'}
          <h2>Audit Command Line</h2>
          <form class="tool-box" onsubmit={handleAudit}>
            <!-- svelte-ignore a11y_autofocus -->
            <input 
              bind:value={commandInput} 
              placeholder="e.g. ls *.txt" 
              autocapitalize="none" 
              autocorrect="off" 
              spellcheck="false" 
              autofocus 
            />
            <button type="submit" disabled={isProcessing}>Audit</button>
          </form>

        {:else if activeTab === 'analyze'}
          <h2>Analyze File/Folder</h2>
          <div class="tool-box-vertical">
            <button class="primary-btn" onclick={handleBrowseFile} disabled={isProcessing}>Browse & Scan File(s)</button>
            <p class="hint">(Tip: You can select multiple files using <strong>Cmd+Click</strong>)</p>
          </div>

        {:else if activeTab === 'certify'}
          <h2>Certify Project</h2>
          <div class="tool-box-vertical">
            <label class="checkbox-label"><input type="checkbox" bind:checked={appendMode} /> Append to Ledger (.raa)</label>
            <button class="primary-btn" onclick={handleCertifyFolder} disabled={isProcessing}>Select Folder & Certify</button>
          </div>
        {/if}

        {#if currentReport.verdict}
          <div class="report-card" class:error={currentReport.is_error}>
            <div class="badge">{currentReport.is_error ? '❌ VIOLATION DETECTED' : '✅ RAA CERTIFIED'}</div>
            <div class="verdict-text">{currentReport.verdict}</div>
            <div class="reasoning-header">SECURITY CONTEXT:</div>
            <div class="reasoning-text">{currentReport.reasoning}</div>
          </div>
        {/if}

        {#if certMsg}<div class="result-bar success">{certMsg}</div>{/if}
      </div>
    </main>
  </div>
</div>

<style>
  :root { font-family: 'Inter', system-ui, sans-serif; }
  .app-layout { display: flex; flex-direction: column; height: 100vh; overflow: hidden; background: #fdfdfd; }
  .top-bar { height: 60px; background: #000; display: flex; align-items: center; justify-content: center; border-bottom: 1px solid #333; flex-shrink: 0; }
  .logo { color: #396cd8; font-size: 20px; font-weight: 800; letter-spacing: 1px; }
  .main-container { display: flex; flex: 1; overflow: hidden; }
  .sidebar { width: 260px; background: #121212; color: #fff; padding: 20px; display: flex; flex-direction: column; gap: 8px; border-right: 1px solid #333; }
  .sidebar button { background: transparent; border: none; color: #888; text-align: left; padding: 14px; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; }
  .sidebar button.active { background: #1a1a1a; color: #fff; box-shadow: inset 3px 0 0 #396cd8; }
  .content-pane { flex: 1; display: flex; align-items: center; justify-content: center; position: relative; overflow-y: auto; color: #1a1a1a; }
  .view-wrapper { width: 100%; max-width: 700px; padding: 40px; display: flex; flex-direction: column; align-items: center; text-align: center; }
  .tool-box { display: flex; gap: 10px; margin: 20px 0; width: 100%; justify-content: center; }
  .tool-box-vertical { display: flex; flex-direction: column; gap: 12px; align-items: center; width: 100%; }
  input { flex: 1; max-width: 400px; padding: 14px; border-radius: 8px; border: 1px solid #ddd; font-family: monospace; }
  button { background: #396cd8; color: white; border: none; padding: 14px 28px; border-radius: 8px; font-weight: bold; cursor: pointer; }
  .report-card { width: 100%; margin-top: 30px; border-radius: 12px; background: #fff; border: 1px solid #ddd; overflow: hidden; text-align: left; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); }
  .badge { padding: 12px; font-weight: 800; font-size: 11px; text-align: center; color: #fff; background: #48bb78; }
  .error .badge { background: #f56565; }
  .verdict-text { padding: 20px; font-weight: 800; border-bottom: 1px solid #eee; font-family: monospace; font-size: 15px; white-space: pre-line; }
  .reasoning-header { padding: 15px 20px 0 20px; font-size: 11px; color: #a0aec0; font-weight: 800; }
  .reasoning-text { padding: 5px 20px 20px 20px; font-size: 14px; line-height: 1.6; color: #4a5568; font-style: italic; white-space: pre-wrap; }
  .result-bar { width: 100%; margin-top: 20px; padding: 15px; border-radius: 8px; font-weight: bold; background: #ebf8ff; color: #2b6cb0; font-family: monospace; }
  .loader-overlay { position: absolute; inset: 0; background: rgba(255,255,255,0.9); display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 10; }
  .spinner { width: 40px; height: 40px; border: 4px solid #f3f3f3; border-top: 4px solid #396cd8; border-radius: 50%; animation: spin 1s linear infinite; }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  .version-seal { margin-top: auto; font-size: 10px; opacity: 0.3; text-align: center; }
  @media (prefers-color-scheme: dark) {
    .app-layout { background: #121212; }
    .content-pane { color: #eee; }
    .report-card { background: #1a1a1a; border-color: #333; }
    .verdict-text { color: #edf2f7; border-color: #333; }
    .reasoning-text { color: #cbd5e0; }
    .loader-overlay { background: rgba(18,18,18,0.9); }
    input { background: #222; border-color: #444; color: white; }
  }
</style>
