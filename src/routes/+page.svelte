<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  // Navigation State (using Svelte 5 Runes)
  let activeTab = $state("audit"); 

  // Audit State
  let commandInput = $state("");
  let auditMsg = $state("");
  let isAuditError = $state(false);

  // Analyze State
  let scanMsg = $state("");
  let isScanError = $state(false);

  // Certify State
  let certMsg = $state("");
  let isCertError = $state(false);

  async function handleAudit() {
    try {
      auditMsg = await invoke("audit_command", { commandStr: commandInput });
      isAuditError = false;
    } catch (err) {
      auditMsg = String(err);
      isAuditError = true;
    }
  }

  async function handleBrowseFile() {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{ name: 'RAA-Files', extensions: ['md', 'txt', 'raa', 'json'] }]
      });
      if (selected) {
        scanMsg = await invoke("scan_file_integrity", { filePath: selected });
        isScanError = false;
      }
    } catch (err) {
      scanMsg = String(err);
      isScanError = true;
    }
  }

  async function handleCertifyFolder() {
    try {
      const selectedFolder = await open({ directory: true, multiple: false });
      if (selectedFolder) {
        certMsg = await invoke("generate_manifest", { folderPath: selectedFolder });
        isCertError = false;
      }
    } catch (err) {
      certMsg = String(err);
      isCertError = true;
    }
  }
</script>

<div class="app-layout">
  <aside class="sidebar">
    <div class="brand">RAA</div>
    <button class:active={activeTab === 'audit'} onclick={() => activeTab = 'audit'}>
      Audit Command
    </button>
    <button class:active={activeTab === 'analyze'} onclick={() => activeTab = 'analyze'}>
      Analyze File
    </button>
    <button class:active={activeTab === 'certify'} onclick={() => activeTab = 'certify'}>
      Certify Project
    </button>
    <div class="version-seal">v0.1.0-ALPHA</div>
  </aside>

  <main class="content-pane">
    {#if activeTab === 'audit'}
      <h2>Shell-Check Auditor</h2>
      <div class="tool-box">
        <input 
          bind:value={commandInput} 
          placeholder="e.g. ls *.txt" 
          autocapitalize="none"
          autocorrect="off"
          spellcheck="false"
        />
        <button onclick={handleAudit}>Check Command</button>
      </div>
      {#if auditMsg}<div class="result-bar" class:error={isAuditError}>{auditMsg}</div>{/if}

    {:else if activeTab === 'analyze'}
      <h2>File Integrity Scanner</h2>
      <div class="tool-box">
        <button class="primary-btn" onclick={handleBrowseFile}>Browse & Scan File</button>
      </div>
      {#if scanMsg}<div class="result-bar" class:error={isScanError}>{scanMsg}</div>{/if}

    {:else if activeTab === 'certify'}
      <h2>Project Manifest Generator</h2>
      <div class="tool-box">
        <button class="primary-btn" onclick={handleCertifyFolder}>Select Folder & Certify</button>
      </div>
      {#if certMsg}<div class="result-bar" class:error={isCertError}>{certMsg}</div>{/if}
    {/if}
  </main>
</div>

<style>
  .app-layout { display: flex; height: 100vh; font-family: sans-serif; }
  .sidebar { width: 200px; background: #121212; color: #fff; padding: 20px; display: flex; flex-direction: column; gap: 8px; }
  .brand { font-size: 24px; font-weight: 800; margin-bottom: 30px; color: #396cd8; }
  .sidebar button { background: transparent; border: none; color: #888; text-align: left; padding: 12px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .sidebar button.active { background: #222; color: #fff; border-left: 3px solid #396cd8; }
  .content-pane { flex: 1; padding: 40px; background: #fdfdfd; color: #1a1a1a; }
  .tool-box { display: flex; gap: 10px; margin: 20px 0; justify-content: center; }
  input { flex: 1; max-width: 400px; padding: 12px; border-radius: 8px; border: 1px solid #ddd; }
  button { background: #396cd8; color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; cursor: pointer; }
  .result-bar { margin-top: 20px; padding: 15px; border-radius: 8px; font-weight: bold; background: #e6fffa; color: #234e52; }
  .result-bar.error { background: #fff5f5; color: #c53030; }
  @media (prefers-color-scheme: dark) { .content-pane { background: #1e1e1e; color: #eee; } input { background: #2a2a2a; border-color: #444; color: white; } }
</style>
