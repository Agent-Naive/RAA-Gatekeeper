<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";

  let command = $state("");
  let resultMsg = $state("");
  let isError = $state(false);

  async function audit(event: Event) {
    event.preventDefault();
    try {
      // Changed 'command' to 'commandStr' to match Rust's 'command_str'
      const result = await invoke<string>("audit_command", { commandStr: command });
      
      // Update logic to check for our specific Rust success message
      resultMsg = result;
      isError = false; 
    } catch (error) {
      // Tauri returns Rust 'Err' results into this catch block
      resultMsg = String(error);
      isError = true;
    }
  }
</script>

<main class="container">
  <h1>RAA Gatekeeper</h1>
  <p>Enter a terminal command to audit for RAA compliance.</p>

  <form class="row" onsubmit={audit}>
    <input id="command-input" placeholder="Enter terminal command..." bind:value={command} />
    <button type="submit">Audit</button>
  </form>

  {#if resultMsg}
    <div class="result-box" class:error={isError}>
      {resultMsg}
    </div>
  {/if}
</main>

<style>
:root {
  font-family: Inter, Avenir, Helvetica, Arial, sans-serif;
  font-size: 16px;
  line-height: 24px;
  font-weight: 400;
  color: #0f0f0f;
  background-color: #f6f6f6;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  -webkit-text-size-adjust: 100%;
}

.container {
  margin: 0;
  padding-top: 10vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  text-align: center;
}

.row {
  display: flex;
  justify-content: center;
}

h1 {
  text-align: center;
}

input,
button {
  border-radius: 8px;
  border: 1px solid transparent;
  padding: 0.6em 1.2em;
  font-size: 1em;
  font-weight: 500;
  font-family: inherit;
  color: #0f0f0f;
  background-color: #ffffff;
  transition: border-color 0.25s;
  box-shadow: 0 2px 2px rgba(0, 0, 0, 0.2);
}

button {
  cursor: pointer;
}

button:hover {
  border-color: #396cd8;
}
button:active {
  border-color: #396cd8;
  background-color: #e8e8e8;
}

input,
button {
  outline: none;
}

#command-input {
  margin-right: 5px;
  width: 300px;
}

.result-box {
  margin-top: 20px;
  padding: 10px;
  border-radius: 5px;
  font-weight: bold;
}

.result-box.error {
  background-color: #ffcccc;
  color: #cc0000;
}

.result-box:not(.error) {
  background-color: #ccffcc;
  color: #006600;
}

@media (prefers-color-scheme: dark) {
  :root {
    color: #f6f6f6;
    background-color: #2f2f2f;
  }

  input,
  button {
    color: #ffffff;
    background-color: #0f0f0f98;
  }
  button:active {
    background-color: #0f0f0f69;
  }

  .result-box.error {
    background-color: #cc000033;
    color: #ff6666;
  }

  .result-box:not(.error) {
    background-color: #00660033;
    color: #66cc66;
  }
}
</style>
