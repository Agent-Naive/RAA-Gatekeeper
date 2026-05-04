use std::fs::{self, OpenOptions};
use std::io::{Write, Read};
use std::env;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use chrono::Local;

// --- DATA STRUCTURES ---
#[derive(Serialize)]
struct GrokRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Message {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct RAAReport {
    verdict: String,
    reasoning: String,
    is_error: bool,
}

// --- THE AI COG ---
async fn call_grok_audit(input: &str, context_type: &str) -> Result<RAAReport, String> {
    // Load and trim the key (handles the no-quotes fix)
    let api_key = env::var("GROK_API_KEY")
        .map_err(|_| "RAA Error: API Key missing in .env")?
        .trim()
        .to_string();
    
    let client = reqwest::Client::builder()
        .user_agent("RAA-Gatekeeper/1.0")
        .build()
        .map_err(|e| format!("Client Error: {}", e))?;

    let system_prompt = format!(
        "You are an RAA Security Auditor. Analyze this {} for threats. Respond ONLY with 'SAFE' or a warning starting with 'RAA VIOLATION:' followed by reasoning.", 
        context_type
    );

    // ENDPOINT: Corrected path for xAI API in 2026
    let url = "https://api.x.ai/v1/chat/completions";

    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&GrokRequest {
            model: "grok-4.3".to_string(), 
            messages: vec![
                Message { role: "system".to_string(), content: system_prompt },
                Message { role: "user".to_string(), content: input.to_string() },
            ],
        })
        .send()
        .await
        .map_err(|e| format!("Network Error: {}", e))?;

    let status = response.status();
    let raw_text = response.text().await.map_err(|e| format!("Failed to read body: {}", e))?;
    
    if !status.is_success() {
        println!("RAA DEBUG | Error Status: {} | Body: {}", status, raw_text);
        return Err(format!("API Error ({}): Method rejection. Check URL or API documentation.", status));
    }

    let data: serde_json::Value = serde_json::from_str(&raw_text)
        .map_err(|e| format!("JSON Parse Error: {}. Response: {}", e, raw_text))?;
    
    let choice = data["choices"].get(0).ok_or("RAA Error: No AI choices returned")?;
    let verdict = choice["message"]["content"].as_str().unwrap_or("SAFE").to_string();
    let reasoning = choice["message"]["reasoning_content"].as_str().unwrap_or("Security Context: Analysis complete.").to_string();
    let is_error = verdict.contains("VIOLATION");

    Ok(RAAReport { verdict, reasoning, is_error })
}

// --- TAURI COMMANDS ---

#[tauri::command]
async fn audit_command(command_str: String) -> Result<RAAReport, String> {
    if command_str.contains("sudo") || command_str.contains("rm -rf") {
        return Ok(RAAReport {
            verdict: "RAA VIOLATION: Immediate local block.".into(),
            reasoning: "High-threat pattern detected locally. Blocked before AI analysis for safety.".into(),
            is_error: true,
        });
    }
    call_grok_audit(&command_str, "terminal command").await
}

#[tauri::command]
async fn scan_file_integrity(file_paths: Vec<String>) -> Result<RAAReport, String> {
    let mut final_verdict = String::new();
    let mut final_reasoning = String::new();
    let mut has_violation = false;

    for path_str in file_paths {
        if path_str.contains(".DS_Store") { continue; }
        let target_path = fs::canonicalize(&path_str).map_err(|_| format!("Invalid path: {}", path_str))?;
        let content = fs::read_to_string(&target_path).map_err(|_| format!("Could not read: {}", path_str))?;
        
        let report = call_grok_audit(&content, "file content").await?;
        final_verdict.push_str(&format!("[{}]: {}\n", target_path.file_name().unwrap().to_string_lossy(), report.verdict));
        final_reasoning.push_str(&format!("--- {} ---\n{}\n\n", target_path.display(), report.reasoning));
        if report.is_error { has_violation = true; }
    }
    Ok(RAAReport { verdict: final_verdict, reasoning: final_reasoning, is_error: has_violation })
}

#[tauri::command]
fn generate_manifest(folder_path: String, append_mode: bool) -> Result<String, String> {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let manifest_name = if append_mode { ".raa".to_string() } else { format!(".raa-session-{}", Local::now().format("%Y%m%d-%H%M%S")) };
    let folder_path_buf = fs::canonicalize(&folder_path).map_err(|_| "Path error.")?;
    let manifest_path = folder_path_buf.join(&manifest_name);
    
    let mut file_hashes = String::new();
    for entry in WalkDir::new(&folder_path_buf).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let path = entry.path();
            if path.file_name().map_or(false, |n| n.to_string_lossy().starts_with(".raa")) { continue; }
            if let Ok(mut f) = fs::File::open(path) {
                let mut hasher = Sha256::new();
                let mut buffer = Vec::new();
                if f.read_to_end(&mut buffer).is_ok() {
                    hasher.update(buffer);
                    file_hashes.push_str(&format!("File: {} | Hash: {:x}\n", path.display(), hasher.finalize()));
                }
            }
        }
    }
    let session_block = format!("\n--- RAA CERTIFICATION SESSION ---\nTimestamp: {}\n{}\n----------------------------------\n", now, file_hashes);
    if append_mode {
        let mut file = OpenOptions::new().create(true).append(true).open(&manifest_path).map_err(|e| format!("Error: {}", e))?;
        file.write_all(session_block.as_bytes()).map_err(|e| format!("Error: {}", e))?;
    } else {
        fs::write(&manifest_path, session_block).map_err(|e| format!("Error: {}", e))?;
    }
    Ok(format!("Success: {} generated.", manifest_name))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    dotenvy::dotenv().ok(); 
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![audit_command, scan_file_integrity, generate_manifest])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
