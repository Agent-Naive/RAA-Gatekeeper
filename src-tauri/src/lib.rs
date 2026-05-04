use std::fs::{self, OpenOptions};
use std::io::{Write, Read};
use std::env;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use chrono::Local;
use zip::ZipArchive; 

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
    let api_key = env::var("GROK_API_KEY").map_err(|_| "RAA Error: API Key missing")?.trim().to_string();
    let client = reqwest::Client::builder().user_agent("RAA-Gatekeeper/1.0").build().map_err(|e| format!("Client Error: {}", e))?;

    let response = client
        .post("https://api.x.ai/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&GrokRequest {
            model: "grok-4.3".to_string(), // Verify if 'grok-4.3' is the correct model identifier for xAI API as of May 2026
            messages: vec![
                Message { 
                    role: "system".to_string(), 
                    content: format!("You are an RAA Security Auditor. Analyze this {} for threats. Respond ONLY with 'SAFE' or a warning starting with 'RAA VIOLATION:'.", context_type) 
                },
                Message { role: "user".to_string(), content: input.to_string() },
            ],
        })
        .send()
        .await
        .map_err(|e| format!("Network Error: {}", e))?;

    let raw_text = response.text().await.map_err(|e| format!("Read Error: {}", e))?;
    let data: serde_json::Value = serde_json::from_str(&raw_text).map_err(|e| format!("JSON Error: {}", e))?;
    
    let choice = data["choices"].get(0).ok_or("No choices")?;
    let verdict = choice["message"]["content"].as_str().unwrap_or("SAFE").to_string();
    let reasoning = choice["message"]["reasoning_content"].as_str().unwrap_or("Analysis complete.").to_string();
    
    let is_error = verdict.contains("VIOLATION");
    Ok(RAAReport { verdict, reasoning, is_error })
}

// --- NEW TAURI COMMAND: ARCHIVE EXTRACTOR ---
#[tauri::command]
async fn scan_compressed_archive(zip_path: String) -> Result<RAAReport, String> {
    let file = fs::File::open(&zip_path).map_err(|_| "RAA Error: Could not open ZIP")?;
    let mut archive = ZipArchive::new(file).map_err(|_| "RAA Error: Invalid ZIP format")?;
    
    let mut final_verdict = String::new();
    let mut final_reasoning = String::new();
    let mut has_violation = false;

    for i in 0..archive.len() {
        let mut zip_file = archive.by_index(i).map_err(|_| "Error reading index")?;
        if zip_file.is_file() {
            let mut content = String::new();
            // Only try to read text files (skip binary/images)
            if zip_file.read_to_string(&mut content).is_ok() {
                let report = call_grok_audit(&content, "archived file content").await?;
                final_verdict.push_str(&format!("[{}]: {}\n", zip_file.name(), report.verdict));
                final_reasoning.push_str(&format!("--- Inside ZIP: {} ---\n{}\n\n", zip_file.name(), report.reasoning));
                if report.is_error { has_violation = true; }
            }
        }
    }

    Ok(RAAReport { 
        verdict: if final_verdict.is_empty() { "No readable text files in ZIP".to_string() } else { final_verdict }, 
        reasoning: final_reasoning, 
        is_error: has_violation 
    })
}

// --- STANDARD COMMANDS ---
#[tauri::command]
async fn audit_command(command_str: String) -> Result<RAAReport, String> {
    call_grok_audit(&command_str, "terminal command").await
}

#[tauri::command]
async fn scan_file_integrity(file_paths: Vec<String>) -> Result<RAAReport, String> {
    let mut final_verdict = String::new();
    let mut final_reasoning = String::new();
    let mut has_violation = false;

    for path_str in file_paths {
        let target_path = fs::canonicalize(&path_str).map_err(|_| "Path error")?;
        let content = fs::read_to_string(&target_path).map_err(|_| "Read error")?;
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
    let manifest_name = if append_mode { ".raa".into() } else { format!(".raa-session-{}", Local::now().format("%Y%m%d-%H%M%S")) };
    let folder_path_buf = fs::canonicalize(&folder_path).map_err(|_| "Path error")?;
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
    let mut file = OpenOptions::new().create(true).append(true).open(&manifest_path).map_err(|e| format!("Error: {}", e))?;
    file.write_all(session_block.as_bytes()).map_err(|e| format!("Error: {}", e))?;
    Ok(format!("Certified: {} generated.", manifest_name))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    dotenvy::dotenv().ok(); 
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            audit_command, 
            scan_file_integrity, 
            generate_manifest,
            scan_compressed_archive // <--- NEW
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
