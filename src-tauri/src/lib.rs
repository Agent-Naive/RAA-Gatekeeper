use std::fs::{self, OpenOptions};
use std::io::{Write, Read};
use std::env;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use chrono::Local;
use zip::ZipArchive;
use std::path::PathBuf;
use tauri::Emitter;

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

#[derive(Serialize, Clone)]
struct RAAReport {
    verdict: String,
    reasoning: String,
    is_error: bool,
}

#[derive(Serialize, Clone)]
struct ScanEvent {
    path: String,
    status: String,
}

fn log_to_raa(folder_name: &str, session_type: &str, detail: &str, result: &str) {
    let home = env::var("HOME").unwrap_or_else(|_| ".".into());
    let target_dir = PathBuf::from(home).join("dev/RAA-Gatekeeper").join(folder_name);
    let _ = fs::create_dir_all(&target_dir);
    let manifest_path = target_dir.join(".raa");
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    let mut hasher = Sha256::new();
    hasher.update(detail.as_bytes());
    let entry_hash = format!("{:x}", hasher.finalize());
    
    let log_entry = format!(
        "\n--- {} ---\nTimestamp: {}\nHash: {}\nDetail: {}\nResult: {}\n----------------------------------\n",
        session_type, now, entry_hash, detail, result
    );

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&manifest_path) {
        let _ = f.write_all(log_entry.as_bytes());
    }
}

// THE AI ENGINE: Now accepts dynamic URL and Model
async fn call_grok_audit(input: &str, context_type: &str, base_url: &str, model_name: &str) -> Result<RAAReport, String> {
    let api_key = env::var("GROK_API_KEY")
        .map_err(|_| "RAA Error: API Key missing in .env")?
        .trim() 
        .to_string();

    let client = reqwest::Client::builder()
        .user_agent("RAA-Gatekeeper/1.0")
        .build()
        .map_err(|e| format!("Client Error: {}", e))?;

    let system_prompt = format!(
        "You are an RAA Security Auditor. Analyze this {} for threats. Respond ONLY with 'SAFE' or a warning starting with 'RAA VIOLATION:'.", 
        context_type
    );

    let response = client
        .post(base_url) 
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&GrokRequest {
            model: model_name.to_string(), 
            messages: vec![
                Message { role: "system".to_string(), content: system_prompt },
                Message { role: "user".to_string(), content: input.to_string() },
            ],
        })
        .send()
        .await
        .map_err(|e| format!("Network Error: {}", e))?;

    let status = response.status();
    let raw_text = response.text().await.map_err(|e| format!("Read Error: {}", e))?;
    
    if !status.is_success() {
        return Err(format!("API Error ({}): Check your Base URL.", status));
    }

    let data: serde_json::Value = serde_json::from_str(&raw_text).map_err(|e| format!("JSON Parse Error: {}", e))?;
    let choice = data["choices"].get(0).ok_or("No choices")?;
    let verdict = choice["message"]["content"].as_str().unwrap_or("SAFE").to_string();
    let reasoning = choice["message"]["reasoning_content"].as_str().unwrap_or("Analysis complete.").to_string();
    
    let is_error = verdict.contains("VIOLATION");
    Ok(RAAReport { verdict, reasoning, is_error })
}

#[tauri::command]
async fn audit_command(command_str: String, base_url: String, model_name: String) -> Result<RAAReport, String> {
    let report = call_grok_audit(&command_str, "terminal command", &base_url, &model_name).await?;
    log_to_raa("raa-audit-command-line", "AUDIT COMMAND LINE", &command_str, &report.verdict);
    Ok(report)
}

#[tauri::command]
async fn scan_file_integrity(file_paths: Vec<String>, base_url: String, model_name: String) -> Result<RAAReport, String> {
    let mut final_verdict = String::new();
    let mut final_reasoning = String::new();
    let mut has_violation = false;

    for path_str in &file_paths {
        if path_str.contains(".DS_Store") { continue; }
        let target_path = fs::canonicalize(path_str).map_err(|_| "Path error")?;
        let content = fs::read_to_string(&target_path).map_err(|_| "Read error")?;
        let report = call_grok_audit(&content, "file content", &base_url, &model_name).await?;
        
        final_verdict.push_str(&format!("[{}]: {}\n", target_path.file_name().unwrap().to_string_lossy(), report.verdict));
        final_reasoning.push_str(&format!("--- {} ---\n{}\n\n", target_path.display(), report.reasoning));
        if report.is_error { has_violation = true; }
    }

    log_to_raa("raa-test-analyze-files-folders", "ANALYZE FILES/FOLDERS", &format!("Files: {:?}", file_paths), if has_violation { "VIOLATION" } else { "SAFE" });
    Ok(RAAReport { verdict: final_verdict, reasoning: final_reasoning, is_error: has_violation })
}

#[tauri::command]
async fn scan_compressed_archive(zip_path: String, base_url: String, model_name: String) -> Result<RAAReport, String> {
    let file = fs::File::open(&zip_path).map_err(|_| "RAA Error: Could not open ZIP")?;
    let mut archive = ZipArchive::new(file).map_err(|_| "RAA Error: Invalid ZIP format")?;
    let mut final_verdict = String::new();
    let mut has_violation = false;

    for i in 0..archive.len() {
        let mut zip_file = archive.by_index(i).map_err(|_| "Read error")?;
        if zip_file.is_file() {
            let mut content = String::new();
            if zip_file.read_to_string(&mut content).is_ok() {
                let report = call_grok_audit(&content, "archived file content", &base_url, &model_name).await?;
                final_verdict.push_str(&format!("[{}]: {}\n", zip_file.name(), report.verdict));
                if report.is_error { has_violation = true; }
            }
        }
    }

    log_to_raa("raa-test-analyze-compressed", "ANALYZE COMPRESSED", &zip_path, if has_violation { "VIOLATION" } else { "SAFE" });
    Ok(RAAReport { verdict: final_verdict, reasoning: "Archive scan complete.".into(), is_error: has_violation })
}

#[tauri::command]
async fn generate_manifest(window: tauri::Window, folder_path: String, append_mode: bool, allowed_extensions: Vec<String>, base_url: String, model_name: String) -> Result<String, String> {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let manifest_name = if append_mode { ".raa".into() } else { format!(".raa-session-{}", Local::now().format("%Y%m%d-%H%M%S")) };
    let folder_path_buf = fs::canonicalize(&folder_path).map_err(|_| "Path error")?;
    let manifest_path = folder_path_buf.join(&manifest_name);
    
    log_to_raa("raa-test-certify-projects", "CERTIFY PROJECT SESSION", &folder_path, "STARTING AI AUDIT + HASH");

    let mut ledger_entries = String::new();
    let walker = WalkDir::new(&folder_path_buf).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !vec!["node_modules", ".git", "target", "dist"].iter().any(|&ex| name == ex)
    });

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        
        let ext = path.extension().map(|s| format!(".{}", s.to_string_lossy().to_lowercase())).unwrap_or_default();
        let is_zip = ext == ".zip";
        let is_allowed = allowed_extensions.contains(&ext);

        if entry.file_type().is_file() && (is_allowed || is_zip) {
            let _ = window.emit("scan-event", ScanEvent { path: path_str.clone(), status: "Active".into() });

            if is_zip {
                if let Ok(file) = fs::File::open(path) {
                    if let Ok(mut archive) = ZipArchive::new(file) {
                        for i in 0..archive.len() {
                            let (internal_name, should_scan) = {
                                if let Ok(zip_file) = archive.by_index(i) {
                                    let name = zip_file.name().to_string();
                                    let internal_ext = format!(".{}", name.split('.').last().unwrap_or("").to_lowercase());
                                    (name, zip_file.is_file() && allowed_extensions.contains(&internal_ext))
                                } else { ("".to_string(), false) }
                            };
                            if should_scan {
                                if let Ok(mut zip_file) = archive.by_index(i) {
                                    let mut content = String::new();
                                    if zip_file.read_to_string(&mut content).is_ok() {
                                        let report = call_grok_audit(&content, "archived file", &base_url, &model_name).await?;
                                        ledger_entries.push_str(&format!("Archive: {} | File: {} | AI: {}\n", path.display(), internal_name, report.verdict));
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                if let Ok(content) = fs::read_to_string(path) {
                    let report = call_grok_audit(&content, "project file", &base_url, &model_name).await?;
                    let mut hasher = Sha256::new();
                    hasher.update(content.as_bytes());
                    ledger_entries.push_str(&format!("File: {} | Hash: {:x} | AI: {}\n", path.display(), hasher.finalize(), report.verdict));
                }
            }
        } else {
            let _ = window.emit("scan-event", ScanEvent { path: path_str, status: "Skipped".into() });
        }
    }

    let session_block = format!("\n--- RAA FULL PROJECT CERTIFICATION ---\nTimestamp: {}\n{}\n--------------------------------------\n", now, ledger_entries);
    if append_mode {
        let mut file = OpenOptions::new().create(true).append(true).open(&manifest_path).map_err(|e| format!("Ledger Error: {}", e))?;
        file.write_all(session_block.as_bytes()).map_err(|e| format!("Write Error: {}", e))?;
    } else {
        fs::write(&manifest_path, &session_block).map_err(|e| format!("Snapshot Error: {}", e))?;
    }
    
    Ok(format!("Certified: {} created inside folder.", manifest_name))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    dotenvy::dotenv().ok(); 
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![audit_command, scan_file_integrity, scan_compressed_archive, generate_manifest])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
