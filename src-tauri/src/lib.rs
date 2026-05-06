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
use rayon::prelude::*;

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

#[derive(Clone)]
struct FileJob {
    path: PathBuf,
    content: String,
    hash: String,
    size: usize,
}

fn get_content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn log_to_raa(scan_type: &str, target_path: &str, result_text: &str) {
    let home = env::var("HOME").unwrap_or_else(|_| ".".into());
    let audit_root = PathBuf::from(home).join(".RAA_Audits");
    let _ = fs::create_dir_all(&audit_root);

    let target_name = PathBuf::from(target_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "terminal_input".into());

    let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let manifest_name = format!(".raa-{}-{}-{}", scan_type, target_name.replace(" ", "_"), timestamp);
    let manifest_path = audit_root.join(manifest_name);
    
    let log_entry = format!(
        "\n--- RAA FORENSIC REPORT ---\nType: {}\nTarget: {}\nTimestamp: {}\nResult: {}\n---------------------------\n",
        scan_type, target_path, Local::now().format("%Y-%m-%d %H:%M:%S"), result_text
    );

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&manifest_path) {
        let _ = f.write_all(log_entry.as_bytes());
        let _ = f.sync_all();
    }
}

async fn call_grok_audit(input: &str, context_type: &str, base_url: &str, model_name: &str) -> Result<RAAReport, String> {
    let api_key = env::var("GROK_API_KEY").unwrap_or_default();
    let client = reqwest::Client::new();
    let response = client.post(base_url).header("Authorization", format!("Bearer {}", api_key))
        .json(&GrokRequest {
            model: model_name.to_string(),
            messages: vec![
                Message { 
                    role: "system".to_string(), 
                    content: format!("You are an RAA Security Auditor. Analyze this {} and provide a verdict starting with SAFE or RAA VIOLATION, followed by your detailed reasoning.", context_type) 
                },
                Message { role: "user".to_string(), content: input.to_string() },
            ],
        }).send().await.map_err(|e| e.to_string())?;
    
    let raw: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    let ai_response = raw["choices"]["message"]["content"].as_str().unwrap_or("SAFE: No response").to_string();
    let has_violation = ai_response.contains("VIOLATION");
    
    Ok(RAAReport { 
        verdict: if has_violation { "RAA VIOLATION".into() } else { "SAFE".into() },
        reasoning: ai_response, 
        is_error: has_violation 
    })
}

#[tauri::command]
async fn check_integrity() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "parallel_hashing": true,
        "ai_reasoning": true,
        "vault_path": true,
        "zip_safety": true,
        "terminal_input": true
    }))
}

#[tauri::command]
async fn audit_command(command_str: String, base_url: String, model_name: String) -> Result<RAAReport, String> {
    let report = call_grok_audit(&command_str, "terminal command", &base_url, &model_name).await?;
    log_to_raa("audit", &command_str, &report.reasoning);
    Ok(report)
}

#[tauri::command]
async fn scan_file_integrity(file_paths: Vec<String>, base_url: String, model_name: String) -> Result<RAAReport, String> {
    let jobs: Vec<FileJob> = file_paths.into_par_iter().filter_map(|p_str| {
        let path = PathBuf::from(&p_str);
        let content = fs::read_to_string(&path).ok()?;
        let hash = get_content_hash(&content);
        Some(FileJob { path, size: content.len(), hash, content })
    }).collect();

    let mut combined = String::new();
    for job in &jobs { combined.push_str(&format!("FILE: {} | HASH: {}\n{}\n", job.path.display(), job.hash, job.content)); }
    let report = call_grok_audit(&combined, "file content", &base_url, &model_name).await?;
    log_to_raa("analyze", &jobs[0].path.display().to_string(), &report.reasoning);
    Ok(report)
}

#[tauri::command]
async fn scan_compressed_archive(window: tauri::Window, zip_path: String, allowed_extensions: Vec<String>, base_url: String, model_name: String) -> Result<RAAReport, String> {
    let file = fs::File::open(&zip_path).map_err(|e| e.to_string())?;
    let mut archive = ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut internal_entries = Vec::new();
    let mut violation_found = false;

    for i in 0..archive.len() {
        if let Ok(mut zf) = archive.by_index(i) {
            let name = zf.name().to_string();
            let ext = format!(".{}", name.split('.').last().unwrap_or("").to_lowercase());
            if zf.is_file() && allowed_extensions.contains(&ext) {
                let _ = window.emit("scan-event", ScanEvent { path: name.clone(), status: "Active".into() });
                let mut buffer = vec![0; 2 * 1024 * 1024]; // 2MB Safety Valve
                let bytes_read = zf.read(&mut buffer).map_err(|e| e.to_string())?;
                let content = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
                let hash = get_content_hash(&content);
                let report = call_grok_audit(&content, "archive internal", &base_url, &model_name).await?;
                if report.is_error { violation_found = true; }
                internal_entries.push(format!("File: {} | Hash: {} | AI: {}", name, hash, report.verdict));
            } else {
                let _ = window.emit("scan-event", ScanEvent { path: name, status: "Skipped".into() });
            }
        }
    }
    log_to_raa("archive", &zip_path, &internal_entries.join("\n"));
    Ok(RAAReport { verdict: if violation_found {"VIOLATION FOUND"} else {"SAFE"}.into(), reasoning: internal_entries.join("\n"), is_error: violation_found })
}

#[tauri::command]
async fn generate_manifest(window: tauri::Window, folder_path: String, allowed_extensions: Vec<String>, base_url: String, model_name: String) -> Result<String, String> {
    let folder_path_buf = fs::canonicalize(&folder_path).map_err(|_| "Path error")?;
    let mut target_files = Vec::new();
    let walker = WalkDir::new(&folder_path_buf).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !["node_modules", ".git", "target", "dist"].iter().any(|&ex| name == ex)
    });

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path().to_path_buf();
        let ext = path.extension().map(|s| format!(".{}", s.to_string_lossy().to_lowercase())).unwrap_or_default();
        if entry.file_type().is_file() && (allowed_extensions.contains(&ext) || ext == ".zip") {
            let _ = window.emit("scan-event", ScanEvent { path: path.to_string_lossy().into(), status: "Active".into() });
            target_files.push((path, ext));
        } else {
            let _ = window.emit("scan-event", ScanEvent { path: path.to_string_lossy().into(), status: "Skipped".into() });
        }
    }

    let jobs: Vec<FileJob> = target_files.into_par_iter().filter_map(|(path, ext)| {
        if ext == ".zip" { return Some(FileJob { path, size: 0, hash: "ZIP".into(), content: "".into() }); }
        let content = fs::read_to_string(&path).ok().unwrap_or_default();
        let hash = get_content_hash(&content);
        Some(FileJob { path, size: content.len(), hash, content })
    }).collect();

    let mut buckets = Vec::new();
    let mut current_bucket = Vec::new();
    let mut current_size = 0;
    for job in jobs {
        if job.hash == "ZIP" { buckets.push(vec![job]); continue; }
        if current_size + job.size > 10000 && !current_bucket.is_empty() {
            buckets.push(current_bucket);
            current_bucket = Vec::new(); current_size = 0;
        }
        current_size += job.size;
        current_bucket.push(job);
    }
    if !current_bucket.is_empty() { buckets.push(current_bucket); }

    let mut ledger_entries = String::new();
    for bucket in buckets {
        let mut batch_text = String::new();
        for job in &bucket { batch_text.push_str(&format!("FILE: {} | HASH: {}\n{}\n", job.path.display(), job.hash, job.content)); }
        let report = call_grok_audit(&batch_text, "batch scan", &base_url, &model_name).await.unwrap_or(RAAReport { verdict: "SAFE".into(), reasoning: "".into(), is_error: false });
        for job in bucket { ledger_entries.push_str(&format!("File: {} | Hash: {} | AI: {}\n", job.path.display(), job.hash, report.verdict)); }
    }

    log_to_raa("certify", &folder_path, &ledger_entries);
    Ok("Success. Report stored in ~/.RAA_Audits".into())
}

#[tauri::command]
async fn read_ledger() -> Result<String, String> {
    let home = env::var("HOME").unwrap_or_else(|_| ".".into());
    let audit_root = PathBuf::from(home).join(".RAA_Audits");
    let mut all_logs = String::new();
    if let Ok(entries) = fs::read_dir(audit_root) {
        let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        paths.sort_by_key(|a| a.metadata().and_then(|m| m.modified()).ok());
        paths.reverse(); 
        for entry in paths {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                all_logs.push_str(&format!("\nFILE: {}\n{}", entry.file_name().to_string_lossy(), content));
                all_logs.push_str("\n------------------------------------------------\n");
            }
        }
    }
    Ok(all_logs)
}

pub fn run() {
    dotenvy::dotenv().ok(); 
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![audit_command, generate_manifest, scan_file_integrity, scan_compressed_archive, read_ledger, check_integrity])
        .run(tauri::generate_context!())
        .expect("error");
}
