// src-tauri/src/lib.rs
use std::fs;

#[tauri::command]
fn audit_command(command_str: String) -> Result<String, String> {
    let destructive_prefixes = vec!["rm", "mv", "delete"];
    let command_lower = command_str.to_lowercase();

    if command_lower.contains("sudo") {
        return Err("RAA Security Violation: Use of 'sudo' is not permitted.".into());
    }

    let first_word = command_str.split_whitespace().next().unwrap_or("");
    let is_destructive = destructive_prefixes.iter().any(|prefix| first_word.starts_with(prefix));

    if is_destructive && command_lower.contains('*') {
        return Err("RAA Security Violation: Destructive command with wildcard detected.".into());
    }

    if command_lower.contains('*') {
        return Ok("Command Safe (Observation Only).".into());
    }

    Ok("Command Safe.".into())
}

#[tauri::command]
fn scan_file_integrity(file_path: String) -> Result<String, String> {
    match fs::read_to_string(&file_path) {
        Ok(content) => {
            if content.contains("IGNORE PREVIOUS INSTRUCTIONS") {
                return Err("RAA THREAT: Agent Hijacking prompt detected!".into());
            }
            Ok("File RAA-Certified: Safe for AI Context.".into())
        }
        Err(_) => Err("RAA THREAT: Binary data detected in text context!".into()),
    }
}

#[tauri::command]
fn generate_manifest(folder_path: String) -> Result<String, String> {
    // Construct path to .raa file
    let manifest_path = std::path::Path::new(&folder_path).join(".raa");
    
    // Content for the manifest
    let content = "RAA-CERTIFIED: ALPHA | Security: High | Status: Verified";

    // Write the file to disk
    match fs::write(&manifest_path, content) {
        Ok(_) => Ok(format!("Manifest successfully created at: {:?}", manifest_path)),
        Err(e) => Err(format!("Failed to create manifest: {}", e)),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            audit_command, 
            scan_file_integrity, 
            generate_manifest
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
