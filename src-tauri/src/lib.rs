#[tauri::command]
fn audit_command(command_str: String) -> Result<String, String> {
    // RAA Logic: Identify destructive or unauthorized command patterns
    let destructive_prefixes = vec!["rm", "mv", "delete"];
    let command_lower = command_str.to_lowercase();

    // Check for sudo usage - always a violation
    if command_lower.contains("sudo") {
        return Err("RAA Security Violation: Use of 'sudo' is not permitted.".into());
    }

    // Split the command string to check the first word
    let first_word = command_str.split_whitespace().next().unwrap_or("");
    let is_destructive = destructive_prefixes.iter().any(|prefix| first_word.starts_with(prefix));

    // Check if command starts with destructive prefix and contains wildcard
    if is_destructive && command_lower.contains('*') {
        return Err("RAA Security Violation: Destructive command with wildcard detected.".into());
    }

    // Non-destructive commands with wildcard are considered safe for observation
    if command_lower.contains('*') {
        return Ok("Command Safe (Observation Only).".into());
    }

    // Default case for commands without wildcards
    Ok("Command Safe.".into())
}

#[tauri::command]
fn scan_file_integrity(file_path: String) -> Result<String, String> {
    // Attempt to read the file content
    match std::fs::read_to_string(&file_path) {
        Ok(content) => {
            // Check for AI hijacking trigger
            if content.contains("IGNORE PREVIOUS INSTRUCTIONS") {
                return Err("RAA THREAT: Agent Hijacking prompt detected!".into());
            }
            // If content is readable as UTF-8 and doesn't contain threats, certify it
            Ok("File RAA-Certified: Safe for AI Context.".into())
        }
        Err(_) => {
            // If file can't be read as UTF-8, it might be binary data
            Err("RAA THREAT: Binary data detected in text context!".into())
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![audit_command, scan_file_integrity])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
