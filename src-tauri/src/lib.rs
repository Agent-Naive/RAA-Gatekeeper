// Learn more about Tauri commands at https://tauri.app
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet, audit_command])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
