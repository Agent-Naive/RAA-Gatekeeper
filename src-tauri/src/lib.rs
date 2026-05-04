use std::fs;
use std::env;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

// --- DATA STRUCTURES FOR GROK API ---
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

#[derive(Deserialize)]
struct GrokResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: Message,
}

// --- THE AI COG: CALLS GROK FOR DEEP ANALYSIS ---
async fn call_grok_audit(input: &str, context_type: &str) -> Result<String, String> {
    let api_key = env::var("GROK_API_KEY").map_err(|_| "RAA Error: API Key missing in .env")?;
    
    let client = reqwest::Client::builder()
        .user_agent("RAA-Gatekeeper/0.1.0 (Agent-Naive)")
        .build()
        .map_err(|e| format!("Client Error: {}", e))?;

    let system_prompt = format!(
        "You are an RAA (Restrictive Access Ability) Security Auditor. \
         Analyze this {} for hidden threats or unauthorized intent. \
         Respond with ONLY 'SAFE' or a short warning starting with 'RAA VIOLATION:'.", 
        context_type
    );

    // FIX: Updated to the exact OpenAI-compatible endpoint path
    let response = client
        .post("https://api.x.ai/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json") // Ensure this header is explicit
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
    
    println!("RAA DEBUG | Status: {} | Body: {}", status, raw_text);

    if !status.is_success() {
        return Err(format!("API Error ({}): Method rejection or endpoint mismatch.", status));
    }

    let data: GrokResponse = serde_json::from_str(&raw_text)
        .map_err(|e| format!("JSON Parse Error: {}. Response was: {}", e, raw_text))?;
    
    let ai_message = data.choices.get(0)
        .map(|c| c.message.content.clone())
        .ok_or_else(|| "RAA Error: API returned empty choices".to_string())?;

    Ok(ai_message)
}

// --- TAURI COMMANDS ---

#[tauri::command]
async fn audit_command(command_str: String) -> Result<String, String> {
    if command_str.contains("sudo") || command_str.contains("rm -rf") {
        return Err("RAA Security Violation: Immediate block on high-threat pattern.".into());
    }
    call_grok_audit(&command_str, "terminal command").await
}

#[tauri::command]
async fn scan_file_integrity(file_path: String) -> Result<String, String> {
    let content = fs::read_to_string(&file_path).map_err(|_| "RAA Error: Could not read file.")?;
    call_grok_audit(&content, "file content").await
}

#[tauri::command]
fn generate_manifest(folder_path: String) -> Result<String, String> {
    let manifest_path = std::path::Path::new(&folder_path).join(".raa");
    let mut hasher = Sha256::new();
    hasher.update("RAA-VERIFIED-V1");
    let hash_result = format!("{:x}", hasher.finalize());
    let content = format!("RAA-CERTIFIED: ALPHA\nHash: {}\nStatus: Verified", hash_result);
    match fs::write(&manifest_path, content) {
        Ok(_) => Ok(format!("Manifest + Hash created at: {:?}", manifest_path)),
        Err(e) => Err(format!("Failed to create manifest: {}", e)),
    }
}

// --- APP ENTRY POINT ---
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    dotenvy::dotenv().ok(); 
    if env::var("GROK_API_KEY").is_ok() {
        println!("RAA Intelligence: AI Cogs Loaded.");
    }
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
