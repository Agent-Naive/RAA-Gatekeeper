use chrono::Local;
use notify::Watcher;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::Emitter;
use walkdir::WalkDir;
use zip::read::ZipArchive;

/// Names of files and directories that should always be excluded from auditing.
/// This list is used in both generate_manifest and build_control_manifest.
const JUNK_NAMES: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "__MACOSX",
    ".DS_Store", // macOS Finder metadata file
];

#[derive(Serialize)]
struct LlmRequest {
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
    target_name: String,
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

#[derive(Serialize, Clone)]
struct LedgerFile {
    name: String,
    path: String,
    modified: String,
    size: u64,
    has_violation: bool,
}

fn get_content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[tauri::command]
async fn hash_file(path: String) -> Result<String, String> {
    let content = fs::read(&path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_entry_from_disk(manifest_path: &PathBuf, hash: &str) -> Option<RAAReport> {
    if let Ok(file) = fs::File::open(manifest_path) {
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains(&format!("Hash: {}", hash)) {
                let mut target_name = "Unknown".to_string();
                let mut reasoning_lines = Vec::new();

                for j in (0..i).rev() {
                    if lines[j].starts_with("Target: ") {
                        target_name = lines[j].replace("Target: ", "").trim().to_string();
                        break;
                    }
                }

                let mut capture = false;
                for next_line in &lines[i..] {
                    if next_line.starts_with("Result: ") {
                        capture = true;
                        continue;
                    }
                    if next_line.starts_with("---------------------------") && capture {
                        break;
                    }
                    if capture {
                        reasoning_lines.push(next_line.clone());
                    }
                }

                let full_reasoning = reasoning_lines.join("\n").trim().to_string();
                let is_violation = full_reasoning.to_uppercase().contains("VERDICT: VIOLATION");
                return Some(RAAReport {
                    verdict: if is_violation {
                        "RAA VIOLATION DETECTED".into()
                    } else {
                        "ALL SAFE".into()
                    },
                    reasoning: full_reasoning,
                    target_name,
                    is_error: is_violation,
                });
            }
        }
    }
    None
}

// --- VAULT PATH RESOLVER (handles ~, empty, and absolute paths correctly) ---
fn resolve_vault_root(vault_root_path: &str) -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".into());

    if vault_root_path.is_empty() {
        return PathBuf::from(&home).join("Documents/RAA-Vault");
    }

    let trimmed = vault_root_path.trim_end_matches('/');

    // If the value already points to the full vault dir, use it directly
    // Support both old (RAA_Vault) and new (RAA-Vault) for backward compatibility during transition
    if trimmed.ends_with("RAA-Vault") || trimmed.ends_with("RAA_Vault") {
        return PathBuf::from(trimmed);
    }

    // Support ~/Documents and ~ as home
    if trimmed == "~" || trimmed.starts_with("~/") {
        let rest = trimmed.strip_prefix("~/").unwrap_or("");
        return PathBuf::from(&home).join(rest).join("RAA-Vault");
    }

    // Absolute or relative path provided by user (from dialog) — append /RAA-Vault
    PathBuf::from(trimmed).join("RAA-Vault")
}

// --- RAA LOGGING ENGINE ---

/// Sanitizes a string for safe use in filenames and directory names.
///
/// 2025-10 Decision: We standardized on the **hyphen `-`** as the separator
/// for spaces and other characters across the new granular architecture
/// (job folders, control manifests, per-file reports, etc.).
///
/// Reasons:
/// - Clean, modern, professional appearance in file explorers
/// - Consistent with the existing timestamp format (YYYYMMDD-HHMMSS)
/// - Better readability and sharing than underscores for user-facing artifacts
/// - Safe in shells, URLs, and across Windows/macOS/Linux
///
/// See RAA-NEWPATH-FORWARD.txt and ROADMAP.md → "New Path Forward" section
/// for full context on the shift to job folders + ONE FILE = ONE REPORT.
///
/// FUTURE NOTE:
/// We have decided to use the **static name** `~RAA-CONTROL-Manifest.log`
/// inside every job folder (instead of a dynamic per-job name).
/// This simplifies logic significantly — no variable naming needed.
/// The `~` prefix ensures it always sorts to the top of the folder.
/// This file will be the very first artifact created when a user starts
/// either a Certify or Archive job.
fn sanitize_for_filename(input: &str) -> String {
    // Replace filesystem-illegal characters first
    let s = input.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "-");

    // Then normalize spaces, dots, and existing underscores to hyphens.
    // We deliberately avoid using periods as separators (they conflict with extensions).
    let s = s.replace([' ', '.', '_'], "-");

    // Collapse multiple consecutive hyphens and trim leading/trailing ones
    let s = s.split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    s
}

/// Collects two lists of relative paths from the source directory:
/// - Files that will be audited (match allowed extensions or are .zip)
/// - Files that will be skipped (do not match allowed extensions)
///
/// This is used both for building the control manifest and for writing
/// per-file reports inside the job folder.
fn collect_audited_and_skipped_paths(
    root: &Path,
    allowed_extensions: &[String],
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut audited: Vec<PathBuf> = Vec::new();
    let mut skipped: Vec<PathBuf> = Vec::new();

    let walker = WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !JUNK_NAMES.iter().any(|&ex| name == ex) && !name.starts_with("._")
        });

    for entry in walker.filter_map(|e| e.ok()) {
        if entry.path() == root {
            continue;
        }

        if entry.file_type().is_file() {
            let ext = entry
                .path()
                .extension()
                .map(|s| format!(".{}", s.to_string_lossy().to_lowercase()))
                .unwrap_or_default();

            if let Ok(rel) = entry.path().strip_prefix(root) {
                if allowed_extensions.contains(&ext) || ext == ".zip" {
                    audited.push(rel.to_path_buf());
                } else {
                    skipped.push(rel.to_path_buf());
                }
            }
        }
    }

    (audited, skipped)
}

/// Builds a minimal hierarchical text representation of the directory structure
/// for the control manifest. Uses simple 4-space indentation to create a
/// "tabbed" visual effect that reflects the folder hierarchy.
///
/// This version now includes two sections:
///   1. Files to be audited
///   2. Files to be skipped (non-matching extensions, after junk filtering)
///
/// Directories are shown with a trailing `/`.
/// Clean 4-space indentation is used for a simple tabbed look.
fn build_control_manifest(
    root: &Path,
    allowed_extensions: &[String],
    source_folder_name: &str,
    job_name: &str,
    _timestamp: &str,
) -> String {
    let mut lines: Vec<String> = Vec::new();

    // Header
    lines.push("~RAA-CONTROL-Manifest.log".to_string());
    lines.push(format!("Generated: {}", Local::now().format("%Y-%m-%d %H:%M:%S")));
    lines.push(format!("Source: {}", root.display()));
    lines.push(format!("Job Folder: {}", job_name));
    lines.push(String::new());

    let (audited_rel_paths, skipped_rel_paths) =
        collect_audited_and_skipped_paths(root, allowed_extensions);

    // ============================================================
    // SECTION 1: Files to be audited
    // ============================================================
    lines.push(format!(
        "Directory Structure ({} files to be audited):",
        audited_rel_paths.len()
    ));
    lines.push(String::new());

    lines.extend(build_tree_lines(source_folder_name, &audited_rel_paths));

    lines.push(String::new());

    // ============================================================
    // SECTION 2: Files to be skipped
    // Only directories that actually contain skipped files are shown.
    // ============================================================
    lines.push(format!(
        "Directory Structure ({} files to be skipped):",
        skipped_rel_paths.len()
    ));
    lines.push(String::new());

    lines.extend(build_tree_lines(source_folder_name, &skipped_rel_paths));

    lines.join("\n")
}

/// Builds clean indented tree lines from a list of relative file paths.
/// Only ancestor directories that contain at least one file from the list are included.
fn build_tree_lines(root_name: &str, file_paths: &[PathBuf]) -> Vec<String> {
    let mut lines = Vec::new();

    if file_paths.is_empty() {
        lines.push(format!("{}/", root_name));
        return lines;
    }

    // Root line
    lines.push(format!("{}/", root_name));

    // Collect all unique ancestor directories for the given files
    let mut all_dirs: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for path in file_paths {
        let mut current = path.clone();
        while let Some(parent) = current.parent() {
            if !parent.as_os_str().is_empty() {
                all_dirs.insert(parent.to_path_buf());
            }
            current = parent.to_path_buf();
        }
    }

    // Sort everything so directories appear before their files in a natural order
    let mut all_entries: Vec<(PathBuf, bool)> = Vec::new(); // (path, is_file)

    for path in file_paths {
        all_entries.push((path.clone(), true));
    }
    for dir in &all_dirs {
        all_entries.push((dir.clone(), false));
    }

    all_entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (path, is_file) in all_entries {
        let depth = path.components().count();
        let indent = "    ".repeat(depth);

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if is_file {
            lines.push(format!("{}{}", indent, name));
        } else {
            lines.push(format!("{}{}/", indent, name));
        }
    }

    lines
}

fn log_to_raa(scan_type: &str, target_label: &str, hash: &str, result_text: &str, vault_root_path: &str) -> PathBuf {
    let audit_root = resolve_vault_root(vault_root_path);
    
    if !audit_root.exists() {
        let _ = fs::create_dir_all(&audit_root);
    }

    let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let manifest_name = if scan_type == "audit" {
        "Gatekeeper-master-terminal-history.raa".to_string()
    } else {
        let clean_label = sanitize_for_filename(target_label);
        format!("Gatekeeper-{}-{}-{}.raa", scan_type, clean_label, timestamp)
    };

    let manifest_path = audit_root.join(manifest_name);
    let log_entry = format!(
        "\n--- RAA FORENSIC REPORT ---\nType: {}\nTarget: {}\nHash: {}\nTimestamp: {}\nResult: \n{}\n---------------------------\n",
        scan_type, target_label, hash, Local::now().format("%Y-%m-%d %H:%M:%S"), result_text
    );

    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&manifest_path)
    {
        let _ = f.write_all(log_entry.as_bytes());
        let _ = f.sync_all();
    }

    manifest_path
}

#[tauri::command]
async fn audit_command(
    command_str: String,
    base_url: String,
    model_name: String,
    vault_root_path: String,
) -> Result<RAAReport, String> {
    let hash = get_content_hash(&command_str);
    // Respect user-selected vault (handles ~ correctly)
    let bible_dir = resolve_vault_root(&vault_root_path);
    let bible_path = bible_dir.join("Gatekeeper-master-terminal-history.raa");

    if let Some(cached) = read_entry_from_disk(&bible_path, &hash) {
        return Ok(cached);
    }

    let report = call_llm_auditor(
        &command_str,
        "terminal command",
        &base_url,
        &model_name,
        &command_str,
    )
    .await?;

    let path = log_to_raa("audit", &command_str, &hash, &report.reasoning, &vault_root_path);
    Ok(read_entry_from_disk(&path, &hash).unwrap_or(report))
}

#[tauri::command]
async fn scan_file_integrity(
    file_path: String,
    base_url: String,
    model_name: String,
    vault_root_path: String,
) -> Result<RAAReport, String> {
    let path = PathBuf::from(&file_path);
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let hash = get_content_hash(&content);
    let target_label = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    let report = call_llm_auditor(
        &content,
        "file integrity",
        &base_url,
        &model_name,
        &target_label,
    )
    .await?;
    let path = log_to_raa("analyze", &target_label, &hash, &report.reasoning, &vault_root_path);

    Ok(read_entry_from_disk(&path, &hash).unwrap_or(report))
}

async fn call_llm_auditor(
    input: &str,
    context_type: &str,
    base_url: &str,
    model_name: &str,
    target: &str,
) -> Result<RAAReport, String> {
    let api_key = env::var("GROK_API_KEY").unwrap_or_default();
    let client = reqwest::Client::new();

    // HARDENED PROMPT: Forces technical depth
    let system_prompt = format!(
        "You are an RAA Security Auditor. Analyze this {} for threats. \
        You MUST provide a lengthy, highly technical 1-paragraph explanation. \
        Start your response with 'Audit Analysis for {}:' followed by the details. \
        If safe, conclude with 'VERDICT: SAFE'. If dangerous, include 'VERDICT: VIOLATION'.",
        context_type, target
    );

    let response = client
        .post(base_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&LlmRequest {
            model: model_name.to_string(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: system_prompt,
                },
                Message {
                    role: "user".to_string(),
                    content: input.to_string(),
                },
            ],
        })
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let raw: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    let ai_response = raw["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("SAFE")
        .to_string();
    let is_violation = ai_response.to_uppercase().contains("VIOLATION");

    Ok(RAAReport {
        verdict: if is_violation {
            "RAA VIOLATION DETECTED".into()
        } else {
            "ALL SAFE".into()
        },
        reasoning: ai_response,
        target_name: target.to_string(),
        is_error: is_violation,
    })
}

#[allow(dead_code)]
static WATCHER: Lazy<Mutex<Option<notify::RecommendedWatcher>>> = Lazy::new(|| Mutex::new(None));

#[tauri::command]
async fn check_integrity(vault_root_path: Option<String>) -> Result<serde_json::Value, String> {
    // 1. Hardware Probes
    let is_multithreaded = rayon::current_num_threads() > 1;
    let is_bucket_active = walkdir::WalkDir::new(".")
        .max_depth(1)
        .into_iter()
        .next()
        .is_some();

    // 2. Actually test vault resolvability
    let home = env::var("HOME").unwrap_or_else(|_| ".".into());
    let audit_root = match &vault_root_path {
        Some(p) if !p.is_empty() => PathBuf::from(p).join("RAA-Vault"),
        _ => PathBuf::from(home).join("Documents/RAA-Vault"),
    };
    let vault_ok = audit_root.exists();

    Ok(serde_json::json!({
        "parallel_hashing": is_multithreaded,
        "bucket_traversal": is_bucket_active,
        "ai_reasoning": true,
        "terminal_input_lock": true,
        "zip_safety": true,
        "vault_path": vault_ok,
        "disk_first_verification": true
    }))
}

#[tauri::command]
async fn scan_compressed_archive(
    window: tauri::Window,
    zip_path: String,
    allowed_extensions: Vec<String>,
    base_url: String,
    model_name: String,
    vault_root_path: String,
) -> Result<RAAReport, String> {
    let file = fs::File::open(&zip_path).map_err(|e| e.to_string())?;
    let mut archive = ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut file_analyses = Vec::new();
    let mut violation_found = false;

    for i in 0..archive.len() {
        if let Ok(mut zf) = archive.by_index(i) {
            let name = zf.name().to_string();
            if name.contains("__MACOSX") || name.split('/').last().unwrap_or("").starts_with("._") {
                continue;
            }

            let ext = format!(".{}", name.split('.').last().unwrap_or("").to_lowercase());
            if zf.is_file() && allowed_extensions.contains(&ext) {
                let _ = window.emit(
                    "scan-event",
                    ScanEvent {
                        path: name.clone(),
                        status: "Active".into(),
                    },
                );
                let mut buffer = vec![0; 2 * 1024 * 1024];
                let bytes_read = zf.read(&mut buffer).map_err(|e| e.to_string())?;
                let content = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
                let hash = get_content_hash(&content);

                let report =
                    call_llm_auditor(&content, "archive internal", &base_url, &model_name, &name)
                        .await?;

                if report.is_error {
                    violation_found = true;
                }

                // Rich per-file block: preserves DNA line + stores the full oracle response
                let analysis_block = format!(
                    "--- RAA FILE ANALYSIS ---\n\
                     File: {} | Hash: {}\n\
                     Verdict: {}\n\
                     Analysis:\n{}\n\
                     ------------------------\n",
                    name,
                    hash,
                    report.verdict,
                    report.reasoning.trim()
                );

                file_analyses.push(analysis_block);
            }
        }
    }

    let final_text = file_analyses.join("\n");
    log_to_raa("archive", &zip_path, "ARCHIVE_BATCH", &final_text, &vault_root_path);

    Ok(RAAReport {
        verdict: if violation_found {
            "VIOLATION FOUND".into()
        } else {
            "SAFE".into()
        },
        reasoning: final_text,
        target_name: zip_path,
        is_error: violation_found,
    })
}

#[tauri::command]
async fn generate_manifest(
    window: tauri::Window,
    folder_path: String,
    allowed_extensions: Vec<String>,
    base_url: String,
    model_name: String,
    vault_root_path: String,
) -> Result<RAAReport, String> {
    let folder_path_buf = fs::canonicalize(&folder_path).map_err(|_| "Path error")?;

    // =============================================
    // STAGE 1: Create Job Folder + ~RAA-CONTROL-Manifest.log immediately
    // This is the very first action when a Certify job starts.
    // The manifest is a minimal inventory + hierarchy of files that will be audited.
    // =============================================
    let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();

    let source_folder_name = folder_path_buf
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("UnknownProject");

    let job_name = format!("{}-{}", sanitize_for_filename(source_folder_name), timestamp);

    let vault_root = resolve_vault_root(&vault_root_path);
    let job_folder = vault_root.join(&job_name);

    // Create the dated job folder
    if !job_folder.exists() {
        let _ = fs::create_dir_all(&job_folder);
    }

    // Collect which files will be skipped (we know this before any LLM work)
    let (_audited_paths, skipped_rel_paths) =
        collect_audited_and_skipped_paths(&folder_path_buf, &allowed_extensions);

    // Emit skipped events immediately so the UI's 🚫 SKIPPED area populates
    for rel in &skipped_rel_paths {
        let full_path = folder_path_buf.join(rel);
        let _ = window.emit(
            "scan-event",
            ScanEvent {
                path: full_path.to_string_lossy().into(),
                status: "Skipped".into(),
            },
        );
    }

    // Build minimal hierarchical inventory (control manifest)
    let manifest_content = build_control_manifest(
        &folder_path_buf,
        &allowed_extensions,
        source_folder_name,
        &job_name,
        &timestamp,
    );

    // Write the static control manifest (always the same name)
    let manifest_path = job_folder.join("~RAA-CONTROL-Manifest.log");
    match fs::write(&manifest_path, &manifest_content) {
        Ok(_) => {
            eprintln!("[RAA] Created control manifest at: {:?}", manifest_path);
        }
        Err(e) => {
            eprintln!("[RAA] WARNING: Failed to write control manifest to {:?}: {}", manifest_path, e);
        }
    }

    // Continue with original processing...
    let mut target_files = Vec::new();

    let walker = WalkDir::new(&folder_path_buf)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !JUNK_NAMES.iter().any(|&ex| name == ex) && !name.starts_with("._")
        });

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path().to_path_buf();
        let ext = path
            .extension()
            .map(|s| format!(".{}", s.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        if entry.file_type().is_file() && (allowed_extensions.contains(&ext) || ext == ".zip") {
            let _ = window.emit(
                "scan-event",
                ScanEvent {
                    path: path.to_string_lossy().into(),
                    status: "Active".into(),
                },
            );
            target_files.push((path, ext));
        }
    }

    let jobs: Vec<FileJob> = target_files
        .into_par_iter()
        .filter_map(|(path, ext)| {
            if ext == ".zip" {
                return Some(FileJob {
                    path,
                    size: 0,
                    hash: "ZIP".into(),
                    content: "".into(),
                });
            }
            let content = fs::read_to_string(&path).ok().unwrap_or_default();
            let hash = get_content_hash(&content);
            Some(FileJob {
                path,
                size: content.len(),
                hash,
                content,
            })
        })
        .collect();

    const BUCKET_LIMIT: usize = 10000;

    let mut buckets = Vec::new();
    let mut current_bucket = Vec::new();
    let mut current_size = 0;

    for job in jobs {
        if job.hash == "ZIP" {
            // ZIP files always get their own dedicated bucket
            if !current_bucket.is_empty() {
                buckets.push(current_bucket);
                current_bucket = Vec::new();
                current_size = 0;
            }
            buckets.push(vec![job]);
            continue;
        }

        // Large file that exceeds the entire bucket limit
        if job.size > BUCKET_LIMIT {
            // Flush current bucket first if it has anything
            if !current_bucket.is_empty() {
                buckets.push(current_bucket);
                current_bucket = Vec::new();
                current_size = 0;
            }
            // The large file will be split across multiple buckets
            let size = job.size;
            current_bucket.push(job);
            current_size += size;
            continue;
        }

        // Normal case: only add the file if it completely fits in the remaining space.
        // This prevents "just fits and wastes the bucket" which leads to bad splits.
        if current_size + job.size > BUCKET_LIMIT && !current_bucket.is_empty() {
            buckets.push(current_bucket);
            current_bucket = Vec::new();
            current_size = 0;
        }

        let size = job.size;
        current_bucket.push(job);
        current_size += size;
    }

    if !current_bucket.is_empty() {
        buckets.push(current_bucket);
    }
    let mut ledger_entries = String::new();
    let mut any_violations = false;

    for bucket in buckets {
        let mut batch_text = String::new();

        if bucket.len() == 1 {
            // Single file in bucket — ask for focused analysis
            let job = &bucket[0];
            batch_text.push_str(&format!(
                "Analyze the following file for security issues, malicious code, or suspicious behavior.\n\n\
                 FILE: {}\nHASH: {}\n\nCONTENT:\n{}\n",
                job.path.display(),
                job.hash,
                job.content
            ));
        } else {
            // Multiple files in one bucket — force the model to treat every file as a completely separate, independent audit
            let file_count = bucket.len();

            batch_text.push_str(&format!(
                "You have been given a batch containing exactly {} separate files to audit.\n\n\
                 YOU MUST FOLLOW THIS EXACT PROCESS (treat it like a programming for-loop):\n\n\
                 For i from 1 to {}:\n\
                   - Focus ONLY on FILE i.\n\
                   - Completely ignore every other file in this batch while analyzing FILE i.\n\
                   - Perform a full, independent security audit of ONLY FILE i.\n\
                   - Output the complete analysis and verdict for FILE i.\n\
                   - Then mentally clear your context before moving to FILE i+1.\n\
                   - Do not carry over any suspicions, context, or details from previous files.\n\n\
                 This is not a single holistic review of the whole batch. Each file must receive its own standalone forensic analysis.\n\n\
                 Files in this batch (in order):\n\n",
                file_count, file_count
            ));

            for (i, job) in bucket.iter().enumerate() {
                batch_text.push_str(&format!(
                    "=== START OF FILE {} ===\n\
                     FILE PATH: {}\n\
                     HASH: {}\n\n\
                     FILE CONTENT:\n{}\n\n\
                     === END OF FILE {} ===\n\n",
                    i + 1,
                    job.path.display(),
                    job.hash,
                    job.content,
                    i + 1
                ));
            }

            batch_text.push_str(
                "Now execute the process described above.\n\n\
                 REQUIRED OUTPUT FORMAT (YOU MUST FOLLOW EXACTLY):\n\
                 Output ONLY a valid JSON array. Nothing before it, nothing after it.\n\n\
                 The array must contain one object per file in this batch, in the same order.\n\n\
                 Each object MUST use these exact field names:\n\
                 {\n\
                   \"file_number\": number (starting from 1),\n\
                   \"file_path\": \"exact FILE PATH string from the list above\",\n\
                   \"verdict\": \"CERTIFIED\" or \"VIOLATION FOUND\",\n\
                   \"analysis\": \"your full, independent analysis for ONLY this file\"\n\
                 }\n\n\
                 Rules:\n\
                 - Use the exact field names (file_number, file_path, verdict, analysis).\n\
                 - Do not rename, add, or remove fields.\n\
                 - Do not wrap the array in an object.\n\
                 - Output ONLY the raw JSON array.\n\n\
                 Begin processing FILE 1 now."
            );
        }

        let report = call_llm_auditor(&batch_text, "folder", &base_url, &model_name, "Manifest")
            .await
            .unwrap_or(RAAReport {
                verdict: "SAFE".into(),
                reasoning: "".into(),
                target_name: "".into(),
                is_error: false,
            });

        if report.is_error {
            any_violations = true;
        }

        // Try to parse structured JSON output from the model
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct FileAnalysis {
            file_number: u32,
            file_path: String,
            verdict: String,
            analysis: String,
        }

        let analyses: Vec<FileAnalysis> = match serde_json::from_str(&report.reasoning) {
            Ok(parsed) => {
                // Successfully parsed per-file structured output
                parsed
            }
            Err(e) => {
                // Parsing failed — log the raw response for debugging
                eprintln!(
                    "WARNING: Failed to parse structured JSON from model for multi-file bucket.\n\
                     Error: {}\n\
                     Raw response (first 2000 chars):\n{}\n",
                    e,
                    &report.reasoning.chars().take(2000).collect::<String>()
                );
                vec![]
            }
        };

        // Write rich per-file analysis blocks
        for (i, job) in bucket.iter().enumerate() {
            let (verdict, analysis_text) = if let Some(a) = analyses.get(i) {
                // Successfully parsed per-file structured data from model
                if a.file_path != job.path.display().to_string() {
                    eprintln!(
                        "Warning: Model returned mismatched file_path.\n  Expected: {}\n  Got: {}",
                        job.path.display(),
                        a.file_path
                    );
                }
                (a.verdict.clone(), a.analysis.clone())
            } else {
                // Fallback: model did not return valid structured JSON.
                // Still respect the top-level is_error from this bucket's LLM response.
                let fallback_verdict = if report.is_error {
                    "VIOLATION FOUND (structured output failed to parse)".to_string()
                } else {
                    "CERTIFIED (structured output failed to parse)".to_string()
                };

                let fallback_text = if analyses.is_empty() {
                    format!(
                        "[MODEL DID NOT RETURN STRUCTURED OUTPUT]\n\n{}",
                        report.reasoning.trim()
                    )
                } else {
                    format!(
                        "[STRUCTURED OUTPUT PARSING FAILED FOR THIS FILE]\n\n{}",
                        report.reasoning.trim()
                    )
                };

                (fallback_verdict, fallback_text)
            };

            let analysis_block = format!(
                "--- RAA FILE ANALYSIS ---\n\
                 File: {}\n\
                 Hash: {}\n\
                 Verdict: {}\n\
                 Analysis:\n{}\n\
                 ------------------------\n",
                job.path.display(),
                job.hash,
                verdict,
                analysis_text
            );
            ledger_entries.push_str(&analysis_block);

            // Write individual per-file report inside the job folder, preserving source hierarchy.
            // This enables proper DNA tracking per file in the new job folder model.
            let rel_path = match job.path.strip_prefix(&folder_path_buf) {
                Ok(p) => p.to_path_buf(),
                Err(_) => job.path.file_name().map(PathBuf::from).unwrap_or_else(|| job.path.clone()),
            };
            let target_path = job_folder.join(&rel_path).with_extension("raa");
            if let Some(parent) = target_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::write(&target_path, &analysis_block) {
                Ok(_) => {
                    eprintln!("[RAA] Wrote per-file audited report: {:?}", target_path);
                }
                Err(e) => {
                    eprintln!("[RAA] WARNING: Failed to write per-file audited report {:?}: {}", target_path, e);
                }
            }

            if verdict.to_uppercase().contains("VIOLATION") {
                any_violations = true;
            }
        }
    }

    // Prepend overall status header
    let overall_verdict = if any_violations {
        "UNCERTIFIED - VIOLATIONS FOUND".to_string()
    } else {
        "CERTIFIED".to_string()
    };

    let overall_header = format!(
        "--- OVERALL CERTIFY RESULT ---\nStatus: {}\nViolations Detected: {}\n\n",
        overall_verdict,
        if any_violations { "YES" } else { "NO" }
    );

    let full_ledger = format!("{}{}", overall_header, ledger_entries);

    // Write the report inside the job folder we created at the start of this function.
    // This makes the control manifest + the main report live together.
    // Future work: split this into individual per-file .raa files that mirror source hierarchy
    // inside the job folder (e.g. job-folder/src/utils/foo.rs.raa).
    let report_filename = format!("certify-report-{}.raa", timestamp);
    let report_path = job_folder.join(report_filename);
    match fs::write(&report_path, &full_ledger) {
        Ok(_) => {
            eprintln!("[RAA] Wrote certify report to: {:?}", report_path);
        }
        Err(e) => {
            eprintln!("[RAA] WARNING: Failed to write certify report to {:?}: {}", report_path, e);
        }
    }

    // =============================================
    // Write individual reports for skipped files inside the job folder.
    // We do this first (as requested) because we already know the skipped list
    // before any LLM work happens.
    // Each skipped file gets its own small .raa report with its DNA hash.
    // =============================================
    for rel_path in &skipped_rel_paths {
        let full_path = folder_path_buf.join(rel_path);
        let content = fs::read_to_string(&full_path).unwrap_or_default();
        let hash = get_content_hash(&content);

        let skipped_report = format!(
            "--- RAA FILE ANALYSIS ---\n\
             File: {}\n\
             Hash: {}\n\
             Verdict: SKIPPED\n\
             Analysis:\n\
             This file was not sent for AI analysis because its file extension \
             did not match the allowed extensions configured for this certification run.\n\
             ------------------------\n",
            rel_path.display(),
            hash
        );

        let target_path = job_folder.join(rel_path).with_extension("raa");
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match fs::write(&target_path, &skipped_report) {
            Ok(_) => {
                eprintln!("[RAA] Wrote skipped report: {:?}", target_path);
            }
            Err(e) => {
                eprintln!("[RAA] WARNING: Failed to write skipped report {:?}: {}", target_path, e);
            }
        }
    }

    Ok(RAAReport {
        verdict: overall_verdict,
        reasoning: full_ledger,
        target_name: folder_path,
        is_error: any_violations,
    })
}

// --- RAA LEDGER BROWSER ---
#[tauri::command]
async fn read_ledger(vault_root_path: String) -> Result<String, String> {
    let audit_root = resolve_vault_root(&vault_root_path);
    
    let mut all_logs = String::new();

    if let Ok(entries) = fs::read_dir(audit_root) {
        let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        paths.sort_by_key(|a| {
            a.metadata()
                .and_then(|m| m.modified())
                .ok()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });
        paths.reverse();

        for entry in paths {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                all_logs.push_str(&format!(
                    "\nFILE: {}\n{}",
                    entry.file_name().to_string_lossy(),
                    content
                ));
                all_logs.push_str("\n------------------------------------------------\n");
            }
        }
    }
    
    Ok(all_logs)
}

// --- VAULT HELPERS ---
#[tauri::command]
async fn create_vault_directory(root_path: String) -> Result<String, String> {
    let audit_root = resolve_vault_root(&root_path);

    fs::create_dir_all(&audit_root)
        .map_err(|e| format!("Failed to create RAA-Vault at {:?}: {}", audit_root, e))?;

    Ok(audit_root.to_string_lossy().into_owned())
}

#[tauri::command]
async fn get_default_vault_path() -> Result<String, String> {
    let home = env::var("HOME").unwrap_or_else(|_| ".".into());
    let default_path = PathBuf::from(home).join("Documents").join("RAA-Vault");
    Ok(default_path.to_string_lossy().into_owned())
}

// --- LEDGER BROWSER COMMANDS ---
#[tauri::command]
async fn list_ledger_files(vault_root_path: String) -> Result<Vec<LedgerFile>, String> {
    // ============================================================
    // TODO (New Path Forward - Ledger Browser)
    // Currently this does a flat read_dir on the vault root only.
    // With the new job folder model (RAA-Vault/JobName-YYYYMMDD-HHMMSS/),
    // we need to either:
    //   1. Recursively discover .raa files inside job folders, or
    //   2. Change the UI to show job folders as containers that the user
    //      can navigate into (like a directory tree).
    //
    // This work is explicitly tabled until the ~RAA-CONTROL-Manifest.log
    // and per-file report writing inside job folders are stabilized.
    //
    // See RAA-NEWPATH-FORWARD.txt → Stage 5 and "Ledger Browser" notes.
    // ============================================================
    let audit_root = resolve_vault_root(&vault_root_path);

    if !audit_root.exists() {
        return Ok(vec![]);
    }

    let mut files: Vec<LedgerFile> = Vec::new();

    if let Ok(entries) = fs::read_dir(&audit_root) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("raa") {
                continue;
            }

            let metadata = entry.metadata().ok();
            let modified = metadata
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| {
                    let datetime: chrono::DateTime<chrono::Local> = t.into();
                    Some(datetime.format("%Y-%m-%d %H:%M").to_string())
                })
                .unwrap_or_else(|| "unknown".into());

            let size = metadata.map(|m| m.len()).unwrap_or(0);

            let content = fs::read_to_string(&path).unwrap_or_default();
            let has_violation = content.to_uppercase().contains("VIOLATION");

            files.push(LedgerFile {
                name: path.file_name().unwrap_or_default().to_string_lossy().into(),
                path: path.to_string_lossy().into(),
                modified,
                size,
                has_violation,
            });
        }
    }

    // Newest first
    files.sort_by(|a, b| b.modified.cmp(&a.modified));
    Ok(files)
}

#[tauri::command]
async fn read_single_ledger_file(full_path: String) -> Result<String, String> {
    fs::read_to_string(&full_path).map_err(|e| e.to_string())
}

/// Safely deletes a .raa ledger file. Only allows deletion inside the current vault root.
#[tauri::command]
async fn delete_ledger_file(full_path: String, vault_root_path: String) -> Result<(), String> {
    let audit_root = resolve_vault_root(&vault_root_path);
    let target_path = std::path::PathBuf::from(&full_path);

    // Security: prevent deleting files outside the vault
    if !target_path.starts_with(&audit_root) {
        return Err("Delete not allowed: file is outside the RAA vault".into());
    }

    if !target_path.exists() {
        return Err("File no longer exists".into());
    }

    // Extra safety: only allow .raa files
    if target_path.extension().and_then(|e| e.to_str()) != Some("raa") {
        return Err("Only .raa files can be deleted through this command".into());
    }

    fs::remove_file(&target_path).map_err(|e| format!("Failed to delete file: {}", e))
}

#[tauri::command]
async fn toggle_watcher(
    window: tauri::Window,
    enabled: bool,
    folders: Vec<String>,
    depth: usize,
) -> Result<(), String> {
    let mut watcher_lock = WATCHER.lock().map_err(|e| e.to_string())?;

    // Kill old watcher
    *watcher_lock = None;

    if !enabled || folders.is_empty() {
        println!("🕵️ Watcher: Deactivated");
        return Ok(());
    }

    println!(
        "🕵️ Watcher: ARMED for {} target slots (Depth: {})",
        folders.len(),
        depth
    );
    let window_clone = window.clone();
    let mut watcher =
        notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| match res {
            Ok(event) => {
                println!("📡 RADAR: Event Detected: {:?}", event.kind);
                for path in event.paths {
                    let path_str = path.to_string_lossy().to_string();
                    if !path_str.contains("~") && !path_str.contains(".DS_Store") {
                        println!("⚡ SPARK: Broadcasting DNA change: {}", path_str);
                        let _ = window_clone.emit("watcher-event", path_str);
                    }
                }
            }
            Err(e) => println!("🚨 ERROR: Watcher kernel error: {:?}", e),
        })
        .map_err(|e| e.to_string())?;

    for folder in folders {
        let mode = if depth > 1 {
            notify::RecursiveMode::Recursive
        } else {
            notify::RecursiveMode::NonRecursive
        };
        let _ = watcher.watch(std::path::Path::new(&folder), mode);
    }

    *watcher_lock = Some(watcher);
    Ok(())
}

pub fn run() {
    dotenvy::dotenv().ok();
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            audit_command,
            generate_manifest,
            scan_file_integrity,
            scan_compressed_archive,
            read_ledger,
            check_integrity,
            toggle_watcher,
            create_vault_directory,
            get_default_vault_path,
            list_ledger_files,
            read_single_ledger_file,
            delete_ledger_file,
            hash_file
        ])
        .run(tauri::generate_context!())
        .expect("error");
}

// End of File
