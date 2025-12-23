// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! Welcome to Strix Security Scanner.", name)
}

#[tauri::command]
async fn check_tool_installed(tool: &str) -> Result<bool, String> {
    use std::process::Command;
    
    let output = if cfg!(target_os = "windows") {
        Command::new("where")
            .arg(tool)
            .output()
    } else {
        Command::new("which")
            .arg(tool)
            .output()
    };
    
    match output {
        Ok(o) => Ok(o.status.success()),
        Err(e) => Err(format!("Failed to check tool: {}", e)),
    }
}

#[tauri::command]
async fn install_tool(tool: &str) -> Result<String, String> {
    use std::process::Command;
    
    // Install via homebrew on macOS or go install for Go tools
    let output = match tool {
        "nuclei" => Command::new("go")
            .args(["install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"])
            .output(),
        "httpx" => Command::new("go")
            .args(["install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"])
            .output(),
        "ffuf" => Command::new("go")
            .args(["install", "github.com/ffuf/ffuf/v2@latest"])
            .output(),
        "katana" => Command::new("go")
            .args(["install", "github.com/projectdiscovery/katana/cmd/katana@latest"])
            .output(),
        "sqlmap" => Command::new("pipx")
            .args(["install", "sqlmap"])
            .output(),
        _ => return Err(format!("Unknown tool: {}", tool)),
    };
    
    match output {
        Ok(o) => {
            if o.status.success() {
                Ok(format!("{} installed successfully", tool))
            } else {
                Err(String::from_utf8_lossy(&o.stderr).to_string())
            }
        }
        Err(e) => Err(format!("Failed to install {}: {}", tool, e)),
    }
}

#[tauri::command]
async fn get_system_info() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
    }))
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            check_tool_installed,
            install_tool,
            get_system_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
