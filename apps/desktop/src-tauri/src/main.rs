// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{Manager, RunEvent};

/// The local LLLanyard UI server we launched; killed when the app exits.
struct Server(Mutex<Option<Child>>);

/// Only ever navigate to the loopback UI. The URL carries a private per-run session secret in its fragment.
fn is_safe_ui_url(raw: &str) -> Option<url::Url> {
    let u = url::Url::parse(raw.trim()).ok()?;
    let ok = u.scheme() == "http"
        && u.host_str() == Some("127.0.0.1")
        && u.port().is_some()
        && u.fragment().map_or(false, |f| f.starts_with("s=") && f.len() > 20);
    ok.then_some(u)
}

/// Apps started from Finder get a minimal PATH (/usr/bin:/bin:...), so add the usual install folders for `lllanyard`
/// and the `node` its launcher needs. Appended, so anything the user's own PATH provides still wins.
#[cfg(not(windows))]
fn child_path() -> String {
    let current = std::env::var("PATH").unwrap_or_default();
    let mut parts: Vec<&str> = current.split(':').filter(|s| !s.is_empty()).collect();
    for extra in ["/opt/homebrew/bin", "/usr/local/bin"] {
        if !parts.contains(&extra) {
            parts.push(extra);
        }
    }
    parts.join(":")
}

fn start_server() -> Result<(Child, url::Url), String> {
    let mut cmd = Command::new("lllanyard");
    cmd.args(["ui", "--no-open", "--print-url"]).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(not(windows))]
    cmd.env("PATH", child_path());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| format!("could not start the lllanyard command: {e}"))?;
    let stdout = child.stdout.take().ok_or("no output from lllanyard")?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).map_err(|e| e.to_string())?;
    match is_safe_ui_url(&line) {
        Some(u) => Ok((child, u)),
        None => {
            let _ = child.kill();
            Err("lllanyard returned an unexpected address".into())
        }
    }
}

fn main() {
    tauri::Builder::default()
        .manage(Server(Mutex::new(None)))
        .setup(|app| {
            let handle = app.handle().clone();
            // Start the server off the UI thread; the window shows the "Starting…" page meanwhile.
            std::thread::spawn(move || match start_server() {
                Ok((child, url)) => {
                    *handle.state::<Server>().0.lock().unwrap() = Some(child);
                    if let Some(w) = handle.get_webview_window("main") {
                        let _ = w.navigate(url);
                    }
                }
                Err(e) => eprintln!("LLLanyard: {e}"),
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building LLLanyard")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(mut c) = app.state::<Server>().0.lock().unwrap().take() {
                    let _ = c.kill();
                }
            }
        });
}
