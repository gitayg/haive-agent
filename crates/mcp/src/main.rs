// HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The HaiveControl Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HaiveControl MCP server — exposes registered devices as MCP tools so an AI
// client can list_devices, screenshot, run_command, control input, and move
// files. Runs on your Mac; it drives devices entirely through the hub's /m API
// (token + owner authed), so it works against cloud/relay devices too — not
// just the LAN. Env:
//   HAIVE_HUB       hub base URL (default http://localhost:8770)
//   HIVE_MCP_TOKEN  token for the hub's /m API (matches the hub's MCP_TOKEN)
//   HIVE_OWNER      owner id to act as (per-user hub scoping)
//   HAIVE_CAFILE    optional PEM to verify a self-signed hub cert
use base64::Engine;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use serde::Deserialize;

#[derive(Deserialize, Default, Clone)]
struct AgentInfo {
    name: String,
    ip: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    scheme: String,
}

impl AgentInfo {
    /// The proxy target the hub understands: `relay://id` for relay devices,
    /// else `scheme://ip:port`.
    fn target(&self) -> String {
        if self.scheme == "relay" {
            format!("relay://{}", self.ip)
        } else {
            format!("{}://{}:{}", self.scheme, self.ip, self.port)
        }
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DeviceArg {
    device: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct RunArgs {
    device: String,
    command: String,
    /// launch fire-and-forget (don't wait for output) — use for GUI apps or long tasks that would otherwise block
    #[serde(default)]
    detach: bool,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct DownloadArgs {
    device: String,
    remote_path: String,
    #[serde(default)]
    save_as: Option<String>,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct UploadArgs {
    device: String,
    local_path: String,
    #[serde(default)]
    remote_dir: Option<String>,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct ClickArgs {
    device: String,
    /// horizontal position as a fraction of the screen width, 0.0 (left) to 1.0 (right)
    x: f64,
    /// vertical position as a fraction of the screen height, 0.0 (top) to 1.0 (bottom)
    y: f64,
    /// "left" (default), "right", or "middle"
    #[serde(default)]
    button: Option<String>,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct TypeArgs {
    device: String,
    text: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct KeyArgs {
    device: String,
    /// key name, e.g. Enter, Tab, Escape, Backspace, ArrowDown, F5
    key: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct CameraArgs {
    device: String,
    /// camera index, default 0
    #[serde(default)]
    index: Option<u32>,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct ReportArgs {
    device: String,
    /// one of: hardware, av, encryption, firewall, processes, services, network, packages
    kind: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct ActionArgs {
    device: String,
    /// one of: reboot, shutdown, sleep, logoff, firewall_on, firewall_off, usb_lock, usb_unlock
    action: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct MessageArgs {
    device: String,
    text: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct PackageArgs {
    device: String,
    /// package id (winget id on Windows, brew formula on macOS, apt package on Linux)
    package: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct FleetRunArgs {
    /// shell command to run on every device you own, in parallel
    command: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct FleetReportArgs {
    /// one of: hardware, av, encryption, firewall, processes, services, network, packages
    kind: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct SearchScriptsArgs {
    /// search text matched against script name, description and category (e.g. "bitlocker", "cleanup temp", "defender")
    query: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct RunScriptArgs {
    device: String,
    /// the script filename returned by search_scripts (e.g. "Win_Bitlocker_Status.ps1")
    script: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct RunScriptFleetArgs {
    /// the script filename returned by search_scripts, to run on every device you own
    script: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct CveArgs {
    /// product or keyword to search NVD for (e.g. "openssl 3.0", "Google Chrome", "log4j")
    query: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct RunPluginArgs {
    device: String,
    /// the plugin id from list_plugins
    plugin: String,
    /// optional argument passed to the plugin's {{arg}} placeholder
    #[serde(default)]
    arg: String,
}

#[derive(Clone)]
struct Srv {
    #[allow(dead_code)]
    tool_router: ToolRouter<Srv>,
    hub: String,
    mtok: String,
    owner: String,
    client: reqwest::Client,
    direct_client: std::sync::Arc<tokio::sync::OnceCell<reqwest::Client>>,
}

fn err(e: impl ToString) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Srv {
    fn new() -> Self {
        let cafile = std::env::var("HAIVE_CAFILE").ok();
        let mut b = reqwest::Client::builder();
        match cafile.and_then(|p| std::fs::read(p).ok()).and_then(|p| reqwest::Certificate::from_pem(&p).ok()) {
            Some(cert) => b = b.add_root_certificate(cert),
            None => b = b.danger_accept_invalid_certs(true),
        }
        Self {
            tool_router: Self::tool_router(),
            hub: std::env::var("HAIVE_HUB").unwrap_or_else(|_| "http://localhost:8770".to_string()),
            mtok: std::env::var("HIVE_MCP_TOKEN").unwrap_or_default(),
            owner: std::env::var("HIVE_OWNER").unwrap_or_default(),
            client: b.build().expect("build http client"),
            direct_client: std::sync::Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Build a hub /m URL: `{hub}/m/{action}?mtok=…&owner=…[&extra]`.
    fn m(&self, action: &str, extra: &str) -> String {
        let base = self.hub.trim_end_matches('/');
        let mut u = format!("{base}/m/{action}?mtok={}&owner={}", urlencode(&self.mtok), urlencode(&self.owner));
        if !extra.is_empty() {
            u.push('&');
            u.push_str(extra);
        }
        u
    }

    async fn agents(&self) -> Result<Vec<AgentInfo>, String> {
        let v: serde_json::Value = self
            .client
            .get(self.m("agents", ""))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(serde_json::from_value(v["agents"].clone()).unwrap_or_default())
    }

    /// Resolve a device name to its hub proxy target.
    async fn resolve(&self, name: &str) -> Result<String, String> {
        let agents = self.agents().await?;
        let exact: Vec<&AgentInfo> = agents.iter().filter(|a| a.name.eq_ignore_ascii_case(name) || a.ip == name).collect();
        let m: Vec<&AgentInfo> = if exact.is_empty() {
            agents.iter().filter(|a| a.name.to_lowercase().contains(&name.to_lowercase())).collect()
        } else {
            exact
        };
        match m.len() {
            0 if agents.is_empty() => Err(format!(
                "no devices visible for this owner ('{}'). Check HIVE_OWNER matches how the device was enrolled (--owner …), or unset it to see all.",
                self.owner
            )),
            0 => Err(format!(
                "no device matching '{name}'. Visible devices: {}",
                agents.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", ")
            )),
            1 => Ok(m[0].target()),
            _ => Err(format!("ambiguous device: {}", m.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", "))),
        }
    }

    async fn input(&self, target: &str, ev: serde_json::Value) -> Result<(), ErrorData> {
        self.client
            .post(self.m("input", ""))
            .json(&serde_json::json!({"target": target, "ev": ev}))
            .send()
            .await
            .map_err(err)?;
        Ok(())
    }
    /// A reqwest client that trusts the hub CA (fetched once from /m/ca) — used
    /// for direct LAN connections to an agent's hub-signed cert. Fast connect
    /// timeout so an unreachable LAN IP falls back to the relay quickly.
    async fn direct_client(&self) -> Option<&reqwest::Client> {
        self.direct_client
            .get_or_try_init(|| async {
                let pem = self.client.get(self.m("ca", "")).send().await.map_err(|_| ())?.bytes().await.map_err(|_| ())?;
                let ca = reqwest::Certificate::from_pem(&pem).map_err(|_| ())?;
                reqwest::Client::builder()
                    .add_root_certificate(ca)
                    .connect_timeout(std::time::Duration::from_secs(2))
                    .build()
                    .map_err(|_| ())
            })
            .await
            .ok()
    }

    /// Ask the hub for a device's LAN IPs + its per-device direct token.
    async fn direct_info(&self, target: &str) -> Option<(Vec<String>, String)> {
        let v: serde_json::Value = self.client.get(self.m("direct", &format!("target={}", urlencode(target)))).send().await.ok()?.json().await.ok()?;
        let ips = v.get("ips")?.as_array()?.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>();
        let token = v.get("token")?.as_str()?.to_string();
        Some((ips, token))
    }

    /// Try to run the command directly over the LAN (validated against the hub
    /// CA, authorized by the per-device token). Returns None to fall back to relay.
    async fn try_direct_exec(&self, target: &str, cmd: &str, detach: bool) -> Option<serde_json::Value> {
        let (ips, token) = self.direct_info(target).await?;
        if ips.is_empty() {
            return None;
        }
        let client = self.direct_client().await?;
        for ip in ips {
            let url = format!("https://{ip}:8765/exec?dtok={}", urlencode(&token));
            if let Ok(r) = client.post(&url).timeout(std::time::Duration::from_secs(65)).json(&serde_json::json!({"cmd": cmd, "detach": detach})).send().await {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    return Some(v);
                }
            }
        }
        None
    }

}

#[tool_router]
impl Srv {
    #[tool(description = "List devices you own on the hub, with full details (OS, user, CPU, memory, live CPU load + free RAM, interfaces, cameras, mics, last-seen). Returns JSON.")]
    async fn list_devices(&self) -> Result<CallToolResult, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("agents", "")).send().await.map_err(err)?.json().await.map_err(err)?;
        let agents = v.get("agents").cloned().unwrap_or_else(|| serde_json::json!([]));
        // Surface the owner-scoping hint on an empty list so it self-diagnoses.
        if agents.as_array().map(|a| a.is_empty()).unwrap_or(true) {
            let hint = if self.owner.is_empty() {
                "No devices are registered on the hub yet.".to_string()
            } else {
                format!(
                    "No devices visible for this owner ('{}'). HIVE_OWNER must match the email the device enrolled under (--owner …); unset HIVE_OWNER to see all devices for this token.",
                    self.owner
                )
            };
            return Ok(CallToolResult::success(vec![ContentBlock::text(hint)]));
        }
        let text = serde_json::to_string_pretty(&agents).unwrap_or_else(|_| "[]".to_string());
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Run a shell command on the named device and return its output.")]
    async fn run_command(&self, Parameters(a): Parameters<RunArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let out: serde_json::Value = match self.try_direct_exec(&target, &a.command, a.detach).await {
            Some(v) => v,
            None => self
                .client
                .post(self.m("exec", ""))
                .json(&serde_json::json!({"target": target, "cmd": a.command, "detach": a.detach}))
                .send()
                .await
                .map_err(err)?
                .json()
                .await
                .map_err(err)?,
        };
        let text = if out["detached"].as_bool().unwrap_or(false) {
            format!("launched (pid {})", out["pid"].as_i64().unwrap_or(0))
        } else if out["ok"].as_bool().unwrap_or(false) {
            let s = format!("{}{}", out["stdout"].as_str().unwrap_or(""), out["stderr"].as_str().unwrap_or(""));
            if s.is_empty() { format!("(exit {})", out["code"].as_i64().unwrap_or(0)) } else { s }
        } else {
            format!("[error] {}", out["error"].as_str().unwrap_or("failed"))
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Capture the current screen of the named device as an image.")]
    async fn screenshot(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let bytes = self
            .client
            .get(self.m("frame", &format!("target={}", urlencode(&target))))
            .send()
            .await
            .map_err(err)?
            .bytes()
            .await
            .map_err(err)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(CallToolResult::success(vec![ContentBlock::image(b64, "image/jpeg")]))
    }

    #[tool(description = "Capture a photo from the device's camera (webcam). Optional index selects the camera (default 0).")]
    async fn camera_snapshot(&self, Parameters(a): Parameters<CameraArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let extra = match a.index {
            Some(i) => format!("target={}&index={i}", urlencode(&target)),
            None => format!("target={}", urlencode(&target)),
        };
        let bytes = self.client.get(self.m("camera", &extra)).send().await.map_err(err)?.bytes().await.map_err(err)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(CallToolResult::success(vec![ContentBlock::image(b64, "image/jpeg")]))
    }

    #[tool(description = "Update the agent on the device to the latest build hosted by the hub (self-replace + restart).")]
    async fn update_agent(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let text = self.client.get(self.m("update", &format!("target={}", urlencode(&target)))).send().await.map_err(err)?.text().await.map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Dissolve the agent on the device — stop it and remove its autostart (the binary is not deleted).")]
    async fn dissolve_agent(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let text = self.client.get(self.m("dissolve", &format!("target={}", urlencode(&target)))).send().await.map_err(err)?.text().await.map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Download a file from the device to the Mac. Returns the local path.")]
    async fn download_file(&self, Parameters(a): Parameters<DownloadArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let url = self.m("download", &format!("target={}&path={}", urlencode(&target), urlencode(&a.remote_path)));
        let bytes = self.client.get(url).send().await.map_err(err)?.bytes().await.map_err(err)?;
        let local = a.save_as.filter(|s| !s.is_empty()).unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_default();
            let name = std::path::Path::new(&a.remote_path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "download".to_string());
            format!("{home}/Downloads/{name}")
        });
        std::fs::write(&local, &bytes).map_err(err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("saved to {local}"))]))
    }

    #[tool(description = "Upload a local file to the device. Returns the saved remote path.")]
    async fn upload_file(&self, Parameters(a): Parameters<UploadArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let data = std::fs::read(&a.local_path).map_err(err)?;
        let name = std::path::Path::new(&a.local_path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "upload.bin".to_string());
        let part = reqwest::multipart::Part::bytes(data).file_name(name);
        let mut form = reqwest::multipart::Form::new().part("file", part);
        if let Some(dir) = a.remote_dir.filter(|d| !d.is_empty()) {
            form = form.text("dir", dir);
        }
        let out: serde_json::Value = self
            .client
            .post(self.m("upload", &format!("target={}", urlencode(&target))))
            .multipart(form)
            .send()
            .await
            .map_err(err)?
            .json()
            .await
            .map_err(err)?;
        let text = if out["ok"].as_bool().unwrap_or(false) {
            out["saved"].as_str().unwrap_or("").to_string()
        } else {
            format!("[error] {}", out["error"].as_str().unwrap_or("failed"))
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(description = "Click at a position on the device's screen. x and y are fractions 0.0-1.0 from the top-left.")]
    async fn click(&self, Parameters(a): Parameters<ClickArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let btn = match a.button.as_deref() { Some("right") => 2, Some("middle") => 1, _ => 0 };
        self.input(&target, serde_json::json!({"type":"down","button":btn,"x":a.x,"y":a.y})).await?;
        self.input(&target, serde_json::json!({"type":"up","button":btn})).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("clicked at ({:.3}, {:.3})", a.x, a.y))]))
    }

    #[tool(description = "Type text on the device as keystrokes.")]
    async fn type_text(&self, Parameters(a): Parameters<TypeArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        for c in a.text.chars() {
            let k = c.to_string();
            self.input(&target, serde_json::json!({"type":"key","action":"down","key":k})).await?;
            self.input(&target, serde_json::json!({"type":"key","action":"up","key":k})).await?;
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("typed {} chars", a.text.chars().count()))]))
    }

    #[tool(description = "Press a named key on the device (e.g. Enter, Tab, Escape, Backspace, ArrowDown).")]
    async fn press_key(&self, Parameters(a): Parameters<KeyArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        self.input(&target, serde_json::json!({"type":"key","action":"down","key":a.key})).await?;
        self.input(&target, serde_json::json!({"type":"key","action":"up","key":a.key})).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("pressed {}", a.key))]))
    }

    async fn sys(&self, device: &str, kind: &str, arg: &str) -> Result<String, ErrorData> {
        let target = self.resolve(device).await.map_err(err)?;
        let mut extra = format!("kind={}&target={}", urlencode(kind), urlencode(&target));
        if !arg.is_empty() {
            extra.push_str(&format!("&arg={}", urlencode(arg)));
        }
        let v: serde_json::Value = self.client.get(self.m("sys", &extra)).send().await.map_err(err)?.json().await.map_err(err)?;
        Ok(v["output"].as_str().or_else(|| v["error"].as_str()).unwrap_or("failed").to_string())
    }

    #[tool(description = "Get a system report from a device. kind: hardware, av (antivirus status), encryption (disk encryption), firewall, processes, services, network (ARP neighbors), packages (installed software).")]
    async fn system_report(&self, Parameters(a): Parameters<ReportArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, &a.kind, "").await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Run a device action: reboot, shutdown, sleep, logoff, firewall_on, firewall_off, usb_lock, usb_unlock (USB storage lock is Windows-only).")]
    async fn device_action(&self, Parameters(a): Parameters<ActionArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, &a.action, "").await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("{}: {}", a.action, out))]))
    }

    #[tool(description = "Show a popup message to the logged-in user on the device.")]
    async fn message_user(&self, Parameters(a): Parameters<MessageArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, "message", &a.text).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Install a software package on the device (winget on Windows, brew on macOS, apt on Linux).")]
    async fn install_package(&self, Parameters(a): Parameters<PackageArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, "install", &a.package).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Uninstall a software package from the device (winget/brew/apt).")]
    async fn uninstall_package(&self, Parameters(a): Parameters<PackageArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, "uninstall", &a.package).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Check for available OS/app updates on the device (winget upgrade / softwareupdate -l / apt upgradable). Use device_action 'update_all' to apply them.")]
    async fn check_updates(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, "updates", "").await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Run a security compliance check on the device (disk encryption, firewall, antivirus, OS updates) and return a score/grade with per-check pass/fail.")]
    async fn compliance_posture(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let v: serde_json::Value = self.client.get(self.m("sys", &format!("kind=posture&target={}", urlencode(&target)))).send().await.map_err(err)?.json().await.map_err(err)?;
        let mut s = format!("Compliance: {} ({}/100)\n", v["grade"].as_str().unwrap_or("?"), v["score"].as_i64().unwrap_or(0));
        if let Some(cs) = v["checks"].as_array() {
            for c in cs {
                s.push_str(&format!("  [{}] {}\n", if c["pass"].as_bool().unwrap_or(false) { "PASS" } else { "FAIL" }, c["check"].as_str().unwrap_or("")));
            }
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(s)]))
    }

    async fn fleet(&self, extra: &str) -> Result<String, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("fleet", extra)).send().await.map_err(err)?.json().await.map_err(err)?;
        let out = v["results"]
            .as_array()
            .map(|arr| arr.iter().map(|r| format!("### {}\n{}", r["device"].as_str().unwrap_or("?"), r["output"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n\n"))
            .unwrap_or_else(|| "no devices".to_string());
        Ok(out)
    }

    #[tool(description = "Run a shell command on EVERY device you own, in parallel, and return each device's output.")]
    async fn fleet_run(&self, Parameters(a): Parameters<FleetRunArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.fleet(&format!("kind=exec&cmd={}", urlencode(&a.command))).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Run a system report (hardware, av, encryption, firewall, processes, services, network, packages) on EVERY device you own, in parallel.")]
    async fn fleet_report(&self, Parameters(a): Parameters<FleetReportArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.fleet(&format!("kind={}", urlencode(&a.kind))).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Search the TacticalRMM community-scripts library (amidaware) for a maintenance/diagnostic script. Returns matching scripts with their filename, shell, platforms and name — pass a filename to run_script or run_script_fleet to execute it.")]
    async fn search_scripts(&self, Parameters(a): Parameters<SearchScriptsArgs>) -> Result<CallToolResult, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("scripts", &format!("q={}", urlencode(&a.query)))).send().await.map_err(err)?.json().await.map_err(err)?;
        let list = v["scripts"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(40)
                    .map(|s| {
                        let plats = s["platforms"].as_array().map(|p| p.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default();
                        format!("- {} ({}) — {}", s["filename"].as_str().unwrap_or(""), plats, s["name"].as_str().unwrap_or(""))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("{} of {} scripts match:\n{}", v["count"].as_i64().unwrap_or(0), v["total"].as_i64().unwrap_or(0), list))]))
    }

    #[tool(description = "Run a community script (from search_scripts) on the named device. Pass the script filename. It is fetched from GitHub and run on the device; its output is returned. Subject to a ~65s execution cap.")]
    async fn run_script(&self, Parameters(a): Parameters<RunScriptArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let v: serde_json::Value = self.client.get(self.m("script", &format!("target={}&file={}", urlencode(&target), urlencode(&a.script)))).send().await.map_err(err)?.json().await.map_err(err)?;
        let out = v["output"].as_str().or_else(|| v["error"].as_str()).unwrap_or("failed").to_string();
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Run the security-compliance posture check (disk encryption, firewall, antivirus, OS updates) on EVERY device you own, in parallel. Returns each device's grade + per-check pass/fail. Checks map to CIS / NIST 800-53 / PCI-DSS / HIPAA / ISO 27001 / Essential Eight controls.")]
    async fn fleet_compliance(&self) -> Result<CallToolResult, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("compliance-fleet", "")).send().await.map_err(err)?.json().await.map_err(err)?;
        let out = v["results"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|d| {
                        let checks = d["checks"]
                            .as_array()
                            .map(|cs| cs.iter().map(|c| format!("{} {}", if c["pass"].as_bool().unwrap_or(false) { "PASS" } else { "FAIL" }, c["check"].as_str().unwrap_or(""))).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default();
                        format!("{} — {} ({}/100): {}", d["device"].as_str().unwrap_or("?"), d["grade"].as_str().unwrap_or("?"), d["score"].as_i64().unwrap_or(0), checks)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|| "no devices".to_string());
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Look up known CVEs for a product/keyword via the NVD database. Returns CVE id, CVSS score/severity and summary, highest severity first. A lookup, not an automated scan.")]
    async fn cve_lookup(&self, Parameters(a): Parameters<CveArgs>) -> Result<CallToolResult, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("cve", &format!("q={}", urlencode(&a.query)))).send().await.map_err(err)?.json().await.map_err(err)?;
        let list = v["cves"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(20)
                    .map(|c| format!("{} [{} {}] {} — {}", c["id"].as_str().unwrap_or(""), c["severity"].as_str().unwrap_or("?"), c["score"].as_f64().map(|s| s.to_string()).unwrap_or_default(), c["published"].as_str().unwrap_or(""), c["summary"].as_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join("\n\n")
            })
            .unwrap_or_default();
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("{} CVEs:\n{}", v["count"].as_i64().unwrap_or(0), list))]))
    }

    #[tool(description = "List command-plugins registered on the hub — custom named actions added via JSON manifests. Returns each plugin's id, platforms and name. Run one with run_plugin.")]
    async fn list_plugins(&self) -> Result<CallToolResult, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("plugins", "")).send().await.map_err(err)?.json().await.map_err(err)?;
        let list = v["plugins"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|p| {
                        let plats = p["platforms"].as_array().map(|x| x.iter().filter_map(|y| y.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default();
                        format!("- {} ({}) — {}", p["id"].as_str().unwrap_or(""), plats, p["name"].as_str().unwrap_or(""))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("{} plugins:\n{}", v["count"].as_i64().unwrap_or(0), list))]))
    }

    #[tool(description = "Run a hub command-plugin (from list_plugins) on the named device. Pass the plugin id and an optional arg.")]
    async fn run_plugin(&self, Parameters(a): Parameters<RunPluginArgs>) -> Result<CallToolResult, ErrorData> {
        let out = self.sys(&a.device, &a.plugin, &a.arg).await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }

    #[tool(description = "Run a community script (from search_scripts) on EVERY device you own, in parallel. Pass the script filename.")]
    async fn run_script_fleet(&self, Parameters(a): Parameters<RunScriptFleetArgs>) -> Result<CallToolResult, ErrorData> {
        let v: serde_json::Value = self.client.get(self.m("script-fleet", &format!("file={}", urlencode(&a.script)))).send().await.map_err(err)?.json().await.map_err(err)?;
        let out = v["results"]
            .as_array()
            .map(|arr| arr.iter().map(|r| format!("### {}\n{}", r["device"].as_str().unwrap_or("?"), r["output"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n\n"))
            .unwrap_or_else(|| "no devices".to_string());
        Ok(CallToolResult::success(vec![ContentBlock::text(out)]))
    }
}

#[tool_handler]
impl ServerHandler for Srv {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "Control HaiveControl devices by hub name: list_devices, screenshot, run_command, click/type_text/press_key, download_file, upload_file, camera_snapshot, update_agent, dissolve_agent.".to_string(),
        );
        info
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Srv::new().serve((tokio::io::stdin(), tokio::io::stdout())).await?;
    service.waiting().await?;
    Ok(())
}
