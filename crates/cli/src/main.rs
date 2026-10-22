// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
//
// itai — run commands and transfer files against a registered device by
// its hub name. The device is resolved through the hub, so no IP is needed.
//
// Transport is the shared LAN-direct hybrid (`it-ai-direct`): when the device
// answers on its LAN address it is driven directly, otherwise through the hub's
// relay. That is the same module and the same per-device route cache the MCP
// server uses — neither binary carries its own copy of the decision.
use std::process::exit;

mod approval;
mod jobs;

use approval::Step;
use clap::{Parser, Subcommand};
use it_ai_direct::reply::{self, Wait};
use it_ai_direct::{Controller, Op};
use reqwest::Client;

#[derive(Parser)]
#[command(name = "itai", version = "2.5.0",
    about = "Drive a IT-AI device from the Mac (resolved by hub name).")]
struct Cli {
    /// hub URL
    #[arg(long, env = "HAIVE_HUB", default_value = "http://localhost:8770")]
    hub: String,
    /// token for the hub's /m API (matches the hub's MCP_TOKEN)
    #[arg(long, env = "HIVE_MCP_TOKEN", default_value = "")]
    mtok: String,
    /// owner id to act as (per-user hub scoping)
    #[arg(long, env = "HIVE_OWNER", default_value = "")]
    owner: String,
    /// agent password, if one was set
    #[arg(long, env = "SCREEN_PW")]
    password: Option<String>,
    /// agent cert.pem to verify TLS against (else unverified — LAN only)
    #[arg(long, env = "HAIVE_CAFILE")]
    cafile: Option<String>,
    /// seconds to wait for a human to approve a privileged action in the IT-AI
    /// dashboard (default 60; `itai approval` waits only when this is given)
    #[arg(long, global = true, value_name = "SECS")]
    wait: Option<u64>,
    /// ask the hub what exec / put / job start / job stop would do (tier, approval,
    /// devices) without running anything
    #[arg(long, global = true)]
    dry_run: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// list registered devices
    List,
    /// run a command on a device
    Exec {
        device: String,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// download a file from a device
    Get {
        device: String,
        remote: String,
        local: Option<String>,
    },
    /// upload a file to a device
    Put {
        device: String,
        local: String,
        remote_dir: Option<String>,
    },
    /// background jobs that outlive one exec: start, logs, stop, list
    Job {
        #[command(subcommand)]
        cmd: jobs::JobCmd,
    },
    /// check an approval request (the id a privileged action printed)
    Approval { id: String },
}

/// How an action call treats the hub's tiers.
#[derive(Clone, Copy)]
pub struct Opts {
    pub wait: Wait,
    pub dry_run: bool,
}

type R = Result<(), Box<dyn std::error::Error>>;

/// The hub client: `X-IT-AI-Client: cli` on every request, so the hub attributes
/// a shared-token call to the CLI rather than an AI agent.
fn build_client(cafile: &Option<String>) -> Client {
    let mut b = Client::builder().default_headers(reply::client_headers("cli"));
    // Add an explicit hub CA as a trusted root (for self-signed LAN-direct agents).
    // The public hub endpoint verifies against the system roots with no cafile.
    if let Some(path) = cafile {
        match std::fs::read(path).ok().and_then(|p| reqwest::Certificate::from_pem(&p).ok()) {
            Some(cert) => b = b.add_root_certificate(cert),
            None => eprintln!("warning: could not read cafile {path}; using system roots"),
        }
    }
    // TLS verification is ON by default. Insecure mode is an explicit, logged opt-in
    // (self-signed LAN use only) — it used to be the silent default with no cafile.
    if std::env::var("HAIVE_INSECURE_TLS").ok().as_deref() == Some("1") {
        eprintln!("warning: TLS verification DISABLED (HAIVE_INSECURE_TLS=1) — LAN use only");
        b = b.danger_accept_invalid_certs(true);
    }
    b.build().expect("build http client")
}

async fn cmd_list(ctl: &Controller) -> R {
    for a in ctl.agents().await? {
        println!("{:24} {}", a.name, a.target());
    }
    Ok(())
}

/// Run `op` on the device (or only ask the hub about it) and settle the answer.
async fn device_step(ctl: &Controller, target: &str, op: Op, o: Opts) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let resp = if o.dry_run { ctl.dry_run(target, op).await } else { ctl.call_device(target, op).await }?;
    let r = reply::read(resp).await?;
    match approval::resolve(ctl, r, o.wait, &mut std::io::stderr()).await {
        Step::Run(v) => Ok(v),
        Step::Stop { text, code } => approval::stop(&text, code),
    }
}

async fn cmd_exec(ctl: &Controller, target: &str, command: &[String], o: Opts) -> R {
    let op = Op::post_json("exec", serde_json::json!({"cmd": command.join(" ")}))
        .target_in_body()
        .timeout(std::time::Duration::from_secs(65));
    let out = device_step(ctl, target, op, o).await?;
    if let serde_json::Value::String(s) = &out {
        return Err(s.clone().into());
    }
    if !out["ok"].as_bool().unwrap_or(false) {
        return Err(out["error"].as_str().unwrap_or("failed").into());
    }
    print!("{}", out["stdout"].as_str().unwrap_or(""));
    eprint!("{}", out["stderr"].as_str().unwrap_or(""));
    exit(out["code"].as_i64().unwrap_or(0) as i32);
}

async fn cmd_get(ctl: &Controller, target: &str, remote: &str, local: &Option<String>) -> R {
    let resp = ctl.call_device(target, Op::get("download").query("path", remote)).await?;
    let bytes = match reply::bytes_or_reply(resp).await? {
        Ok(b) => b,
        Err(r) => match approval::step(ctl.settle(r, Wait::secs(0)).await, &mut std::io::stderr()) {
            Step::Run(v) => return Err(reply::result_text(&v).into()),
            Step::Stop { text, code } => approval::stop(&text, code),
        },
    };
    let local = local.clone().unwrap_or_else(|| {
        std::path::Path::new(remote)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "download".to_string())
    });
    std::fs::write(&local, &bytes)?;
    println!("saved → {local}");
    Ok(())
}

async fn cmd_put(ctl: &Controller, target: &str, local: &str, remote_dir: &Option<String>, o: Opts) -> R {
    let name = std::path::Path::new(local)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "upload.bin".to_string());
    // A dry run asks about the request; the file itself is not sent.
    let data = if o.dry_run { Vec::new() } else { std::fs::read(local)? };
    let mut op = Op::post_file("upload", name, data);
    if let Some(dir) = remote_dir {
        op = op.field("dir", dir.clone());
    }
    let out = device_step(ctl, target, op, o).await?;
    if out["ok"].as_bool().unwrap_or(false) {
        println!("{}", out["saved"].as_str().unwrap_or(""));
    } else {
        return Err(out["error"].as_str().unwrap_or("failed").into());
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();
    let ctl = Controller::new(cli.hub, cli.mtok, cli.owner, build_client(&cli.cafile))
        .with_password(cli.password);
    let o = Opts { wait: Wait::secs(cli.wait.unwrap_or(60)), dry_run: cli.dry_run };
    let result = match &cli.cmd {
        Cmd::List => cmd_list(&ctl).await,
        Cmd::Approval { id } => match approval::check(&ctl, id, Wait::secs(cli.wait.unwrap_or(0)), &mut std::io::stderr()).await {
            Ok(Step::Stop { text, code }) => approval::stop(&text, code),
            Ok(Step::Run(_)) => Ok(()),
            Err(e) => Err(e.into()),
        },
        Cmd::Exec { device, command } => match ctl.resolve(device).await {
            Ok(t) => cmd_exec(&ctl, &t, command, o).await,
            Err(e) => Err(e.into()),
        },
        Cmd::Get { device, remote, local } => match ctl.resolve(device).await {
            Ok(t) => cmd_get(&ctl, &t, remote, local).await,
            Err(e) => Err(e.into()),
        },
        Cmd::Put { device, local, remote_dir } => match ctl.resolve(device).await {
            Ok(t) => cmd_put(&ctl, &t, local, remote_dir, o).await,
            Err(e) => Err(e.into()),
        },
        Cmd::Job { cmd } => match ctl.resolve(cmd.device()).await {
            Ok(t) => jobs::run(&ctl, &t, cmd, o).await,
            Err(e) => Err(e.into()),
        },
    };
    if let Err(e) = result {
        eprintln!("error: {}", jobs::redact_token(&e.to_string()));
        exit(1);
    }
}
