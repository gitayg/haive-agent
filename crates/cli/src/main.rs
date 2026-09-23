// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The IT-AI Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// itai — run commands and transfer files against a registered device by
// its hub name. The device is resolved through the hub, so no IP is needed.
//
// Transport is the shared LAN-direct hybrid (`it-ai-direct`): when the device
// answers on its LAN address it is driven directly, otherwise through the hub's
// relay. That is the same module and the same per-device route cache the MCP
// server uses — neither binary carries its own copy of the decision.
use std::process::exit;

use clap::{Parser, Subcommand};
use it_ai_direct::{Controller, Op};
use reqwest::Client;

#[derive(Parser)]
#[command(name = "itai", version = "2.3.0",
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
}

type R = Result<(), Box<dyn std::error::Error>>;

fn build_client(cafile: &Option<String>) -> Client {
    let mut b = Client::builder();
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

async fn cmd_exec(ctl: &Controller, target: &str, command: &[String]) -> R {
    let op = Op::post_json("exec", serde_json::json!({"cmd": command.join(" ")}))
        .target_in_body()
        .timeout(std::time::Duration::from_secs(65));
    let out: serde_json::Value = ctl.call_device(target, op).await?.json().await?;
    if !out["ok"].as_bool().unwrap_or(false) {
        return Err(out["error"].as_str().unwrap_or("failed").into());
    }
    print!("{}", out["stdout"].as_str().unwrap_or(""));
    eprint!("{}", out["stderr"].as_str().unwrap_or(""));
    exit(out["code"].as_i64().unwrap_or(0) as i32);
}

async fn cmd_get(ctl: &Controller, target: &str, remote: &str, local: &Option<String>) -> R {
    let bytes = ctl
        .call_device(target, Op::get("download").query("path", remote))
        .await?
        .bytes()
        .await?;
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

async fn cmd_put(ctl: &Controller, target: &str, local: &str, remote_dir: &Option<String>) -> R {
    let name = std::path::Path::new(local)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "upload.bin".to_string());
    let mut op = Op::post_file("upload", name, std::fs::read(local)?);
    if let Some(dir) = remote_dir {
        op = op.field("dir", dir.clone());
    }
    let out: serde_json::Value = ctl.call_device(target, op).await?.json().await?;
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
    let result = match &cli.cmd {
        Cmd::List => cmd_list(&ctl).await,
        Cmd::Exec { device, command } => match ctl.resolve(device).await {
            Ok(t) => cmd_exec(&ctl, &t, command).await,
            Err(e) => Err(e.into()),
        },
        Cmd::Get { device, remote, local } => match ctl.resolve(device).await {
            Ok(t) => cmd_get(&ctl, &t, remote, local).await,
            Err(e) => Err(e.into()),
        },
        Cmd::Put { device, local, remote_dir } => match ctl.resolve(device).await {
            Ok(t) => cmd_put(&ctl, &t, local, remote_dir).await,
            Err(e) => Err(e.into()),
        },
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        exit(1);
    }
}
