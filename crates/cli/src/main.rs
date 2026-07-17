// HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The HaiveControl Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// haivectl — run commands and transfer files against a registered device by
// its hub name. The device is resolved through the hub, so no IP is needed.
use std::process::exit;

use clap::{Parser, Subcommand};
use reqwest::blocking::Client;

#[derive(Parser)]
#[command(name = "haivectl", version = "2.3.0",
    about = "Drive a HaiveControl device from the Mac (resolved by hub name).")]
struct Cli {
    /// hub URL
    #[arg(long, env = "HAIVE_HUB", default_value = "http://localhost:8770")]
    hub: String,
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
    match cafile {
        Some(path) => match std::fs::read(path).ok().and_then(|p| reqwest::Certificate::from_pem(&p).ok()) {
            Some(cert) => b = b.add_root_certificate(cert),
            None => eprintln!("warning: could not read cafile {path}; TLS not verified"),
        },
        None => {
            eprintln!("warning: TLS not verified (no --cafile) — LAN use only");
            b = b.danger_accept_invalid_certs(true);
        }
    }
    b.build().expect("build http client")
}

fn resolve(client: &Client, hub: &str, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let v: serde_json::Value = client
        .get(format!("{}/agents", hub.trim_end_matches('/')))
        .send()?
        .json()?;
    let agents = v["agents"].as_array().cloned().unwrap_or_default();
    let matches: Vec<&serde_json::Value> = {
        let exact: Vec<_> = agents
            .iter()
            .filter(|a| {
                a["name"].as_str().map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false)
                    || a["ip"].as_str() == Some(name)
            })
            .collect();
        if exact.is_empty() {
            agents
                .iter()
                .filter(|a| a["name"].as_str().map(|n| n.to_lowercase().contains(&name.to_lowercase())).unwrap_or(false))
                .collect()
        } else {
            exact
        }
    };
    if matches.is_empty() {
        return Err(format!("no device matching '{name}' (try: haivectl list)").into());
    }
    if matches.len() > 1 {
        let names: Vec<_> = matches.iter().filter_map(|a| a["name"].as_str()).collect();
        return Err(format!("'{name}' is ambiguous: {}", names.join(", ")).into());
    }
    let a = matches[0];
    Ok(format!(
        "{}://{}:{}",
        a["scheme"].as_str().unwrap_or("http"),
        a["ip"].as_str().unwrap_or(""),
        a["port"].as_u64().unwrap_or(8765)
    ))
}

fn auth<'a>(rb: reqwest::blocking::RequestBuilder, pw: &Option<String>) -> reqwest::blocking::RequestBuilder {
    match pw {
        Some(p) => rb.basic_auth("admin", Some(p)),
        None => rb,
    }
}

fn cmd_list(client: &Client, hub: &str) -> R {
    let v: serde_json::Value = client.get(format!("{}/agents", hub.trim_end_matches('/'))).send()?.json()?;
    for a in v["agents"].as_array().cloned().unwrap_or_default() {
        println!(
            "{:24} {}://{}:{}",
            a["name"].as_str().unwrap_or("?"),
            a["scheme"].as_str().unwrap_or("http"),
            a["ip"].as_str().unwrap_or(""),
            a["port"].as_u64().unwrap_or(0)
        );
    }
    Ok(())
}

fn cmd_exec(client: &Client, base: &str, pw: &Option<String>, command: &[String]) -> R {
    let body = serde_json::json!({"cmd": command.join(" ")});
    let out: serde_json::Value = auth(client.post(format!("{base}/exec")), pw).json(&body).send()?.json()?;
    if !out["ok"].as_bool().unwrap_or(false) {
        return Err(out["error"].as_str().unwrap_or("failed").into());
    }
    print!("{}", out["stdout"].as_str().unwrap_or(""));
    eprint!("{}", out["stderr"].as_str().unwrap_or(""));
    exit(out["code"].as_i64().unwrap_or(0) as i32);
}

fn cmd_get(client: &Client, base: &str, pw: &Option<String>, remote: &str, local: &Option<String>) -> R {
    let url = format!("{base}/download?path={}", urlencode(remote));
    let bytes = auth(client.get(url), pw).send()?.bytes()?;
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

fn cmd_put(client: &Client, base: &str, pw: &Option<String>, local: &str, remote_dir: &Option<String>) -> R {
    let mut form = reqwest::blocking::multipart::Form::new().file("file", local)?;
    if let Some(dir) = remote_dir {
        form = form.text("dir", dir.clone());
    }
    let out: serde_json::Value = auth(client.post(format!("{base}/upload")), pw).multipart(form).send()?.json()?;
    if out["ok"].as_bool().unwrap_or(false) {
        println!("{}", out["saved"].as_str().unwrap_or(""));
    } else {
        return Err(out["error"].as_str().unwrap_or("failed").into());
    }
    Ok(())
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn main() {
    let cli = Cli::parse();
    let client = build_client(&cli.cafile);
    let result = match &cli.cmd {
        Cmd::List => cmd_list(&client, &cli.hub),
        Cmd::Exec { device, command } => match resolve(&client, &cli.hub, device) {
            Ok(base) => cmd_exec(&client, &base, &cli.password, command),
            Err(e) => Err(e),
        },
        Cmd::Get { device, remote, local } => match resolve(&client, &cli.hub, device) {
            Ok(base) => cmd_get(&client, &base, &cli.password, remote, local),
            Err(e) => Err(e),
        },
        Cmd::Put { device, local, remote_dir } => match resolve(&client, &cli.hub, device) {
            Ok(base) => cmd_put(&client, &base, &cli.password, local, remote_dir),
            Err(e) => Err(e),
        },
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        exit(1);
    }
}
