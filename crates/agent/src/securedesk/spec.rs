// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// The SPEC argument of the hidden `--screen-helper <SPEC>` flag, and the exit
// codes the helper reports back.
//
// SPEC carries only non-secret launch parameters:
//   v1:ppid=<u32>,port=<u16>,mon=<usize>,q=<u8>,w=<u32>,idle=<secs>
// The per-launch key travels in the helper's environment block (`KEY_ENV`), not
// on the command line: since Windows 8.1 a process's command line can be read
// with only PROCESS_QUERY_LIMITED_INFORMATION, while reading its environment
// needs PROCESS_VM_READ. The helper removes the variable as soon as it reads it.
#![cfg_attr(not(windows), allow(dead_code))]

pub const KEY_ENV: &str = "ITAI_SCREEN_HELPER_KEY";

/// The helper exited because nobody used it for `idle` seconds — normal, not a failure.
pub const EXIT_IDLE: u32 = 0;
/// The service that launched it is gone.
pub const EXIT_PARENT_GONE: u32 = 10;
/// SPEC or key missing/malformed.
pub const EXIT_BAD_SPEC: u32 = 11;
/// Couldn't bind 127.0.0.1:<port>.
pub const EXIT_BIND: u32 = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperSpec {
    pub ppid: u32,
    pub port: u16,
    pub monitor: usize,
    pub quality: u8,
    pub max_width: u32,
    pub idle_secs: u64,
}

impl HelperSpec {
    pub fn format(&self) -> String {
        format!(
            "v1:ppid={},port={},mon={},q={},w={},idle={}",
            self.ppid, self.port, self.monitor, self.quality, self.max_width, self.idle_secs
        )
    }

    pub fn parse(s: &str) -> Result<HelperSpec, String> {
        let body = s.strip_prefix("v1:").ok_or("SPEC must start with v1:")?;
        let (mut ppid, mut port, mut mon, mut q, mut w, mut idle) = (None, None, None, None, None, None);
        for kv in body.split(',') {
            let (k, v) = kv.split_once('=').ok_or_else(|| format!("bad SPEC field {kv:?}"))?;
            let slot = match k {
                "ppid" => &mut ppid,
                "port" => &mut port,
                "mon" => &mut mon,
                "q" => &mut q,
                "w" => &mut w,
                "idle" => &mut idle,
                _ => return Err(format!("unknown SPEC field {k:?}")),
            };
            if slot.is_some() {
                return Err(format!("duplicate SPEC field {k:?}"));
            }
            *slot = Some(v.parse::<u64>().map_err(|_| format!("SPEC field {k} is not a number"))?);
        }
        let need = |v: Option<u64>, k: &str| v.ok_or_else(|| format!("SPEC is missing {k}"));
        let spec = HelperSpec {
            ppid: u32::try_from(need(ppid, "ppid")?).map_err(|_| "ppid out of range")?,
            port: u16::try_from(need(port, "port")?).map_err(|_| "port out of range")?,
            monitor: usize::try_from(need(mon, "mon")?).map_err(|_| "mon out of range")?,
            quality: u8::try_from(need(q, "q")?).map_err(|_| "q out of range")?,
            max_width: u32::try_from(need(w, "w")?).map_err(|_| "w out of range")?,
            idle_secs: need(idle, "idle")?,
        };
        if spec.ppid == 0 || spec.port == 0 {
            return Err("ppid and port must be non-zero".into());
        }
        if !(30..=86_400).contains(&spec.idle_secs) {
            return Err("idle must be 30..=86400 seconds".into());
        }
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HelperSpec {
        HelperSpec { ppid: 4242, port: 50123, monitor: 1, quality: 60, max_width: 1600, idle_secs: 600 }
    }

    #[test]
    fn spec_round_trips() {
        let s = sample().format();
        assert_eq!(s, "v1:ppid=4242,port=50123,mon=1,q=60,w=1600,idle=600");
        assert_eq!(HelperSpec::parse(&s), Ok(sample()));
    }

    #[test]
    fn spec_never_contains_the_key() {
        assert!(!sample().format().to_lowercase().contains("key"));
        assert!(!sample().format().to_lowercase().contains("secret"));
    }

    #[test]
    fn spec_rejects_malformed_input() {
        for bad in [
            "",
            "ppid=1,port=2,mon=0,q=60,w=1600,idle=600",
            "v2:ppid=1,port=2,mon=0,q=60,w=1600,idle=600",
            "v1:ppid=1,port=2,mon=0,q=60,w=1600",
            "v1:ppid=1,port=2,mon=0,q=60,w=1600,idle=600,key=abc",
            "v1:ppid=1,ppid=2,port=2,mon=0,q=60,w=1600,idle=600",
            "v1:ppid=0,port=2,mon=0,q=60,w=1600,idle=600",
            "v1:ppid=1,port=0,mon=0,q=60,w=1600,idle=600",
            "v1:ppid=1,port=70000,mon=0,q=60,w=1600,idle=600",
            "v1:ppid=1,port=2,mon=0,q=300,w=1600,idle=600",
            "v1:ppid=1,port=2,mon=0,q=60,w=1600,idle=5",
            "v1:ppid=1,port=2,mon=0,q=-1,w=1600,idle=600",
            "v1:ppid=1,port=2,mon=0,q=60,w=1600,idle",
        ] {
            assert!(HelperSpec::parse(bad).is_err(), "accepted {bad:?}");
        }
    }
}
