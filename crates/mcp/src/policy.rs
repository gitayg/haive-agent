// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// MCP tool annotations from the hub's graduated-autonomy tiers (hub 3.18.0,
// `autonomy::CATALOG`, served as `/m/policy`). Each tool is annotated with the
// default tier of the hub action it performs; a tool that can perform several
// (device_action: sleep is `change`, reboot is `privileged`) takes the highest.
//
//   read        readOnlyHint true
//   change      readOnlyHint false, destructiveHint false
//   privileged  readOnlyHint false, destructiveHint true  (needs a human's approval)
//
// These are the hub's DEFAULTS. An admin can move an action between tiers in
// policy.json, and a free-form command drops from privileged to change when every
// program in it is on the safe list, so the hub's answer at call time — not this
// table — decides what runs. The annotations only tell a client what to expect.
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::ToolAnnotations;

use crate::Srv;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    Read,
    Change,
    Privileged,
}

/// (tool, hub action, default tier).
pub const TOOLS: &[(&str, &str, Tier)] = &[
    ("list_devices", "list", Tier::Read),
    ("screenshot", "screenshot", Tier::Read),
    ("camera_snapshot", "camera", Tier::Read),
    ("download_file", "download", Tier::Read),
    ("system_report", "report", Tier::Read),
    ("check_updates", "report", Tier::Read),
    ("compliance_posture", "report", Tier::Read),
    ("fleet_report", "report", Tier::Read),
    ("fleet_compliance", "inventory", Tier::Read),
    ("search_scripts", "catalog", Tier::Read),
    ("cve_lookup", "catalog", Tier::Read),
    ("list_plugins", "catalog", Tier::Read),
    ("approval_status", "catalog", Tier::Read),
    ("job_logs", "logs", Tier::Read),
    ("job_list", "logs", Tier::Read),
    ("upload_file", "upload", Tier::Change),
    ("push_file", "upload", Tier::Change),
    ("click", "input", Tier::Change),
    ("type_text", "input", Tier::Change),
    ("press_key", "input", Tier::Change),
    ("message_user", "device_action", Tier::Change),
    ("install_package", "device_action", Tier::Change),
    ("run_plugin", "device_action", Tier::Change),
    ("job_stop", "job_stop", Tier::Change),
    ("run_command", "exec", Tier::Privileged),
    ("job_start", "job_start", Tier::Privileged),
    ("fleet_run", "fleet_run", Tier::Privileged),
    ("run_script", "script", Tier::Privileged),
    ("run_script_fleet", "script_fleet", Tier::Privileged),
    ("uninstall_package", "uninstall", Tier::Privileged),
    ("device_action", "power", Tier::Privileged),
    ("update_agent", "update", Tier::Privileged),
    ("dissolve_agent", "dissolve", Tier::Privileged),
];

pub fn tier(tool: &str) -> Option<Tier> {
    TOOLS.iter().find(|t| t.0 == tool).map(|t| t.2)
}

pub fn annotations(t: Tier) -> ToolAnnotations {
    ToolAnnotations::new().read_only(t == Tier::Read).destructive(t == Tier::Privileged)
}

/// Annotate every tool in `router` that the table knows.
pub fn annotate(router: &mut ToolRouter<Srv>) {
    for (name, route) in router.map.iter_mut() {
        if let Some(t) = tier(name) {
            route.attr.annotations = Some(annotations(t));
        }
    }
}
