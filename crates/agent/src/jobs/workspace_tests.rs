use super::*;

fn sh(cmd: &str) -> Command {
    let mut c = Command::new("sh");
    c.arg("-c").arg(cmd);
    c
}

fn scratch(name: &str) -> (Registry, PathBuf) {
    let d = std::env::temp_dir().join(format!("it-ai-jobws-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    (Registry::new(d.join("jobs"), d.join("workspaces")), d)
}

fn start_ws(r: &Registry, cmd: &str) -> (String, PathBuf) {
    let (v, code) = r.start(&json!({"cmd": cmd, "workspace": true}).to_string(), sh);
    assert_eq!(code, 200, "{v}");
    (v["id"].as_str().unwrap().to_string(), PathBuf::from(v["workspace"].as_str().expect("start must name the workspace")))
}

fn wait_done(r: &Registry, id: &str) {
    let (_, exit) = r.exit_of(id).unwrap();
    assert!(wait_exit(&exit, Duration::from_secs(10)), "job {id} did not exit");
}

fn wait_log(r: &Registry, id: &str, needle: &str) -> String {
    let t = Instant::now();
    loop {
        let data = r.logs(id, None, None).0["data"].as_str().unwrap().to_string();
        if data.contains(needle) {
            return data;
        }
        assert!(t.elapsed() < Duration::from_secs(5), "{needle:?} never logged: {data:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn jobs_workspace_is_cwd_and_env_then_removed_on_exit() {
    let (r, base) = scratch("exit");
    let (id, ws) = start_ws(&r, "pwd -P; echo \"env=$IT_AI_WORKSPACE\"; echo data > made.txt; mkdir -p a/b; echo x > a/b/c; exit 7");
    assert_eq!(ws, base.join("workspaces").join(&id));
    wait_done(&r, &id);
    let (v, _) = r.logs(&id, None, None);
    assert_eq!(v["exit_code"], 7);
    let data = v["data"].as_str().unwrap();
    let real = std::fs::canonicalize(base.join("workspaces")).unwrap().join(&id);
    assert!(data.contains(&format!("{}\n", real.display())), "cwd was not the workspace: {data:?}");
    assert!(data.contains(&format!("env={}\n", ws.display())), "IT_AI_WORKSPACE not set: {data:?}");
    assert!(!ws.exists(), "workspace {ws:?} survived the job's exit");
    assert_eq!(v["workspace"].as_str(), ws.to_str(), "status must carry the workspace");
    let (l, _) = r.list();
    assert_eq!(l["jobs"][0]["workspace"].as_str(), ws.to_str(), "list must carry the workspace");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn jobs_workspace_is_removed_when_the_job_is_stopped() {
    let (r, base) = scratch("stop");
    let (id, ws) = start_ws(&r, "echo kept > f; sleep 300 & echo started; wait");
    wait_log(&r, &id, "started");
    assert!(ws.join("f").exists(), "the job did not write into its workspace");
    let (v, code) = r.stop(&id);
    assert_eq!((code, v["stopped"].as_bool()), (200, Some(true)), "{v}");
    assert!(!ws.exists(), "workspace {ws:?} survived stop");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn jobs_workspace_two_jobs_get_separate_folders() {
    let (r, base) = scratch("two");
    let (a, wa) = start_ws(&r, "sleep 300");
    let (b, wb) = start_ws(&r, "sleep 300");
    assert_ne!(wa, wb);
    assert!(wa.is_dir() && wb.is_dir());
    r.stop(&a);
    assert!(!wa.exists() && wb.is_dir(), "stopping one job touched the other's workspace");
    r.stop(&b);
    assert!(!wb.exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn jobs_without_workspace_flag_are_unchanged() {
    let (r, base) = scratch("none");
    for body in [json!({"cmd": "echo \"env=[$IT_AI_WORKSPACE]\""}), json!({"cmd": "echo \"env=[$IT_AI_WORKSPACE]\"", "workspace": false})] {
        let (v, code) = r.start(&body.to_string(), sh);
        assert_eq!(code, 200, "{v}");
        assert!(v.get("workspace").is_none(), "{v}");
        let id = v["id"].as_str().unwrap().to_string();
        wait_done(&r, &id);
        let (l, _) = r.logs(&id, None, None);
        assert!(l.get("workspace").is_none(), "{l}");
        assert!(l["data"].as_str().unwrap().contains("env=[]"), "{l}");
    }
    let (l, _) = r.list();
    assert!(l["jobs"].as_array().unwrap().iter().all(|j| j.get("workspace").is_none()), "{l}");
    assert!(!base.join("workspaces").exists(), "a workspace was made without the flag");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn jobs_workspace_refuses_a_cwd_too() {
    let (r, base) = scratch("cwd");
    let (v, code) = r.start(&json!({"cmd": "true", "workspace": true, "cwd": "/tmp"}).to_string(), sh);
    assert_eq!((code, v["error"].as_str()), (400, Some("cwd and workspace cannot be combined")));
    assert!(!base.join("workspaces").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn jobs_workspace_is_removed_when_the_spawn_fails() {
    let (r, base) = scratch("spawnfail");
    fn missing(_: &str) -> Command {
        Command::new("/nonexistent/it-ai-no-such-shell")
    }
    let (v, code) = r.start(&json!({"cmd": "true", "workspace": true}).to_string(), missing);
    assert_eq!(code, 500, "{v}");
    let left: Vec<_> = std::fs::read_dir(base.join("workspaces")).unwrap().flatten().collect();
    assert!(left.is_empty(), "a failed start left {left:?}");
    let _ = std::fs::remove_dir_all(&base);
}
