use super::free_bytes;

const GIB: u64 = 1_073_741_824;

#[test]
fn a_macos_level_is_that_percent_of_total_ram() {
    assert_eq!(free_bytes(48 * GIB, 7, Some(45)), 48 * GIB * 45 / 100);
}

#[test]
fn level_zero_is_nothing_free_and_level_100_is_all_of_it() {
    assert_eq!(free_bytes(48 * GIB, 7, Some(0)), 0);
    assert_eq!(free_bytes(48 * GIB, 7, Some(100)), 48 * GIB);
}

#[test]
fn without_a_level_it_is_sysinfo_available_memory() {
    assert_eq!(free_bytes(48 * GIB, 13 * GIB, None), 13 * GIB);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_reports_a_memory_pressure_level() {
    let l = super::memorystatus_level().expect("sysctl kern.memorystatus_level unreadable");
    assert!(l <= 100, "level {l}");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_live_metrics_report_free_ram_above_zero_and_within_total() {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let total_gb = sys.total_memory() as f64 / GIB as f64;
    let free_gb = crate::live_metrics()["free_gb"].as_f64().unwrap();
    assert!(free_gb > 0.0 && free_gb <= total_gb, "free_gb={free_gb} total_gb={total_gb}");
}
