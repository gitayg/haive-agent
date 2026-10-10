// SPDX-License-Identifier: MIT
//! Which WireGuard implementation runs `itai-wg`, and how iptables gets onto the box.
//! Decisions only; the side effects are passed in, so the order is testable.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// The kernel module, configured with `wg`.
    Kernel,
    /// The agent's embedded boringtun device on /dev/net/tun, configured over its UAPI socket.
    Userspace,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Backend::Kernel => "kernel",
            Backend::Userspace => "userspace",
        }
    }
}

/// The two ways to create the interface, tried in order by `bring_up`.
pub trait Bringup {
    /// `ip link add … type wireguard`. Fails when this kernel has no WireGuard module.
    fn kernel(&mut self) -> Result<(), String>;
    /// The embedded userspace device. Fails without /dev/net/tun.
    fn userspace(&mut self) -> Result<(), String>;
}

/// The kernel module when it is there (faster), the built-in userspace WireGuard when it is not.
/// `have_wg`: the kernel interface is configured with `wg`, which the agent no longer installs, so
/// without it the module is not tried. `force_userspace`: HIVE_VPN_USERSPACE=1, for testing.
pub fn bring_up(force_userspace: bool, have_wg: bool, b: &mut impl Bringup) -> Result<Backend, String> {
    let kernel = if force_userspace {
        "not tried (HIVE_VPN_USERSPACE=1)".to_string()
    } else if !have_wg {
        "not tried (wireguard-tools is not installed)".to_string()
    } else {
        match b.kernel() {
            Ok(()) => return Ok(Backend::Kernel),
            Err(e) => e,
        }
    };
    b.userspace()
        .map(|()| Backend::Userspace)
        .map_err(|e| format!("cannot create the WireGuard interface — kernel module: {kernel}; built-in userspace WireGuard: {e}"))
}

/// Package managers the agent can install iptables with, in the order it looks for them.
pub const PKG_MANAGERS: &[&str] = &["apt-get", "dnf", "pacman", "apk"];

/// The first package manager present, by `have`.
pub fn pick_pkg_manager(have: impl Fn(&str) -> bool) -> Option<&'static str> {
    PKG_MANAGERS.iter().copied().find(|pm| have(pm))
}

/// `(install, refresh)` for iptables: the install is retried once after the refresh, for an
/// image whose package index was never downloaded.
pub fn iptables_install(pm: &str) -> Option<(Vec<&'static str>, Vec<&'static str>)> {
    Some(match pm {
        "apt-get" => (vec!["install", "-y", "-qq", "iptables"], vec!["update", "-qq"]),
        "dnf" => (vec!["install", "-y", "-q", "iptables"], vec!["makecache", "-q"]),
        "pacman" => (vec!["-S", "--noconfirm", "--needed", "iptables"], vec!["-Sy", "--noconfirm"]),
        "apk" => (vec!["add", "-q", "iptables"], vec!["update", "-q"]),
        _ => return None,
    })
}

pub const NO_PKG_MANAGER: &str =
    "the VPN exit needs iptables for its NAT and firewall rules, and it is not installed; the agent can install it with apt-get, dnf, pacman or apk, and found none of them — install iptables";

/// `ip -d link show` output for a kernel WireGuard interface has a `wireguard` line; a TUN
/// device (boringtun, wireguard-go) has `tun type tun …` instead.
pub fn is_kernel_wireguard(ip_d_link: &str) -> bool {
    ip_d_link.lines().any(|l| l.trim_start().starts_with("wireguard"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        kernel_ok: bool,
        tun_ok: bool,
        tried: Vec<&'static str>,
    }

    impl Bringup for Fake {
        fn kernel(&mut self) -> Result<(), String> {
            self.tried.push("kernel");
            if self.kernel_ok {
                Ok(())
            } else {
                Err("ip link add: Operation not supported".into())
            }
        }
        fn userspace(&mut self) -> Result<(), String> {
            self.tried.push("userspace");
            if self.tun_ok {
                Ok(())
            } else {
                Err("/dev/net/tun: No such file or directory".into())
            }
        }
    }

    #[test]
    fn the_kernel_module_wins_when_present() {
        let mut f = Fake { kernel_ok: true, tun_ok: true, ..Default::default() };
        assert_eq!(bring_up(false, true, &mut f), Ok(Backend::Kernel));
        assert_eq!(f.tried, ["kernel"], "boringtun is not started when the kernel works");
    }

    #[test]
    fn no_kernel_module_falls_back_to_boringtun() {
        let mut f = Fake { kernel_ok: false, tun_ok: true, ..Default::default() };
        assert_eq!(bring_up(false, true, &mut f), Ok(Backend::Userspace));
        assert_eq!(f.tried, ["kernel", "userspace"]);
    }

    #[test]
    fn without_wg_the_kernel_module_is_not_tried() {
        let mut f = Fake { kernel_ok: true, tun_ok: true, ..Default::default() };
        assert_eq!(bring_up(false, false, &mut f), Ok(Backend::Userspace));
        assert_eq!(f.tried, ["userspace"], "nothing could configure a kernel interface");
    }

    #[test]
    fn hive_vpn_userspace_forces_boringtun() {
        let mut f = Fake { kernel_ok: true, tun_ok: true, ..Default::default() };
        assert_eq!(bring_up(true, true, &mut f), Ok(Backend::Userspace));
        assert_eq!(f.tried, ["userspace"]);
    }

    #[test]
    fn neither_backend_is_a_clear_error_naming_both_causes() {
        let mut f = Fake::default();
        let e = bring_up(false, true, &mut f).unwrap_err();
        assert_eq!(f.tried, ["kernel", "userspace"]);
        assert!(e.contains("Operation not supported") && e.contains("/dev/net/tun"), "{e}");

        let e = bring_up(false, false, &mut Fake::default()).unwrap_err();
        assert!(e.contains("wireguard-tools is not installed") && e.contains("/dev/net/tun"), "{e}");
    }

    #[test]
    fn iptables_installs_with_whichever_package_manager_is_there() {
        assert_eq!(pick_pkg_manager(|c| c == "apk" || c == "dnf"), Some("dnf"), "first in PKG_MANAGERS order");
        assert_eq!(pick_pkg_manager(|c| c == "pacman"), Some("pacman"));
        assert_eq!(pick_pkg_manager(|_| false), None);
        for pm in PKG_MANAGERS {
            let (install, _) = iptables_install(pm).unwrap_or_else(|| panic!("{pm} has no install command"));
            assert_eq!(install.last(), Some(&"iptables"), "{pm}");
        }
        assert!(iptables_install("zypper").is_none());
    }

    #[test]
    fn kernel_wireguard_is_told_apart_from_a_tun_device() {
        let kernel = "7: itai-wg: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    link/none  promiscuity 0  allmulti 0 minmtu 0 maxmtu 2147483552 \n    wireguard addrgenmode none numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535\n";
        let tun = "8: itai-wg: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1380 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\n    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 \n    tun type tun pi off vnet_hdr off multi_queue on persist off addrgenmode none\n";
        assert!(is_kernel_wireguard(kernel));
        assert!(!is_kernel_wireguard(tun));
        assert!(!is_kernel_wireguard(""));
    }
}
