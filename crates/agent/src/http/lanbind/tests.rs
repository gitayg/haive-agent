use std::time::Duration;

use super::super::{build_server, Config};
use super::{until_bound, PACE};

fn cfg(port: u16, tls: bool) -> Config {
    Config {
        password: String::new(),
        port,
        quality: 60,
        max_width: 1600,
        exec_enabled: false,
        tls,
        share: String::new(),
        grabber: crate::capture::Grabber { index: 0 },
        cert: None,
        direct_token: String::new(),
    }
}

#[test]
fn the_lan_listener_binds_once_the_previous_holder_lets_go_of_the_port() {
    let holder = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = holder.local_addr().unwrap().port();
    let lets_go = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        drop(holder);
    });
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let c = cfg(port, false);
        let _ = tx.send(until_bound(c.port, &PACE, || build_server(&c)).map_err(|e| e.to_string()));
    });
    let server = rx.recv_timeout(Duration::from_secs(10)).expect("still not bound 10 s after the port was let go");
    lets_go.join().unwrap();
    let server = server.expect("the bind gave up while the port was only briefly taken");
    assert_eq!(server.server_addr().to_ip().map(|a| a.port()), Some(port));
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(), "nothing listens on {port}");
}

#[test]
fn a_bind_that_cannot_succeed_is_not_retried() {
    let c = cfg(0, true);
    let t0 = std::time::Instant::now();
    assert!(until_bound(c.port, &PACE, || build_server(&c)).is_err(), "TLS without a certificate bound");
    assert!(t0.elapsed() < Duration::from_secs(1), "a missing certificate was retried for {:?}", t0.elapsed());
}
