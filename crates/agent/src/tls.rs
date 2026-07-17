// Persistent self-signed certificate (generated once, reused across restarts).
use std::fs;
use std::path::PathBuf;

pub fn ensure_cert(dir: &str, ip: &str, hostnames: &[String]) -> Option<(Vec<u8>, Vec<u8>)> {
    let d = PathBuf::from(dir);
    let cert_p = d.join("cert.pem");
    let key_p = d.join("key.pem");
    if cert_p.exists() && key_p.exists() {
        return Some((fs::read(&cert_p).ok()?, fs::read(&key_p).ok()?));
    }
    let mut sans: Vec<String> = hostnames.to_vec();
    sans.push(ip.to_string());
    let ck = rcgen::generate_simple_self_signed(sans).ok()?;
    let cert_pem = ck.cert.pem().into_bytes();
    let key_pem = ck.key_pair.serialize_pem().into_bytes();
    let _ = fs::create_dir_all(&d);
    let _ = fs::write(&cert_p, &cert_pem);
    let _ = fs::write(&key_p, &key_pem);
    Some((cert_pem, key_pem))
}
