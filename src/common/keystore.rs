
use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};
use tokio_native_tls::native_tls::Identity;

const DUMMY_PW: &str = "secret";

pub fn import_identity(key_path: &str, certificate_path: &str) -> Identity {
    let key_bytes = std::fs::read(key_path).unwrap();
    let key = PKey::private_key_from_pem(&key_bytes).unwrap();
    let cert_bytes = std::fs::read(certificate_path).unwrap();
    let cert = X509::from_pem(&cert_bytes).unwrap();
    let store = Pkcs12::builder().cert(&cert).pkey(&key).build2(DUMMY_PW).unwrap();
    let store_bytes = store.to_der().unwrap();
    return Identity::from_pkcs12(&store_bytes, DUMMY_PW).unwrap();
}