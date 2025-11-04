
use openssl::{pkcs12::Pkcs12, pkey::PKey, stack::Stack, x509::X509};
use tokio_native_tls::native_tls::Identity;

const DUMMY_PW: &str = "secret";

pub fn import_identity(key_path: &str, certificate_path: &str) -> Identity {
    let key_bytes = std::fs::read(key_path).unwrap();
    let key = PKey::private_key_from_pem(&key_bytes).unwrap();
    let cert_bytes = std::fs::read(certificate_path).unwrap();
    let cert_chain = X509::stack_from_pem(&cert_bytes).unwrap();
    let leaf_cert = cert_chain.first().unwrap();
    let ca_certs: Vec<&X509> = cert_chain.iter().skip(1).collect();
    let mut ca_stack: Stack<X509> = Stack::new().unwrap();
    for ca_cert in ca_certs {
        ca_stack.push((*ca_cert).clone()).unwrap();
    }
    let mut store_builder = Pkcs12::builder();
    store_builder.cert(leaf_cert);
    store_builder.ca(ca_stack);
    store_builder.pkey(&key);
    let store = store_builder.build2(DUMMY_PW).unwrap();
    let store_bytes = store.to_der().unwrap();
    return Identity::from_pkcs12(&store_bytes, DUMMY_PW).unwrap();
}