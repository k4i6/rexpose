pub mod udp;
pub mod tcp;

use std::{error::Error, time::Duration};

use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tokio_native_tls::{native_tls::Certificate, TlsConnector, TlsStream};


const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const MGMT_STREAM_TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
pub const CONNECTION_RETRY_COUNT: u8 = 2;


pub struct Client {
    mgmt_port: u16,
    server_address: String,
    tls_connector: TlsConnector,
}

pub struct ConnectedClient {
    client: Client,
    mgmt_stream: TlsStream<TcpStream>,
}

impl ConnectedClient {
    async fn authorize_internal(&mut self, password: &str) -> Result<(), Box<dyn Error>> {
        return send_password(&mut self.mgmt_stream, &password).await
    }
}

pub async fn send_password(tls_stream: &mut TlsStream<TcpStream>, password: &str) -> Result<(), Box<dyn Error>> {
    timeout(WRITE_TIMEOUT, tls_stream.write_all(password.as_bytes())).await??;
    return Ok(())
}

impl Client {
    pub fn new(server_address: &str, mgmt_port: &u16, certificate_path: &Option<String>) -> Client {
        let mut cert_builder = tokio_native_tls::native_tls::TlsConnector::builder();
        if let Some(certificate_path) = certificate_path {
            let cert = Certificate::from_pem(&std::fs::read(certificate_path).unwrap()).unwrap();
            cert_builder.add_root_certificate(cert);
        }
        let tls_connector = TlsConnector::from(cert_builder.build().unwrap());
        return Self { mgmt_port: *mgmt_port, server_address: server_address.to_string(), tls_connector: tls_connector }
    }

    pub fn tcp_address(&self) -> String {
        return format!("{}:{}", self.server_address, self.mgmt_port);
    }

    async fn connect_internal(self) -> Result<ConnectedClient, Box<dyn Error>> {
        let mgmt_stream = timeout(MGMT_STREAM_TCP_CONNECTION_TIMEOUT, TcpStream::connect(self.tcp_address())).await??;
        log::debug!("start TLS connection");
        let tls_stream = timeout(TLS_CONNECTION_TIMEOUT, self.tls_connector.connect(&self.server_address, mgmt_stream)).await??;
        log::debug!("TLS connection established");
        return Ok(ConnectedClient { client: self, mgmt_stream: tls_stream })
    }
}