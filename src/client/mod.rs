pub mod udp;
pub mod tcp;

use std::{error::Error, time::Duration};

use tokio::{io::{AsyncRead, AsyncWrite, AsyncWriteExt, AsyncReadExt}, net::TcpStream, time::timeout};
use tokio_native_tls::{native_tls::Certificate, TlsConnector, TlsStream};

use crate::common::protocol::{MgmtMessage, HTTP_METHOD, MGMT_MESSAGE_SIZE};


const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const MGMT_STREAM_INIT_ACK_TIMEOUT: Duration = Duration::from_secs(1);
const MGMT_STREAM_TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);


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
        timeout(WRITE_TIMEOUT, self.mgmt_stream.write_all(password.as_bytes())).await??;
        return Ok(())
    }
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
        let mut mgmt_stream = timeout(MGMT_STREAM_TCP_CONNECTION_TIMEOUT, TcpStream::connect(self.tcp_address())).await??;
        self.init_mgmt_stream(&mut mgmt_stream).await.map_err(|_| "Mgmt connection initialisation failed.")?;
        log::debug!("start TLS connection");
        let tls_stream = timeout(TLS_CONNECTION_TIMEOUT, self.tls_connector.connect(&self.server_address, mgmt_stream)).await??;
        log::debug!("TLS connection established");
        return Ok(ConnectedClient { client: self, mgmt_stream: tls_stream })
    }

    pub async fn init_mgmt_stream<T: AsyncRead + AsyncWrite + Unpin>(&self, conn: &mut T) -> Result<(), ()> {
        let http_header = format!("{} / HTTP/1.1\nHost: {}\n\n", HTTP_METHOD,  &self.server_address);
        match timeout(WRITE_TIMEOUT, conn.write_all(http_header.as_bytes())).await {
            Ok(Ok(_)) => log::debug!("Initial HTTP request sent."),
            Ok(Err(err)) => {
                log::error!("Error while sending initial HTTP request: {}", err);
                return Err(());
            }
            Err(_) => {
                log::error!("Timeout while sending initial HTTP request.");
                return Err(());
            },
        }
        let mut ack_buf: [u8; MGMT_MESSAGE_SIZE] = [0; MGMT_MESSAGE_SIZE];
        let msg_count = match timeout(MGMT_STREAM_INIT_ACK_TIMEOUT, conn.read_exact(&mut ack_buf)).await {
            Ok(Ok(count)) => count,
            Ok(Err(err)) => {
                log::error!("Error while reading ACK msg: {}", err);
                return Err(());
            }
            Err(_) => {
                log::error!("Timeout while waiting for ACK msg.");
                return Err(());
            },
        };
        if msg_count != MGMT_MESSAGE_SIZE {
            log::error!("Invalid ACK msg size received: {}", msg_count);
            return Err(());
        }
        if MgmtMessage::Ack.message().eq(&ack_buf) {
            log::debug!("ACK received.");
            return Ok(());
        }
        log::error!("Invalid ACK msg received.");
        return Err(());
    }
}