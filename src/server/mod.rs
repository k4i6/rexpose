pub mod tcp;
pub mod udp;

use std::{error::Error, fmt, net::SocketAddr, time::Duration};

use tokio::{io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::{TcpListener, TcpStream}, time::timeout};
use tokio_native_tls::{TlsAcceptor, TlsStream};

use crate::common::{keystore::import_identity, protocol::{MgmtMessage, HTTP_METHOD}};

const READ_TIMEOUT: Duration = Duration::from_secs(1);
const HTTP_INIT_BUF_SIZE: usize = 512;
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);


pub struct Server {
    mgmt_port: u16,
    tls_acceptor: TlsAcceptor,
}

impl Server {
    pub fn new(key_path: &str, certificate_path: &str, mgmt_port: &u16) -> Server {
        let identity = import_identity(key_path, certificate_path);
        let tls_acceptor =
            tokio_native_tls::TlsAcceptor::from(tokio_native_tls::native_tls::TlsAcceptor::builder(identity).build().unwrap());
        return Self { mgmt_port: *mgmt_port, tls_acceptor: tls_acceptor }
    }

    async fn connect_internal(self) -> Result<UnauthorizedServer, Box<dyn Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.mgmt_port)).await?;
        log::debug!("listening for client to connect");
        let (mut stream, address) = listener.accept().await?;
        self.init_mgmt_stream(&mut stream).await.map_err(|_| "Stream init failed.")?;
        log::debug!("client connected, starting tls connection");
        let tls_stream = self.tls_acceptor.accept(stream).await?;
        log::debug!("tls connection established");
        return Ok(UnauthorizedServer { mgmt_stream: tls_stream, mgmt_listener: listener, connected_address: address, server: self });
    }

    pub async fn init_mgmt_stream<T: AsyncRead + AsyncWrite + Unpin>(&self, conn: &mut T) -> Result<(), ()> {
        let mut init_buf: [u8; HTTP_INIT_BUF_SIZE] = [0; HTTP_INIT_BUF_SIZE];
        let msg_size = match timeout(READ_TIMEOUT, conn.read(&mut init_buf)).await {
            Ok(Ok(size)) => size,
            Ok(Err(err)) => {
                log::error!("Error while receiving initial HTTP request: {}", err);
                return Err(());
            }
            Err(_) => {
                log::error!("Timeout while waiting for initial HTTP request.");
                return Err(());
            },
        };
        let expected_http_method = HTTP_METHOD.as_bytes();
        if msg_size < expected_http_method.len() {
            log::error!("Unexpected msg size: {}", msg_size);
            return Err(());
        }
        if !expected_http_method.eq(&init_buf[..expected_http_method.len()]) {
            log::error!("Unexpected msg content.");
            return Err(());
        }
        log::debug!("HTTP msg received.");
        match timeout(WRITE_TIMEOUT, conn.write_all(MgmtMessage::Ack.message())).await {
            Ok(Ok(_)) => {
                log::debug!("ACK msg sent.");
                return Ok(());
            },
            Ok(Err(err)) => {
                log::error!("Error while sending ACK msg: {}", err);
                return Err(());
            }
            Err(_) => {
                log::error!("Timeout while sending ACK msg.");
                return Err(());
            },
        }
    }
}

pub struct UnauthorizedServer {
    server: Server,
    mgmt_stream: TlsStream<TcpStream>,
    mgmt_listener: TcpListener,
    connected_address: SocketAddr,
}

impl UnauthorizedServer {
    async fn authorize_internal(&mut self, password: &str) -> Result<(), Box<dyn Error>> {
        let mut pw_buf: [u8; 256] = [0; 256];
        let pw_read_size = timeout(READ_TIMEOUT, self.mgmt_stream.read(&mut pw_buf)).await??;
        if pw_read_size == 0 {
            return Err(Box::new(io::Error::new(std::io::ErrorKind::InvalidData, "Zero read, connection closing")));
        }
        if password.eq(std::str::from_utf8(&pw_buf.split(|byte| *byte == 0).next().unwrap_or_default()).unwrap_or_default()) {
            return Ok(());
        }
        return Err(Box::new(InvalidPassword {}));
    }
}

#[derive(Debug, Clone)]
struct InvalidPassword;

impl fmt::Display for InvalidPassword {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid password provided")
    }
}

impl Error for InvalidPassword {}
