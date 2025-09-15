pub mod tcp;
pub mod udp;

use std::{error::Error, fmt, net::SocketAddr, time::Duration};

use tokio::{io::{self, AsyncReadExt}, net::{TcpListener, TcpStream}, time::timeout};
use tokio_native_tls::{TlsAcceptor, TlsStream};

use crate::common::keystore::import_identity;

const READ_TIMEOUT: Duration = Duration::from_secs(1);


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
        let (stream, address) = listener.accept().await?;
        log::debug!("client connected, starting tls connection");
        let tls_stream = self.tls_acceptor.accept(stream).await?;
        log::debug!("tls connection established");
        return Ok(UnauthorizedServer { mgmt_stream: tls_stream, mgmt_listener: listener, connected_address: address, server: self });
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
