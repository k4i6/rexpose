use std::{error::Error, net::SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

pub const MGMT_MESSAGE_SIZE: usize = 3;
pub const UDP_BUFFER_SIZE: usize = 65_535;

pub enum MgmtMessage {
    NotifyRequest,
    KeepAlive,
    UdpStart,
}

impl MgmtMessage {
    pub fn message(&self) -> &[u8; MGMT_MESSAGE_SIZE] {
        return match self {
            MgmtMessage::NotifyRequest => b"REQ",
            MgmtMessage::KeepAlive => b"KAL",
            MgmtMessage::UdpStart => b"UDP",
        }
    }
}

pub fn addressed_udp_message(addr: SocketAddr, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut serialized_addr = serde_cbor::to_vec(&addr)?;
    let addr_size: u32 = serialized_addr.len().try_into()?;
    let message_size: u32 = message.len().try_into()?;
    let mut result: Vec<u8> = Vec::new();
    result.append(&mut addr_size.to_be_bytes().to_vec()); 
    result.append(&mut serialized_addr);
    result.append(&mut message_size.to_be_bytes().to_vec());
    result.append(&mut message.to_vec());
    return Ok(result);
}

pub async fn read_addressed_udp_message<T: AsyncRead + Unpin>(stream: &mut T) -> Result<(SocketAddr, Vec<u8>), Box<dyn Error>> {
    let addr_size = stream.read_u32().await?;
    let mut addr_buf = vec![0u8; addr_size.try_into()?];
    stream.read_exact(&mut addr_buf).await?;
    let addr: SocketAddr = serde_cbor::from_slice(&addr_buf)?;
    let message_size = stream.read_u32().await?;
    let mut message_buf = vec![0u8; message_size.try_into()?];
    stream.read_exact(&mut message_buf).await?;
    return Ok((addr, message_buf))
}

pub trait Connectable<A:AuthorizedConnection, U:UnauthorizedConnection<A>> {
    async fn connect(self) -> Result<U, Box<dyn Error>>;
}

pub trait UnauthorizedConnection<A:AuthorizedConnection> {
    async fn authorize(self, password: &str) -> Result<A, Box<dyn Error>>;
}

pub trait AuthorizedConnection {
    async fn forward_communication(&mut self, forwarded_port: &u16, encrypted: bool) -> Result<(), Box<dyn Error>>;
    async fn shutdown(self);
}