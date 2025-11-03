mod client;
mod server;
mod common;


use clap::{ArgAction, Parser};
use tokio::io::{self};

use crate::{client::{tcp::AuthorizedClient, udp::AuthorizedUdpClient, Client, ConnectedClient}, common::protocol::{AuthorizedConnection, Connectable, UnauthorizedConnection}, server::{tcp::AuthorizedServer, udp::AuthorizedUdpServer, Server, UnauthorizedServer}};

/// A reverse proxy to expose TCP and UDP services behind any NAT via a public server.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Start in server mode
    #[arg(short = 's', long, action = ArgAction::SetTrue, default_value_t = false)]
    server_mode: bool,

    /// Only used in client mode: IP address or hostname of the server
    #[arg(short = 'a', long, default_value = Option::None)]
    server_address: Option<String>,

    /// Server communication port
    #[arg(short = 'm', long, default_value_t = 8088)]
    server_port: u16,

    /// Port which should be exposed (client mode) or forwarded to the client (server mode)
    #[arg(short = 'p', long, default_value_t = 80)]
    port: u16,

    /// The password used for authorization between server and client
    #[arg(short = 'P', long, default_value = Option::None)]
    password: Option<String>,

    /// Path to the trusted certificate used for TLS communication between server and client
    #[arg(short = 'c', long, default_value = Option::None)]
    certificate_path: Option<String>,

    /// Only used in server mode: Path to the private key with which the certificate was created
    #[arg(short = 'k', long, default_value = Option::None)]
    key_path: Option<String>,

    /// Enable verbose logging
    #[arg(short = 'v', long, action = ArgAction::SetTrue, default_value_t = false)]
    log_verbose: bool,

    /// Indicate that the forwarded service is a UDP service
    #[arg(short = 'u', long, action = ArgAction::SetTrue, default_value_t = false)]
    udp: bool,

    /// Encrypt all traffic between client and server
    #[arg(short = 'e', long, action = ArgAction::SetTrue, default_value_t = false)]
    encrypted: bool,
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args = Args::parse();
    let log_level = if args.log_verbose {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new().filter_level(log_level).init();
    let password = match read_password(&args).await {
        Ok(password) => password,
        Err(err) => {
            log::error!("No password provided.\n{}", err);
            return Err(());
        },
    };
    if args.server_mode {
        start_server(&args, &password).await?;
    } else {
        start_client(&args, &password).await?;
    }
    return Ok(());
}

async fn start_client(args: &Args, password: &str) -> Result<(), ()> {
    log::info!("start in client mode");
    let server_address = match &args.server_address {
        Some(address) => address,
        None => {
            log::error!("Please provide the address to the server to connect to");
            return Err(());
        },
    };
    let client = Client::new(&server_address, &args.server_port, &args.certificate_path);
    if args.udp {
        handle_connection::<AuthorizedUdpClient, ConnectedClient, Client>(client, &password, &args.port, args.encrypted).await?;
    } else {
        handle_connection::<AuthorizedClient, ConnectedClient, Client>(client, &password, &args.port, args.encrypted).await?;
    }
    return Ok(());
}

async fn start_server(args: &Args, password: &str) -> Result<(), ()> {
    log::info!("start in server mode");
    let key_path = match &args.key_path {
        Some(path) => path,
        None => {
            log::error!("please provide the key path used to generate the provided certificate");
            return Err(());
        },
    };
    let certificate_path = match &args.certificate_path {
        Some(path) => path,
        None => {
            log::error!("please provide the certificate path");
            return Err(());
        },
    };
    loop {
        let server = Server::new(&key_path, &certificate_path, &args.server_port);
        if args.udp {
            handle_connection::<AuthorizedUdpServer, UnauthorizedServer, Server>(server, &password, &args.port, args.encrypted).await?;
        } else {
            handle_connection::<AuthorizedServer, UnauthorizedServer, Server>(server, &password, &args.port, args.encrypted).await?;
        }
    }
}

async fn read_password(args: &Args) -> io::Result<String> {
    if let Some(password) = &args.password {
        return Ok(password.to_string());
    }
    let password = rpassword::prompt_password("Enter password: ").unwrap();
    return Ok(password.trim_end().to_string());
}

async fn handle_connection<A: AuthorizedConnection, U: UnauthorizedConnection<A>, C: Connectable<A,U>>(connectable: C, password: &str, port: &u16, encrypted: bool) -> Result<(), ()> {
    log::info!("start connection");
    let unauthorized_connection = match connectable.connect().await {
        Ok(connection) => connection,
        Err(err) => {
            log::error!("unable to establish connection: {}", err);
            return Err(());
        },
    };
    log::info!("connection established");
    log::info!("authorize connection");
    let mut authorized_connection = match unauthorized_connection.authorize(password).await {
        Ok(connection) => connection,
        Err(err) => {
            log::error!("authorization failed: {}", err);
            return Err(());
        },
    };
    log::info!("start forwarding communication");
    match authorized_connection.forward_communication(port, encrypted).await {
        Ok(_) => {},
        Err(err) => {
            log::error!("error while forwarding communication: {}", err);
            return Err(());
        },
    };
    log::info!("shutdown connection");
    authorized_connection.shutdown().await;
    return Ok(());
}
