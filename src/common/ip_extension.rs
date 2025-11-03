use std::net::IpAddr;

pub fn is_ip_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr.is_private(),
        IpAddr::V6(_ipv6_addr) => false,
    }
}