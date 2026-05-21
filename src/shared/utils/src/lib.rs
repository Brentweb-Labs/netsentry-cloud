use std::net::IpAddr;
use std::str::FromStr;

/// Returns true if `ip` falls within the given `cidr` block.
pub fn is_in_cidr(ip: &str, cidr: &str) -> anyhow::Result<bool> {
    let addr = IpAddr::from_str(ip)?;
    let network: ipnetwork::IpNetwork = cidr.parse()?;
    Ok(network.contains(addr))
}
