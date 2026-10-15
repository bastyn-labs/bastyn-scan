//! Refuses MCP server URLs that point at cloud-metadata or link-local
//! addresses, and URL schemes other than http/https.
//!
//! The URL can come from a scanned repository's own config file, which is
//! untrusted: without this guard a hostile config could aim the inspector at
//! an instance-metadata endpoint. Loopback and private ranges stay allowed
//! because local servers are the common case.
//!
//! Limitation: the host is resolved here, and again by the HTTP client when
//! it connects. A DNS server that answers differently the second time can
//! defeat the check. Closing that would need a custom resolver in the HTTP
//! client; it is documented rather than hidden.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use ureq::http::Uri;

/// Why a URL was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GuardError {
    /// Only `http` and `https` are spoken.
    #[error("unsupported URL scheme `{0}`; only http and https are allowed")]
    UnsupportedScheme(String),
    /// The URL has no host.
    #[error("the URL has no host")]
    NoHost,
    /// The host did not resolve.
    #[error("could not resolve `{0}`")]
    Resolve(String),
    /// The host is, or resolves to, a blocked address.
    #[error("refusing to connect to `{host}`: {address} is a link-local or cloud-metadata address")]
    Blocked {
        /// The host as written in the URL.
        host: String,
        /// The blocked address it is or resolves to.
        address: IpAddr,
    },
    /// The host is, or resolves to, an address that is not public.
    #[error("refusing to connect to `{host}`: {address} is not a public address")]
    NotPublic {
        /// The host as written in the URL.
        host: String,
        /// The non-public address it is or resolves to.
        address: IpAddr,
    },
    /// Remote inspection speaks only `https`.
    #[error("only https URLs to public servers are inspected; got `{0}`")]
    NotHttps(String),
}

const BLOCKED_NAMES: [&str; 2] = ["metadata.google.internal", "metadata.goog"];

/// True for link-local, cloud-metadata and equivalent addresses.
pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_link_local()
                || v4 == Ipv4Addr::new(100, 100, 100, 200)
                || v4 == Ipv4Addr::new(192, 0, 0, 192)
        }
        IpAddr::V6(v6) => {
            v6.is_unicast_link_local()
                || v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_blocked_ip(IpAddr::V4(v4)))
        }
    }
}

/// Check the scheme and every address the host resolves to.
pub(crate) fn check_url(url: &str) -> Result<(), GuardError> {
    let Ok(uri) = url.parse::<Uri>() else {
        // Some URLs the parser rejects (for example `file:///path`, which has
        // an empty authority) still name a scheme worth reporting.
        return Err(match url.split_once(':') {
            Some((scheme, _))
                if !scheme.eq_ignore_ascii_case("http")
                    && !scheme.eq_ignore_ascii_case("https") =>
            {
                GuardError::UnsupportedScheme(scheme.to_owned())
            }
            _ => GuardError::NoHost,
        });
    };
    match uri.scheme_str() {
        Some("http" | "https") => {}
        other => {
            return Err(GuardError::UnsupportedScheme(
                other.unwrap_or_default().to_owned(),
            ));
        }
    }
    let host = uri.host().ok_or(GuardError::NoHost)?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if BLOCKED_NAMES
        .iter()
        .any(|name| bare.eq_ignore_ascii_case(name))
    {
        return Err(GuardError::Blocked {
            host: bare.to_owned(),
            address: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        });
    }
    let addresses = resolve_addresses(&uri, bare)?;
    match addresses.into_iter().find(|ip| is_blocked_ip(*ip)) {
        Some(address) => Err(GuardError::Blocked {
            host: bare.to_owned(),
            address,
        }),
        None => Ok(()),
    }
}

/// Every address `bare` (the URL's host without IPv6 brackets) is or resolves
/// to. An IP literal is returned as is; a name is resolved with the URL's port
/// (or the scheme's default). An empty answer counts as a resolution failure.
fn resolve_addresses(uri: &Uri, bare: &str) -> Result<Vec<IpAddr>, GuardError> {
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let addresses: Vec<IpAddr> = match bare.parse::<IpAddr>() {
        Ok(literal) => vec![literal],
        Err(_) => (bare, port)
            .to_socket_addrs()
            .map_err(|_| GuardError::Resolve(bare.to_owned()))?
            .map(|socket| socket.ip())
            .collect(),
    };
    if addresses.is_empty() {
        return Err(GuardError::Resolve(bare.to_owned()));
    }
    Ok(addresses)
}

/// True for an IPv4 address outside every reserved, private, shared,
/// documentation, benchmarking, multicast and link-local range, and not one
/// that [`is_blocked_ip`] already blocks.
fn is_public_ipv4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    let reserved = a == 0 // 0.0.0.0/8
        || a == 10 // 10.0.0.0/8
        || (a == 100 && (b & 0xc0) == 64) // 100.64.0.0/10
        || a == 127 // 127.0.0.0/8
        || (a == 169 && b == 254) // 169.254.0.0/16
        || (a == 172 && (b & 0xf0) == 16) // 172.16.0.0/12
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24
        || (a == 192 && b == 0 && c == 2) // 192.0.2.0/24
        || (a == 192 && b == 168) // 192.168.0.0/16
        || (a == 198 && (b & 0xfe) == 18) // 198.18.0.0/15
        || (a == 198 && b == 51 && c == 100) // 198.51.100.0/24
        || (a == 203 && b == 0 && c == 113) // 203.0.113.0/24
        || a >= 224; // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved
    !reserved && !is_blocked_ip(IpAddr::V4(v4))
}

/// True only for an address that is routable on the public internet.
///
/// Rejected IPv4 ranges: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`,
/// `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`,
/// `192.0.2.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`,
/// `203.0.113.0/24`, `224.0.0.0/4` (multicast) and `240.0.0.0/4` (reserved,
/// including broadcast), plus everything [`is_blocked_ip`] blocks.
///
/// Rejected IPv6 ranges: `::` and `::1`, `::/96` (IPv4-compatible),
/// `fc00::/7`, `fe80::/10`, `ff00::/8` and `2001:db8::/32`. An IPv4-mapped
/// address (`::ffff:a.b.c.d`) and a NAT64 address (`64:ff9b::/96`) are judged
/// as the IPv4 address they embed. Everything else is public.
#[allow(
    dead_code,
    reason = "the remote-inspection entry point uses this in a later change"
)]
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ipv4(v4);
            }
            let bits = u128::from(v6);
            if (bits >> 32) == 0x0064_ff9b_0000_0000_0000_0000 {
                // Low 32 bits of a NAT64 address carry the IPv4 address.
                let [.., c, d, e, f] = bits.to_be_bytes();
                return is_public_ipv4(Ipv4Addr::new(c, d, e, f));
            }
            let reserved = (bits >> 32) == 0 // ::/96, includes :: and ::1
                || (bits >> 121) == 0x7e // fc00::/7
                || (bits >> 118) == 0x3fa // fe80::/10
                || (bits >> 120) == 0xff // ff00::/8
                || (bits >> 96) == 0x2001_0db8; // 2001:db8::/32
            !reserved && !is_blocked_ip(IpAddr::V6(v6))
        }
    }
}

/// Parse `url` and return it with its host (IPv6 brackets removed), or `None`
/// when it does not parse, is not `https`, has no host, or names `localhost`
/// or a `*.localhost` host.
fn https_host(url: &str) -> Option<(Uri, String)> {
    let uri = url.parse::<Uri>().ok()?;
    if uri.scheme_str() != Some("https") {
        return None;
    }
    let bare = uri
        .host()?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let lower = bare.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return None;
    }
    Some((uri, bare))
}

/// True when `url` is an `https` URL whose host is not `localhost` or
/// `*.localhost` and, if it is an IP literal, is a public address. Syntactic
/// only: no name is resolved.
#[allow(
    dead_code,
    reason = "the remote-inspection entry point uses this in a later change"
)]
pub(crate) fn is_public_https_url(url: &str) -> bool {
    https_host(url).is_some_and(|(_, bare)| bare.parse::<IpAddr>().map_or(true, is_public_ip))
}

/// Check that `url` is an `https` URL to a public server: the syntactic rules
/// of [`is_public_https_url`] plus resolution, where every address the host
/// resolves to must be public.
#[allow(
    dead_code,
    reason = "the remote-inspection entry point uses this in a later change"
)]
pub(crate) fn check_public_url(url: &str) -> Result<(), GuardError> {
    let Some((uri, bare)) = https_host(url) else {
        return Err(public_url_refusal(url));
    };
    for address in resolve_addresses(&uri, &bare)? {
        if !is_public_ip(address) {
            return Err(GuardError::NotPublic {
                host: bare,
                address,
            });
        }
    }
    Ok(())
}

/// The error for a URL that [`https_host`] rejected: a missing host, a
/// `localhost` name, or a scheme other than `https`.
fn public_url_refusal(url: &str) -> GuardError {
    match url.parse::<Uri>() {
        Ok(uri) if uri.scheme_str() == Some("https") => match uri.host() {
            Some(host) => GuardError::NotPublic {
                host: host.to_owned(),
                address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            None => GuardError::NoHost,
        },
        Ok(_) => GuardError::NotHttps(url.to_owned()),
        Err(_) => match url.split_once(':') {
            Some((scheme, _)) if scheme.eq_ignore_ascii_case("https") => GuardError::NoHost,
            _ => GuardError::NotHttps(url.to_owned()),
        },
    }
}

/// True when the URL's host is `localhost` or a loopback literal.
pub(crate) fn is_loopback_host(url: &str) -> bool {
    let Ok(uri) = url.parse::<Uri>() else {
        return false;
    };
    let Some(host) = uri.host() else {
        return false;
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    #[test]
    fn blocks_link_local_and_metadata_addresses() {
        for text in [
            "169.254.169.254",
            "169.254.0.1",
            "100.100.100.200",
            "192.0.0.192",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_blocked_ip(text.parse().unwrap()), "{text}");
        }
    }

    #[test]
    fn allows_loopback_private_and_public_addresses() {
        for text in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "192.168.1.5",
            "8.8.8.8",
            "2606:4700::1111",
        ] {
            assert!(!is_blocked_ip(text.parse().unwrap()), "{text}");
        }
    }

    #[test]
    fn check_url_refuses_bad_schemes_and_metadata_hosts() {
        assert!(matches!(
            check_url("ftp://example.com/mcp"),
            Err(GuardError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            check_url("file:///etc/passwd"),
            Err(GuardError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            check_url("http://169.254.169.254/latest/meta-data"),
            Err(GuardError::Blocked { .. })
        ));
        assert!(matches!(
            check_url("http://metadata.google.internal/computeMetadata/v1/"),
            Err(GuardError::Blocked { .. })
        ));
        assert!(matches!(
            check_url("http://[fd00:ec2::254]/"),
            Err(GuardError::Blocked { .. })
        ));
        assert!(matches!(
            check_url("http://user@169.254.169.254:80/"),
            Err(GuardError::Blocked { .. })
        ));
    }

    #[test]
    fn check_url_allows_loopback_and_private_literals() {
        assert!(check_url("http://127.0.0.1:8080/mcp").is_ok());
        assert!(check_url("http://[::1]:8080/mcp").is_ok());
        assert!(check_url("http://10.0.0.5/mcp").is_ok());
    }

    #[test]
    fn public_ip_boundaries() {
        let public = [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.255.255",
            "172.32.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
            "::ffff:8.8.8.8",
        ];
        let private = [
            "0.0.0.1",
            "10.0.0.5",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::10.0.0.1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
        ];
        for ip in public {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in private {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn public_https_url_is_syntactic() {
        for ok in [
            "https://example.com/mcp",
            "https://8.8.8.8/mcp",
            "https://[2606:4700:4700::1111]/mcp",
            "HTTPS://Example.com",
        ] {
            assert!(is_public_https_url(ok), "{ok}");
        }
        for bad in [
            "http://example.com/mcp",
            "https://localhost/mcp",
            "https://app.localhost/mcp",
            "https://127.0.0.1/mcp",
            "https://10.0.0.5/mcp",
            "https://[::1]/mcp",
            "file:///etc/passwd",
            "ftp://example.com",
            "https://",
            "not a url",
            "https://${HOST}/mcp",
        ] {
            assert!(!is_public_https_url(bad), "{bad}");
        }
    }

    #[test]
    fn check_public_url_refuses_localhost_by_resolution_without_network() {
        // `localhost` resolves locally to a loopback address; no network is needed.
        assert!(matches!(
            check_public_url("https://localhost/mcp"),
            Err(GuardError::NotPublic { .. } | GuardError::NotHttps(_))
        ));
        assert!(matches!(
            check_public_url("http://example.com"),
            Err(GuardError::NotHttps(_))
        ));
    }

    #[test]
    fn loopback_hosts_are_recognised() {
        assert!(is_loopback_host("http://localhost:3000/mcp"));
        assert!(is_loopback_host("http://127.0.0.1/mcp"));
        assert!(is_loopback_host("http://[::1]:3000/mcp"));
        assert!(!is_loopback_host("http://example.com/mcp"));
    }
}
