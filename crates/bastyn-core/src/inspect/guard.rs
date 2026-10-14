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
    match addresses.into_iter().find(|ip| is_blocked_ip(*ip)) {
        Some(address) => Err(GuardError::Blocked {
            host: bare.to_owned(),
            address,
        }),
        None => Ok(()),
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
    fn loopback_hosts_are_recognised() {
        assert!(is_loopback_host("http://localhost:3000/mcp"));
        assert!(is_loopback_host("http://127.0.0.1/mcp"));
        assert!(is_loopback_host("http://[::1]:3000/mcp"));
        assert!(!is_loopback_host("http://example.com/mcp"));
    }
}
