//! Simple PROXY protocol v2 encoder.

use std::net::SocketAddr;

use const_for::const_for;

#[inline]
/// Encode PROXY protocol header.
///
/// Currently we only suoport PROXY protocol v2.
pub(crate) const fn encode_v2(
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<(usize, [u8; 64])> {
    let mut buf: [u8; 64] = [
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10,   // b"\r\n\r\n\x00\r\nQUIT\n"
        0x21, // Protocol version = v2, Command = PROXY
        0,    // transport protocol = TCP, address family = IPv4 / IPv6
        0, 0, // u16, the length of the source address, 12 for IPv4, 36 for IPv6
        // The following is data
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // ! Address family and transport protocol
    let len = match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            // TCP over IPv4
            buf[13] = 0x11;
            // 12u16, Big Endian => [0, 12]
            buf[15] = 12;
            // src_addr
            let src_addr = src.ip().octets();
            const_for!(i in 0..4 => {
                buf[16 + i] = src_addr[i];
            });
            // dst_addr
            let dst_addr = dst.ip().octets();
            const_for!(i in 0..4 => {
                buf[20 + i] = dst_addr[i];
            });
            // src_port
            let src_port = src.port().to_be_bytes();
            buf[24] = src_port[0];
            buf[25] = src_port[1];
            // dst_port
            let dst_port = dst.port().to_be_bytes();
            buf[26] = dst_port[0];
            buf[27] = dst_port[1];

            28
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            // TCP over IPv6
            buf[13] = 0x21;
            // 36u16, Big Endian => [0, 36]
            buf[15] = 36;
            // src_addr
            let src_addr = src.ip().octets();
            const_for!(i in 0..16 => {
                buf[16 + i] = src_addr[i];
            });
            // dst_addr
            let dst_addr = dst.ip().octets();
            const_for!(i in 0..16 => {
                buf[32 + i] = dst_addr[i];
            });
            // src_port
            let src_port = src.port().to_be_bytes();
            buf[48] = src_port[0];
            buf[49] = src_port[1];
            // dst_port
            let dst_port = dst.port().to_be_bytes();
            buf[50] = dst_port[0];
            buf[51] = dst_port[1];

            52
        }
        _ => return None,
    };

    Some((len, buf))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use super::encode_v2;

    #[test]
    fn test_encode_ipv4() {
        let (len, buf) = encode_v2(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 5678)),
        )
        .unwrap();

        assert_eq!(
            &buf[..len],
            b"\r\n\r\n\x00\r\nQUIT\n!\x11\x00\x0c\x7f\x00\x00\x01\x7f\x00\x00\x01\x04\xd2\x16."
        );
    }

    #[test]
    fn test_encode_ipv6() {
        let (len, buf) = encode_v2(
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                1234,
                0,
                0,
            )),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                5678,
                0,
                0,
            )),
        )
        .unwrap();

        assert_eq!(&buf[..len], &[
            13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 33, 0, 36, 32, 1, 13, 184, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 210, 22,
            46
        ]);
    }
}
