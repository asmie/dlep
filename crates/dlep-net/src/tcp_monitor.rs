//! Linux packet monitoring supplements IP_MINTTL: the kernel drops bad
//! segments, while the monitor resets the matching established connection.
//! Packet sockets require CAP_NET_RAW. No packet contents are retained.

#[cfg(target_os = "linux")]
mod platform {
    use std::collections::HashMap;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::AsRawFd;
    use std::sync::{Arc, Mutex};

    use nix::libc;
    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tokio::net::TcpStream;
    use tokio::task::JoinHandle;

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    struct Connection {
        local: SocketAddr,
        peer: SocketAddr,
    }

    #[derive(Default)]
    struct State {
        sockets: HashMap<Connection, Arc<Socket>>,
        failed: bool,
    }

    pub(crate) struct Monitor {
        state: Arc<Mutex<State>>,
        task: JoinHandle<()>,
    }

    impl Monitor {
        pub(crate) fn new() -> io::Result<Arc<Self>> {
            let socket = Socket::new(
                Domain::from(libc::AF_PACKET),
                Type::DGRAM,
                Some(Protocol::from(i32::from((libc::ETH_P_ALL as u16).to_be()))),
            )
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "strict TCP GTSM requires a Linux packet socket (CAP_NET_RAW): {error}"
                    ),
                )
            })?;
            filter_low_ttl(&socket)?;
            socket.set_nonblocking(true)?;
            let socket = AsyncFd::new(socket)?;
            let state = Arc::new(Mutex::new(State::default()));
            let task_state = state.clone();
            let task = tokio::spawn(async move {
                if let Err(error) = receive(socket, &task_state).await {
                    tracing::error!(%error, "GTSM monitor failed; resetting monitored connections");
                    let mut state = task_state.lock().unwrap();
                    state.failed = true;
                    for socket in state.sockets.values() {
                        reset(socket);
                    }
                }
            });
            Ok(Arc::new(Self { state, task }))
        }

        pub(crate) fn register(self: &Arc<Self>, stream: &TcpStream) -> io::Result<Registration> {
            let connection = Connection {
                local: normalize(stream.local_addr()?),
                peer: normalize(stream.peer_addr()?),
            };
            let socket = Arc::new(socket2::SockRef::from(stream).try_clone()?);
            let mut state = self.state.lock().unwrap();
            if state.failed {
                return Err(io::Error::other("TCP GTSM monitor has failed"));
            }
            state.sockets.insert(connection, socket.clone());
            Ok(Registration {
                monitor: self.clone(),
                connection,
                socket,
            })
        }
    }

    impl Drop for Monitor {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub(crate) struct Registration {
        monitor: Arc<Monitor>,
        connection: Connection,
        socket: Arc<Socket>,
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            let mut state = self.monitor.state.lock().unwrap();
            // A reset tuple may already have been reused by a new connection.
            if state
                .sockets
                .get(&self.connection)
                .is_some_and(|s| Arc::ptr_eq(s, &self.socket))
            {
                state.sockets.remove(&self.connection);
            }
        }
    }

    // Discard conforming traffic in the kernel so ordinary bulk data never
    // wakes the monitor. Offsets are relative to the stripped IP header.
    fn filter_low_ttl(socket: &Socket) -> io::Result<()> {
        let ins = |code, jt, jf, k| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let mut instructions = [
            ins(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 0),
            ins(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K, 0, 0, 0xf0),
            ins(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 3, 0x40),
            ins(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 8),
            ins(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 5, 0, 255),
            ins(libc::BPF_RET | libc::BPF_K, 0, 0, 65_536),
            ins(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 3, 0x60),
            ins(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 7),
            ins(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 1, 0, 255),
            ins(libc::BPF_RET | libc::BPF_K, 0, 0, 65_536),
            ins(libc::BPF_RET | libc::BPF_K, 0, 0, 0),
        ];
        let program = libc::sock_fprog {
            len: instructions.len() as u16,
            filter: instructions.as_mut_ptr(),
        };
        // SAFETY: both the program and instruction array live until setsockopt
        // returns; SO_ATTACH_FILTER copies and validates the complete program.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                (&program as *const libc::sock_fprog).cast(),
                std::mem::size_of_val(&program) as libc::socklen_t,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn normalize(addr: SocketAddr) -> SocketAddr {
        match addr {
            SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
                Some(v4) => SocketAddr::new(v4.into(), v6.port()),
                None => addr,
            },
            _ => addr,
        }
    }

    /// AF_UNSPEC disconnect aborts a Linux TCP connection and sends RST,
    /// even while another fd references it. Readers wake with EOF/error.
    fn reset(socket: &Socket) {
        let addr = libc::sockaddr {
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        // SAFETY: socket and the initialized sockaddr remain valid throughout
        // connect; the kernel copies the address and retains no pointer.
        let result = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                &addr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        if result < 0 {
            tracing::error!(error = %io::Error::last_os_error(), "TCP GTSM reset failed");
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    }

    async fn receive(socket: AsyncFd<Socket>, state: &Mutex<State>) -> io::Result<()> {
        let mut buf = vec![0u8; 65_536];
        loop {
            let mut ready = socket.readable().await?;
            let result = ready.try_io(|socket| {
                // SAFETY: zero is a valid initial sockaddr_ll representation;
                // recvfrom writes at most the supplied buffer/address lengths.
                let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                let mut addr_len = std::mem::size_of_val(&addr) as libc::socklen_t;
                let size = unsafe {
                    libc::recvfrom(
                        socket.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        0,
                        (&mut addr as *mut libc::sockaddr_ll).cast(),
                        &mut addr_len,
                    )
                };
                if size < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok((size as usize, addr))
                }
            });
            let (size, addr) = match result {
                Err(_) => continue,
                Ok(result) => result?,
            };
            // Outbound traffic may share a tuple with another local session.
            // Loopback also delivers an incoming copy, which is checked.
            if !matches!(
                i32::from(u16::from_be(addr.sll_protocol)),
                libc::ETH_P_IP | libc::ETH_P_IPV6
            ) {
                continue;
            }
            if addr.sll_pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            if let Some(connection) = low_ttl_connection(&buf[..size], addr.sll_ifindex as u32) {
                let state = state.lock().unwrap();
                if let Some(socket) = state.sockets.get(&connection) {
                    tracing::warn!(peer = %connection.peer, "TCP GTSM violation; resetting connection");
                    reset(socket);
                }
            }
        }
    }

    // SOCK_DGRAM strips the link-layer header. Bounds-check all variable IP
    // headers and never interpret a later fragment's payload as TCP ports.
    fn low_ttl_connection(packet: &[u8], interface: u32) -> Option<Connection> {
        let (source, dest, offset) = match packet.first()? >> 4 {
            4 => {
                if packet.len() < 20 || packet[8] == 255 || packet[9] != 6 {
                    return None;
                }
                let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
                let offset = usize::from(packet[0] & 15) * 4;
                if offset < 20
                    || length < offset + 20
                    || length > packet.len()
                    || u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0
                {
                    return None;
                }
                (
                    IpAddr::V4(Ipv4Addr::new(
                        packet[12], packet[13], packet[14], packet[15],
                    )),
                    IpAddr::V4(Ipv4Addr::new(
                        packet[16], packet[17], packet[18], packet[19],
                    )),
                    offset,
                )
            }
            6 => {
                if packet.len() < 40 || packet[7] == 255 {
                    return None;
                }
                let length = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
                if length > packet.len() {
                    return None;
                }
                let mut next = packet[6];
                let mut offset = 40;
                while next != 6 {
                    let header = packet.get(offset..length)?;
                    let kind = next;
                    next = *header.first()?;
                    let size = match kind {
                        0 | 43 | 60 => (usize::from(*header.get(1)?) + 1) * 8,
                        51 => (usize::from(*header.get(1)?) + 2) * 4,
                        44 => {
                            if u16::from_be_bytes([*header.get(2)?, *header.get(3)?]) & 0xfff8 != 0
                            {
                                return None;
                            }
                            8
                        }
                        _ => return None,
                    };
                    offset += size;
                }
                if offset + 20 > length {
                    return None;
                }
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
                    offset,
                )
            }
            _ => return None,
        };
        let tcp = packet.get(offset..offset + 20)?;
        if tcp[12] >> 4 < 5 {
            return None;
        }
        let addr = |ip, port| {
            let mut addr = SocketAddr::new(ip, port);
            if let SocketAddr::V6(ref mut v6) = addr {
                if v6.ip().is_unicast_link_local() {
                    v6.set_scope_id(interface);
                }
            }
            addr
        };
        Some(Connection {
            local: addr(dest, u16::from_be_bytes([tcp[2], tcp[3]])),
            peer: addr(source, u16::from_be_bytes([tcp[0], tcp[1]])),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio::time::{Duration, timeout};

        #[tokio::test]
        async fn disconnect_resets_peer_and_wakes_local_reader() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut peer = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut local, _) = listener.accept().await.unwrap();
            let socket = socket2::SockRef::from(&local).try_clone().unwrap();
            reset(&socket);
            let mut buf = [0; 1];
            let error = timeout(Duration::from_secs(1), peer.read(&mut buf))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            let result = timeout(Duration::from_secs(1), local.read(&mut buf))
                .await
                .unwrap();
            assert!(matches!(result, Ok(0) | Err(_)));
        }

        #[test]
        fn packet_parser_rejects_truncation_fragments_and_valid_ttl() {
            let mut packet = vec![0; 40];
            packet[0] = 0x45;
            packet[3] = 40;
            packet[8] = 254;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
            packet[16..20].copy_from_slice(&[192, 0, 2, 2]);
            packet[20..24].copy_from_slice(&[0x03, 0x56, 0x12, 0x34]);
            packet[32] = 0x50;
            let connection = low_ttl_connection(&packet, 1).unwrap();
            assert_eq!(connection.peer, "192.0.2.1:854".parse().unwrap());
            assert_eq!(connection.local, "192.0.2.2:4660".parse().unwrap());
            for size in 0..40 {
                assert!(low_ttl_connection(&packet[..size], 1).is_none());
            }
            packet[8] = 255;
            assert!(low_ttl_connection(&packet, 1).is_none());
            packet[8] = 254;
            packet[7] = 1;
            assert!(low_ttl_connection(&packet, 1).is_none());
        }

        #[test]
        fn ipv6_extension_header_and_scope_are_checked() {
            let mut packet = vec![0; 68];
            packet[0] = 0x60;
            packet[5] = 28;
            packet[6] = 0; // hop-by-hop header
            packet[7] = 254;
            packet[8..24].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
            packet[24..40].copy_from_slice(&"fe80::2".parse::<Ipv6Addr>().unwrap().octets());
            packet[40] = 6;
            packet[48..52].copy_from_slice(&[0x03, 0x56, 0x12, 0x34]);
            packet[60] = 0x50;
            let connection = low_ttl_connection(&packet, 7).unwrap();
            assert_eq!(connection.peer, "[fe80::1%7]:854".parse().unwrap());
            for size in 0..68 {
                assert!(low_ttl_connection(&packet[..size], 7).is_none());
            }
            packet[7] = 255;
            assert!(low_ttl_connection(&packet, 7).is_none());
            packet[7] = 254;
            packet[41] = 255;
            assert!(low_ttl_connection(&packet, 7).is_none());
            packet[6] = 44;
            packet[43] = 8;
            assert!(low_ttl_connection(&packet, 7).is_none());
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::{io, sync::Arc};
    pub(crate) struct Monitor;
    pub(crate) struct Registration;
    impl Monitor {
        pub(crate) fn new() -> io::Result<Arc<Self>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "strict TCP GTSM requires Linux",
            ))
        }
        pub(crate) fn register(
            self: &Arc<Self>,
            _: &tokio::net::TcpStream,
        ) -> io::Result<Registration> {
            unreachable!()
        }
    }
}

pub(crate) use platform::{Monitor, Registration};
