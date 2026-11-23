use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// Linux ARM64 网络/FD 相关错误码（负值）
pub const EAGAIN: i64 = -11;
pub const EACCES: i64 = -13;
pub const EINVAL: i64 = -22;
pub const EPIPE: i64 = -32;
pub const ENOTSOCK: i64 = -88;
pub const EAFNOSUPPORT: i64 = -97;
pub const EADDRINUSE: i64 = -98;
pub const ECONNRESET: i64 = -104;
pub const ENOTCONN: i64 = -107;
pub const ETIMEDOUT: i64 = -110;
pub const ECONNREFUSED: i64 = -111;
pub const EINPROGRESS: i64 = -115;

/// Linux Socket 常量
pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_NONBLOCK: i32 = 0o4000; // 0x800 on Linux AArch64
pub const SOCK_CLOEXEC: i32 = 0o2000000; // 0x80000 on Linux AArch64

pub const O_NONBLOCK: u32 = 0o4000;

/// `poll` / `epoll` 事件掩码
pub const POLLIN: u32 = 0x0001;
pub const POLLOUT: u32 = 0x0004;
pub const POLLERR: u32 = 0x0008;
pub const POLLHUP: u32 = 0x0010;
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;

pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

/// Linux `ioctl` 网络与非阻塞常量
pub const FIONBIO: u64 = 0x5421;
pub const SIOCGIFCONF: u64 = 0x8912;
pub const SIOCGIFFLAGS: u64 = 0x8913;
pub const SIOCGIFADDR: u64 = 0x8915;
pub const SIOCGIFNETMASK: u64 = 0x891B;
pub const SIOCGIFHWADDR: u64 = 0x8927;

/// 虚拟网卡画像（用于 `/proc/net/*`、`/sys/class/net/*`、`ioctl(SIOCGIF*)`、`getifaddrs`）
#[derive(Debug, Clone)]
pub struct VirtualNic {
    pub name: String,
    pub ipv4: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mac: [u8; 6],
    pub ipv6: String,
}

impl Default for VirtualNic {
    fn default() -> Self {
        Self {
            name: "wlan0".to_string(),
            ipv4: [192, 168, 1, 108],
            netmask: [255, 255, 255, 0],
            gateway: [192, 168, 1, 1],
            mac: [0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e],
            ipv6: "fe80::1a:2bff:fe3c:4d5e".to_string(),
        }
    }
}

impl VirtualNic {
    pub fn mac_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }

    pub fn ipv4_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.ipv4[0], self.ipv4[1], self.ipv4[2], self.ipv4[3]
        )
    }

    pub fn gateway_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.gateway[0], self.gateway[1], self.gateway[2], self.gateway[3]
        )
    }

    /// 合成 `/proc/net/route` 内容（Linux 内核小端十六进制格式）
    pub fn to_proc_net_route(&self) -> String {
        let gw_le = u32::from_le_bytes(self.gateway);
        let net_bytes = [
            self.ipv4[0] & self.netmask[0],
            self.ipv4[1] & self.netmask[1],
            self.ipv4[2] & self.netmask[2],
            self.ipv4[3] & self.netmask[3],
        ];
        let net_le = u32::from_le_bytes(net_bytes);
        let mask_le = u32::from_le_bytes(self.netmask);
        format!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
             {}\t00000000\t{:08X}\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             {}\t{:08X}\t00000000\t0001\t0\t0\t600\t{:08X}\t0\t0\t0\n",
            self.name, gw_le, self.name, net_le, mask_le
        )
    }

    /// 合成 `/proc/net/if_inet6` 内容
    pub fn to_proc_net_if_inet6(&self) -> String {
        format!(
            "00000000000000000000000000000001 01 80 10 80       lo\n\
             fe80000000000000001a2bfffe3c4d5e 02 40 20 80 {:>8}\n",
            self.name
        )
    }

    /// 合成 `/proc/net/arp` 内容
    pub fn to_proc_net_arp(&self) -> String {
        format!(
            "IP address       HW type     Flags       HW address            Mask     Device\n\
             {:<16} 0x1         0x2         aa:bb:cc:dd:ee:01     *        {}\n",
            self.gateway_string(),
            self.name
        )
    }
}

/// 网络子系统策略配置（默认关闭真实联网，确保离线样本分析安全）
#[derive(Debug, Clone, Default)]
pub struct NetConfig {
    /// 是否允许 Guest 通过宿主机真实收发 TCP/UDP 包
    pub enabled: bool,
    /// 允许连接的目标主机/IP 白名单（空列表表示 `enabled == true` 时放行全部）
    pub allow_hosts: Vec<String>,
    /// 是否自动记录收发包明细供 `emu.net.packets()` 查询
    pub capture_packets: bool,
    /// 虚拟网卡画像
    pub nic: VirtualNic,
}

/// 捕获的单个网络包记录
#[derive(Debug, Clone)]
pub struct PacketRecord {
    pub fd: i32,
    pub dir: &'static str, // "send" | "recv"
    pub peer: String,
    pub data: Vec<u8>,
}

/// 进程级网络/事件 FD 内部状态
pub enum NetFd {
    UnboundSocket {
        domain: i32,
        sock_type: i32,
        protocol: i32,
        nonblocking: bool,
        bound_addr: Option<SocketAddr>,
    },
    TcpStream {
        stream: TcpStream,
        nonblocking: bool,
        peer: Option<SocketAddr>,
    },
    TcpListener {
        listener: TcpListener,
        nonblocking: bool,
    },
    UdpSocket {
        socket: UdpSocket,
        nonblocking: bool,
        connected_peer: Option<SocketAddr>,
    },
    Epoll {
        /// watched_fd -> (events_mask, user_data)
        interests: BTreeMap<i32, (u32, u64)>,
    },
    EventFd {
        counter: u64,
        nonblocking: bool,
    },
    Pipe {
        /// 共享同一管道槽位 ID（支持 pipe2 / socketpair 双向或单向通信）
        pipe_id: usize,
        is_read_end: bool,
        nonblocking: bool,
    },
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PipeChannelTape {
    pub buf: Vec<u8>,
    pub write_closed: bool,
    pub read_closed: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum NetVirtualFdTape {
    Epoll {
        interests: Vec<(i32, u32, u64)>,
    },
    EventFd {
        counter: u64,
        nonblocking: bool,
    },
    Pipe {
        pipe_id: usize,
        is_read_end: bool,
        nonblocking: bool,
    },
}

/// 网络子系统可序列化状态（持久化虚拟网卡配置与内存态 Epoll/EventFd/Pipe，不含宿主机真实 Socket）
#[derive(Debug, Clone, Default)]
pub(crate) struct NetTapeState {
    pub config: NetConfig,
    pub virtual_fds: Vec<(i32, NetVirtualFdTape)>,
    pub pipes: Vec<(usize, PipeChannelTape)>,
    pub next_pipe_id: usize,
}

#[derive(Debug, Default)]
struct PipeChannel {
    buf: VecDeque<u8>,
    write_closed: bool,
    read_closed: bool,
}

/// 可选发包/收包拦截回调（参数: fd, peer, data -> 返回 `Some(new_data)` 替换内容，`None` 保持原样）
pub type PacketInterceptor = Box<dyn FnMut(i32, &str, &[u8]) -> Option<Vec<u8>>>;

/// 宿主机 Socket 透传 + Epoll/EventFD/Pipe + 虚拟网卡管理器
pub struct NetManager {
    pub config: NetConfig,
    fds: BTreeMap<i32, NetFd>,
    pipes: BTreeMap<usize, PipeChannel>,
    next_pipe_id: usize,
    packets: Vec<PacketRecord>,
    on_send: Option<PacketInterceptor>,
    on_recv: Option<PacketInterceptor>,
}

impl Default for NetManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetManager {
    pub fn new() -> Self {
        Self {
            config: NetConfig::default(),
            fds: BTreeMap::new(),
            pipes: BTreeMap::new(),
            next_pipe_id: 1,
            packets: Vec::new(),
            on_send: None,
            on_recv: None,
        }
    }

    pub fn set_on_send(&mut self, cb: Option<PacketInterceptor>) {
        self.on_send = cb;
    }

    pub fn set_on_recv(&mut self, cb: Option<PacketInterceptor>) {
        self.on_recv = cb;
    }

    pub fn packets(&self) -> &[PacketRecord] {
        &self.packets
    }

    pub fn clear_packets(&mut self) {
        self.packets.clear();
    }

    pub fn contains_fd(&self, fd: i32) -> bool {
        self.fds.contains_key(&fd)
    }

    pub(crate) fn export_tape_state(&self) -> NetTapeState {
        let mut virtual_fds = Vec::new();
        for (&fd, nfd) in &self.fds {
            match nfd {
                NetFd::Epoll { interests } => {
                    virtual_fds.push((
                        fd,
                        NetVirtualFdTape::Epoll {
                            interests: interests
                                .iter()
                                .map(|(&wfd, &(ev, ud))| (wfd, ev, ud))
                                .collect(),
                        },
                    ));
                }
                NetFd::EventFd {
                    counter,
                    nonblocking,
                } => {
                    virtual_fds.push((
                        fd,
                        NetVirtualFdTape::EventFd {
                            counter: *counter,
                            nonblocking: *nonblocking,
                        },
                    ));
                }
                NetFd::Pipe {
                    pipe_id,
                    is_read_end,
                    nonblocking,
                } => {
                    virtual_fds.push((
                        fd,
                        NetVirtualFdTape::Pipe {
                            pipe_id: *pipe_id,
                            is_read_end: *is_read_end,
                            nonblocking: *nonblocking,
                        },
                    ));
                }
                // 宿主机真实 Socket 句柄不可跨进程/跨时间线持久化
                NetFd::UnboundSocket { .. }
                | NetFd::TcpStream { .. }
                | NetFd::TcpListener { .. }
                | NetFd::UdpSocket { .. } => {}
            }
        }
        let pipes = self
            .pipes
            .iter()
            .map(|(&id, ch)| {
                (
                    id,
                    PipeChannelTape {
                        buf: ch.buf.iter().copied().collect(),
                        write_closed: ch.write_closed,
                        read_closed: ch.read_closed,
                    },
                )
            })
            .collect();
        NetTapeState {
            config: self.config.clone(),
            virtual_fds,
            pipes,
            next_pipe_id: self.next_pipe_id,
        }
    }

    pub(crate) fn restore_tape_state(&mut self, state: NetTapeState) {
        self.config = state.config;
        // 清理旧宿主机 Socket 与抓包记录，仅恢复内存态 Epoll/EventFd/Pipe
        self.fds.clear();
        for (fd, vfd) in state.virtual_fds {
            let entry = match vfd {
                NetVirtualFdTape::Epoll { interests } => NetFd::Epoll {
                    interests: interests
                        .into_iter()
                        .map(|(wfd, ev, ud)| (wfd, (ev, ud)))
                        .collect(),
                },
                NetVirtualFdTape::EventFd {
                    counter,
                    nonblocking,
                } => NetFd::EventFd {
                    counter,
                    nonblocking,
                },
                NetVirtualFdTape::Pipe {
                    pipe_id,
                    is_read_end,
                    nonblocking,
                } => NetFd::Pipe {
                    pipe_id,
                    is_read_end,
                    nonblocking,
                },
            };
            self.fds.insert(fd, entry);
        }
        self.pipes = state
            .pipes
            .into_iter()
            .map(|(id, ch)| {
                (
                    id,
                    PipeChannel {
                        buf: ch.buf.into_iter().collect(),
                        write_closed: ch.write_closed,
                        read_closed: ch.read_closed,
                    },
                )
            })
            .collect();
        self.next_pipe_id = state.next_pipe_id.max(1);
        self.packets.clear();
    }

    fn is_target_allowed(&self, addr: &SocketAddr) -> bool {
        if !self.config.enabled {
            return false;
        }
        if self.config.allow_hosts.is_empty() {
            return true;
        }
        let ip_str = addr.ip().to_string();
        let host_port = addr.to_string();
        self.config.allow_hosts.iter().any(|allowed| {
            allowed == "*"
                || allowed == &ip_str
                || allowed == &host_port
                || (allowed == "localhost" && addr.ip().is_loopback())
        })
    }

    fn is_host_allowed(&self, host: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        if self.config.allow_hosts.is_empty() {
            return true;
        }
        self.config
            .allow_hosts
            .iter()
            .any(|a| a == "*" || a.eq_ignore_ascii_case(host))
    }

    /// 创建 Socket（注册到指定 Guest FD）
    pub fn create_socket(&mut self, fd: i32, domain: i32, raw_type: i32, protocol: i32) -> i64 {
        let nonblocking = (raw_type & SOCK_NONBLOCK) != 0;
        let sock_type = raw_type & 0xF;
        if domain != AF_INET && domain != AF_INET6 && domain != AF_UNIX {
            return EAFNOSUPPORT;
        }
        if sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM {
            return EINVAL;
        }
        if !self.config.enabled {
            let fam = match domain {
                AF_INET => "AF_INET",
                AF_INET6 => "AF_INET6",
                _ => "AF_UNIX",
            };
            let ty = if sock_type == SOCK_STREAM { "SOCK_STREAM" } else { "SOCK_DGRAM" };
            tracing::warn!(
                target: "runidbg::net",
                fd,
                domain = fam,
                sock_type = ty,
                protocol,
                "网络默认已关闭：Guest 创建了 Socket（后续外连将被拦截；如需放行请配置 Emu.create({{ net: {{ enabled: true }} }})）"
            );
        }
        self.fds.insert(
            fd,
            NetFd::UnboundSocket {
                domain,
                sock_type,
                protocol,
                nonblocking,
                bound_addr: None,
            },
        );
        fd as i64
    }

    /// 创建 `epoll` 实例 FD
    pub fn create_epoll(&mut self, fd: i32) -> i64 {
        self.fds.insert(
            fd,
            NetFd::Epoll {
                interests: BTreeMap::new(),
            },
        );
        fd as i64
    }

    /// 创建 `eventfd2` FD
    pub fn create_eventfd(&mut self, fd: i32, initval: u64, flags: u32) -> i64 {
        let nonblocking = (flags & O_NONBLOCK) != 0;
        self.fds.insert(
            fd,
            NetFd::EventFd {
                counter: initval,
                nonblocking,
            },
        );
        fd as i64
    }

    /// 创建 `pipe2` 读写双端 FD
    pub fn create_pipe(&mut self, rfd: i32, wfd: i32, flags: u32) -> i64 {
        let nonblocking = (flags & O_NONBLOCK) != 0;
        let pipe_id = self.next_pipe_id;
        self.next_pipe_id += 1;
        self.pipes.insert(pipe_id, PipeChannel::default());
        self.fds.insert(
            rfd,
            NetFd::Pipe {
                pipe_id,
                is_read_end: true,
                nonblocking,
            },
        );
        self.fds.insert(
            wfd,
            NetFd::Pipe {
                pipe_id,
                is_read_end: false,
                nonblocking,
            },
        );
        0
    }

    pub fn close_fd(&mut self, fd: i32) -> bool {
        let Some(entry) = self.fds.remove(&fd) else {
            return false;
        };
        if let NetFd::Pipe {
            pipe_id,
            is_read_end,
            ..
        } = entry
        {
            if let Some(ch) = self.pipes.get_mut(&pipe_id) {
                if is_read_end {
                    ch.read_closed = true;
                } else {
                    ch.write_closed = true;
                }
                if ch.read_closed && ch.write_closed {
                    self.pipes.remove(&pipe_id);
                }
            }
        }
        true
    }

    pub fn set_nonblocking(&mut self, fd: i32, nb: bool) -> i64 {
        let Some(entry) = self.fds.get_mut(&fd) else {
            return ENOTSOCK;
        };
        match entry {
            NetFd::UnboundSocket { nonblocking, .. }
            | NetFd::EventFd { nonblocking, .. }
            | NetFd::Pipe { nonblocking, .. } => {
                *nonblocking = nb;
                0
            }
            NetFd::TcpStream {
                stream,
                nonblocking,
                ..
            } => {
                let _ = stream.set_nonblocking(nb);
                *nonblocking = nb;
                0
            }
            NetFd::TcpListener {
                listener,
                nonblocking,
            } => {
                let _ = listener.set_nonblocking(nb);
                *nonblocking = nb;
                0
            }
            NetFd::UdpSocket {
                socket,
                nonblocking,
                ..
            } => {
                let _ = socket.set_nonblocking(nb);
                *nonblocking = nb;
                0
            }
            NetFd::Epoll { .. } => 0,
        }
    }

    pub fn is_nonblocking(&self, fd: i32) -> bool {
        match self.fds.get(&fd) {
            Some(NetFd::UnboundSocket { nonblocking, .. })
            | Some(NetFd::TcpStream { nonblocking, .. })
            | Some(NetFd::TcpListener { nonblocking, .. })
            | Some(NetFd::UdpSocket { nonblocking, .. })
            | Some(NetFd::EventFd { nonblocking, .. })
            | Some(NetFd::Pipe { nonblocking, .. }) => *nonblocking,
            _ => false,
        }
    }

    pub fn bind(&mut self, fd: i32, addr: SocketAddr) -> i64 {
        if !self.config.enabled {
            tracing::warn!(
                target: "runidbg::net",
                fd,
                addr = %addr,
                "已拦截 bind({addr}) -> -EACCES（网络默认关闭）"
            );
            return EACCES;
        }
        let Some(entry) = self.fds.get_mut(&fd) else {
            return ENOTSOCK;
        };
        match entry {
            NetFd::UnboundSocket {
                sock_type,
                nonblocking,
                bound_addr,
                ..
            } => {
                if *sock_type == SOCK_DGRAM {
                    match UdpSocket::bind(addr) {
                        Ok(sock) => {
                            let _ = sock.set_nonblocking(*nonblocking);
                            let nb = *nonblocking;
                            *entry = NetFd::UdpSocket {
                                socket: sock,
                                nonblocking: nb,
                                connected_peer: None,
                            };
                            0
                        }
                        Err(e) => io_err_to_errno(&e),
                    }
                } else {
                    *bound_addr = Some(addr);
                    0
                }
            }
            _ => EINVAL,
        }
    }

    pub fn listen(&mut self, fd: i32) -> i64 {
        if !self.config.enabled {
            tracing::warn!(
                target: "runidbg::net",
                fd,
                "已拦截 listen(fd={fd}) -> -EACCES（网络默认关闭）"
            );
            return EACCES;
        }
        let Some(entry) = self.fds.get_mut(&fd) else {
            return ENOTSOCK;
        };
        match entry {
            NetFd::UnboundSocket {
                sock_type,
                nonblocking,
                bound_addr,
                ..
            } if *sock_type == SOCK_STREAM => {
                let bind_at = bound_addr
                    .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
                match TcpListener::bind(bind_at) {
                    Ok(listener) => {
                        let nb = *nonblocking;
                        let _ = listener.set_nonblocking(nb);
                        *entry = NetFd::TcpListener {
                            listener,
                            nonblocking: nb,
                        };
                        0
                    }
                    Err(e) => io_err_to_errno(&e),
                }
            }
            _ => EINVAL,
        }
    }

    pub fn accept(&mut self, fd: i32, new_fd: i32, flags: i32) -> Result<SocketAddr, i64> {
        let Some(NetFd::TcpListener { listener, .. }) = self.fds.get(&fd) else {
            return Err(ENOTSOCK);
        };
        match listener.accept() {
            Ok((stream, peer)) => {
                let nb = (flags & SOCK_NONBLOCK) != 0;
                let _ = stream.set_nonblocking(nb);
                self.fds.insert(
                    new_fd,
                    NetFd::TcpStream {
                        stream,
                        nonblocking: nb,
                        peer: Some(peer),
                    },
                );
                Ok(peer)
            }
            Err(e) => Err(io_err_to_errno(&e)),
        }
    }

    pub fn connect(&mut self, fd: i32, addr: SocketAddr) -> i64 {
        if !self.is_target_allowed(&addr) {
            tracing::warn!(
                target: "runidbg::net",
                fd,
                target = %addr,
                enabled = self.config.enabled,
                "已拦截 connect({addr}) -> -EACCES（网络关闭或目标不在 allowHosts 白名单内）"
            );
            return EACCES;
        }
        let Some(entry) = self.fds.get_mut(&fd) else {
            return ENOTSOCK;
        };
        match entry {
            NetFd::UnboundSocket {
                sock_type,
                nonblocking,
                bound_addr,
                ..
            } => {
                let nb = *nonblocking;
                if *sock_type == SOCK_STREAM {
                    match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
                        Ok(stream) => {
                            let _ = stream.set_nonblocking(nb);
                            *entry = NetFd::TcpStream {
                                stream,
                                nonblocking: nb,
                                peer: Some(addr),
                            };
                            0
                        }
                        Err(e) => io_err_to_errno(&e),
                    }
                } else {
                    let local = bound_addr.unwrap_or_else(|| match addr {
                        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                    });
                    match UdpSocket::bind(local) {
                        Ok(sock) => {
                            if let Err(e) = sock.connect(addr) {
                                return io_err_to_errno(&e);
                            }
                            let _ = sock.set_nonblocking(nb);
                            *entry = NetFd::UdpSocket {
                                socket: sock,
                                nonblocking: nb,
                                connected_peer: Some(addr),
                            };
                            0
                        }
                        Err(e) => io_err_to_errno(&e),
                    }
                }
            }
            NetFd::UdpSocket {
                socket,
                connected_peer,
                ..
            } => match socket.connect(addr) {
                Ok(()) => {
                    *connected_peer = Some(addr);
                    0
                }
                Err(e) => io_err_to_errno(&e),
            },
            NetFd::TcpStream { .. } => 0,
            _ => EINVAL,
        }
    }

    pub fn send(&mut self, fd: i32, data: &[u8], dest: Option<SocketAddr>) -> i64 {
        if let Some(d) = dest {
            if !self.is_target_allowed(&d) {
                tracing::warn!(
                    target: "runidbg::net",
                    fd,
                    dest = %d,
                    len = data.len(),
                    enabled = self.config.enabled,
                    "已拦截 sendto({d}, {} bytes) -> -EACCES（网络关闭或目标不在 allowHosts 白名单内）",
                    data.len()
                );
                return EACCES;
            }
        }
        let peer_str = dest
            .map(|a| a.to_string())
            .or_else(|| self.peer_addr(fd).map(|a| a.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        let payload_owned: Vec<u8> = if let Some(ref mut cb) = self.on_send {
            cb(fd, &peer_str, data).unwrap_or_else(|| data.to_vec())
        } else {
            data.to_vec()
        };

        let res = match self.fds.get_mut(&fd) {
            Some(NetFd::TcpStream { stream, .. }) => match stream.write(&payload_owned) {
                Ok(n) => n as i64,
                Err(e) => io_err_to_errno(&e),
            },
            Some(NetFd::UdpSocket {
                socket,
                connected_peer,
                ..
            }) => {
                let r = if let Some(target) = dest {
                    socket.send_to(&payload_owned, target)
                } else if connected_peer.is_some() {
                    socket.send(&payload_owned)
                } else {
                    return ENOTCONN;
                };
                match r {
                    Ok(n) => n as i64,
                    Err(e) => io_err_to_errno(&e),
                }
            }
            Some(NetFd::UnboundSocket {
                sock_type,
                nonblocking,
                ..
            }) if *sock_type == SOCK_DGRAM => {
                let Some(target) = dest else {
                    return ENOTCONN;
                };
                let local = match target {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };
                let nb = *nonblocking;
                match UdpSocket::bind(local) {
                    Ok(sock) => {
                        let _ = sock.set_nonblocking(nb);
                        let r = sock.send_to(&payload_owned, target);
                        self.fds.insert(
                            fd,
                            NetFd::UdpSocket {
                                socket: sock,
                                nonblocking: nb,
                                connected_peer: None,
                            },
                        );
                        match r {
                            Ok(n) => n as i64,
                            Err(e) => io_err_to_errno(&e),
                        }
                    }
                    Err(e) => io_err_to_errno(&e),
                }
            }
            Some(NetFd::EventFd { counter, .. }) => {
                if payload_owned.len() < 8 {
                    return EINVAL;
                }
                let add = u64::from_le_bytes(payload_owned[..8].try_into().unwrap_or([0; 8]));
                *counter = counter.saturating_add(add);
                8
            }
            Some(NetFd::Pipe {
                pipe_id,
                is_read_end,
                ..
            }) => {
                if *is_read_end {
                    return EINVAL;
                }
                let pid = *pipe_id;
                if let Some(ch) = self.pipes.get_mut(&pid) {
                    if ch.read_closed {
                        return EPIPE;
                    }
                    ch.buf.extend(&payload_owned);
                    payload_owned.len() as i64
                } else {
                    EPIPE
                }
            }
            _ => ENOTSOCK,
        };

        if res > 0 && self.config.capture_packets {
            let n = (res as usize).min(payload_owned.len());
            self.packets.push(PacketRecord {
                fd,
                dir: "send",
                peer: peer_str,
                data: payload_owned[..n].to_vec(),
            });
        }
        res
    }

    pub fn recv(&mut self, fd: i32, max_len: usize) -> Result<(Vec<u8>, Option<SocketAddr>), i64> {
        let mut buf = vec![0u8; max_len.min(1024 * 1024)];
        let (n, peer) = match self.fds.get_mut(&fd) {
            Some(NetFd::TcpStream { stream, peer, .. }) => match stream.read(&mut buf) {
                Ok(n) => (n, *peer),
                Err(e) => return Err(io_err_to_errno(&e)),
            },
            Some(NetFd::UdpSocket { socket, .. }) => match socket.recv_from(&mut buf) {
                Ok((n, src)) => (n, Some(src)),
                Err(e) => return Err(io_err_to_errno(&e)),
            },
            Some(NetFd::EventFd { counter, .. }) => {
                if max_len < 8 {
                    return Err(EINVAL);
                }
                if *counter == 0 {
                    return Err(EAGAIN);
                }
                let val = *counter;
                *counter = 0;
                buf[..8].copy_from_slice(&val.to_le_bytes());
                (8, None)
            }
            Some(NetFd::Pipe {
                pipe_id,
                is_read_end,
                ..
            }) => {
                if !*is_read_end {
                    return Err(EINVAL);
                }
                let pid = *pipe_id;
                if let Some(ch) = self.pipes.get_mut(&pid) {
                    if ch.buf.is_empty() {
                        if ch.write_closed {
                            (0, None)
                        } else {
                            return Err(EAGAIN);
                        }
                    } else {
                        let take = ch.buf.len().min(buf.len());
                        for slot in buf.iter_mut().take(take) {
                            *slot = ch.buf.pop_front().unwrap_or(0);
                        }
                        (take, None)
                    }
                } else {
                    (0, None)
                }
            }
            _ => return Err(ENOTSOCK),
        };

        buf.truncate(n);
        let peer_str = peer
            .map(|a| a.to_string())
            .unwrap_or_else(|| "local".to_string());
        if n > 0 {
            if let Some(ref mut cb) = self.on_recv {
                if let Some(replaced) = cb(fd, &peer_str, &buf) {
                    buf = replaced;
                    if buf.len() > max_len {
                        buf.truncate(max_len);
                    }
                }
            }
            if self.config.capture_packets {
                self.packets.push(PacketRecord {
                    fd,
                    dir: "recv",
                    peer: peer_str,
                    data: buf.clone(),
                });
            }
        }
        Ok((buf, peer))
    }

    pub fn shutdown(&mut self, fd: i32, how: i32) -> i64 {
        let Some(NetFd::TcpStream { stream, .. }) = self.fds.get(&fd) else {
            return 0;
        };
        let mode = match how {
            0 => Shutdown::Read,
            1 => Shutdown::Write,
            _ => Shutdown::Both,
        };
        match stream.shutdown(mode) {
            Ok(()) => 0,
            Err(e) => io_err_to_errno(&e),
        }
    }

    pub fn local_addr(&self, fd: i32) -> Option<SocketAddr> {
        match self.fds.get(&fd) {
            Some(NetFd::TcpStream { stream, .. }) => stream.local_addr().ok(),
            Some(NetFd::TcpListener { listener, .. }) => listener.local_addr().ok(),
            Some(NetFd::UdpSocket { socket, .. }) => socket.local_addr().ok(),
            Some(NetFd::UnboundSocket { bound_addr, .. }) => *bound_addr,
            _ => None,
        }
    }

    pub fn peer_addr(&self, fd: i32) -> Option<SocketAddr> {
        match self.fds.get(&fd) {
            Some(NetFd::TcpStream { stream, peer, .. }) => stream.peer_addr().ok().or(*peer),
            Some(NetFd::UdpSocket {
                socket,
                connected_peer,
                ..
            }) => socket.peer_addr().ok().or(*connected_peer),
            _ => None,
        }
    }

    pub fn epoll_ctl(&mut self, epfd: i32, op: i32, target_fd: i32, events: u32, data: u64) -> i64 {
        let Some(NetFd::Epoll { interests }) = self.fds.get_mut(&epfd) else {
            return EINVAL;
        };
        match op {
            EPOLL_CTL_ADD | EPOLL_CTL_MOD => {
                interests.insert(target_fd, (events, data));
                0
            }
            EPOLL_CTL_DEL => {
                interests.remove(&target_fd);
                0
            }
            _ => EINVAL,
        }
    }

    /// 检查单个 FD 当前可读/可写就绪事件
    pub fn probe_fd_readiness(&self, fd: i32, want_events: u32) -> u32 {
        let mut ready = 0u32;
        match self.fds.get(&fd) {
            Some(NetFd::EventFd { counter, .. }) => {
                if (want_events & POLLIN) != 0 && *counter > 0 {
                    ready |= POLLIN;
                }
                if (want_events & POLLOUT) != 0 {
                    ready |= POLLOUT;
                }
            }
            Some(NetFd::Pipe {
                pipe_id,
                is_read_end,
                ..
            }) => {
                if let Some(ch) = self.pipes.get(pipe_id) {
                    if *is_read_end {
                        if (want_events & POLLIN) != 0 && (!ch.buf.is_empty() || ch.write_closed) {
                            ready |= POLLIN;
                        }
                        if ch.write_closed && ch.buf.is_empty() {
                            ready |= POLLHUP;
                        }
                    } else if (want_events & POLLOUT) != 0 && !ch.read_closed {
                        ready |= POLLOUT;
                    }
                }
            }
            Some(NetFd::TcpStream {
                stream,
                nonblocking,
                ..
            }) => {
                if (want_events & POLLOUT) != 0 {
                    ready |= POLLOUT;
                }
                if (want_events & POLLIN) != 0 {
                    if !*nonblocking {
                        let _ = stream.set_nonblocking(true);
                    }
                    let mut tmp = [0u8; 1];
                    match stream.peek(&mut tmp) {
                        Ok(0) => ready |= POLLIN | POLLHUP,
                        Ok(_) => ready |= POLLIN,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => ready |= POLLERR,
                    }
                    if !*nonblocking {
                        let _ = stream.set_nonblocking(false);
                    }
                }
            }
            Some(NetFd::UdpSocket {
                socket,
                nonblocking,
                ..
            }) => {
                if (want_events & POLLOUT) != 0 {
                    ready |= POLLOUT;
                }
                if (want_events & POLLIN) != 0 {
                    if !*nonblocking {
                        let _ = socket.set_nonblocking(true);
                    }
                    let mut tmp = [0u8; 1];
                    match socket.peek(&mut tmp) {
                        Ok(_) => ready |= POLLIN,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => ready |= POLLERR,
                    }
                    if !*nonblocking {
                        let _ = socket.set_nonblocking(false);
                    }
                }
            }
            Some(NetFd::TcpListener { .. }) if (want_events & POLLIN) != 0 => {
                ready |= POLLIN;
            }
            _ => {}
        }
        ready
    }

    /// 执行 `epoll_pwait`（带超时轮询，返回 `(events, user_data)` 列表）
    pub fn epoll_wait(&self, epfd: i32, max_events: usize, timeout_ms: i32) -> Result<Vec<(u32, u64)>, i64> {
        let Some(NetFd::Epoll { interests }) = self.fds.get(&epfd) else {
            return Err(EINVAL);
        };
        let list: Vec<(i32, u32, u64)> = interests
            .iter()
            .map(|(&fd, &(ev, data))| (fd, ev, data))
            .collect();

        let deadline = if timeout_ms < 0 {
            Some(Instant::now() + Duration::from_secs(5))
        } else {
            Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
        };

        loop {
            let mut ready = Vec::new();
            for &(fd, ev, data) in &list {
                let got = self.probe_fd_readiness(fd, ev);
                if got != 0 {
                    ready.push((got, data));
                    if ready.len() >= max_events {
                        break;
                    }
                }
            }
            if !ready.is_empty() || timeout_ms == 0 {
                return Ok(ready);
            }
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Ok(ready);
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// 执行 `ppoll` / `poll`（返回就绪 FD 数量及对应的 `revents`）
    pub fn poll_fds(&self, fds: &[(i32, u16)], timeout_ms: i32) -> Vec<u16> {
        let deadline = if timeout_ms < 0 {
            Some(Instant::now() + Duration::from_secs(5))
        } else {
            Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
        };

        loop {
            let mut revents = vec![0u16; fds.len()];
            let mut count = 0usize;
            for (i, &(fd, ev)) in fds.iter().enumerate() {
                let got = self.probe_fd_readiness(fd, ev as u32) as u16;
                if got != 0 {
                    revents[i] = got;
                    count += 1;
                }
            }
            if count > 0 || timeout_ms == 0 {
                return revents;
            }
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return revents;
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// DNS 解析（受 `NetConfig` 白名单保护）
    pub fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, i64> {
        if !self.is_host_allowed(host) {
            tracing::warn!(
                target: "runidbg::net",
                host,
                port,
                enabled = self.config.enabled,
                "已拦截 DNS 解析 getaddrinfo({host}:{port}) -> -EACCES（网络关闭或主机不在 allowHosts 白名单内）"
            );
            return Err(EACCES);
        }
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|_| EINVAL)?
            .collect();
        Ok(addrs)
    }
}

/// 解析 Linux `sockaddr_in` (16B) / `sockaddr_in6` (28B)
pub fn parse_sockaddr(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < 4 {
        return None;
    }
    let family = u16::from_le_bytes([bytes[0], bytes[1]]) as i32;
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family {
        AF_INET if bytes.len() >= 8 => {
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        AF_INET6 if bytes.len() >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let ip = Ipv6Addr::from(octets);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

/// 序列化 `SocketAddr` 为 Linux `sockaddr_in` (16B) / `sockaddr_in6` (28B)
pub fn serialize_sockaddr(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut out = vec![0u8; 16];
            out[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
            out[2..4].copy_from_slice(&v4.port().to_be_bytes());
            out[4..8].copy_from_slice(&v4.ip().octets());
            out
        }
        SocketAddr::V6(v6) => {
            let mut out = vec![0u8; 28];
            out[0..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
            out[2..4].copy_from_slice(&v6.port().to_be_bytes());
            out[8..24].copy_from_slice(&v6.ip().octets());
            out
        }
    }
}

fn io_err_to_errno(err: &io::Error) -> i64 {
    match err.kind() {
        io::ErrorKind::WouldBlock => EAGAIN,
        io::ErrorKind::ConnectionRefused => ECONNREFUSED,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => ECONNRESET,
        io::ErrorKind::NotConnected => ENOTCONN,
        io::ErrorKind::AddrInUse => EADDRINUSE,
        io::ErrorKind::TimedOut => ETIMEDOUT,
        io::ErrorKind::PermissionDenied => EACCES,
        io::ErrorKind::BrokenPipe => EPIPE,
        _ => EINVAL,
    }
}
