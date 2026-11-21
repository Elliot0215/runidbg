use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;

use runidbg_arm64_emu_tracer::os::net::{
    serialize_sockaddr, AF_INET, EACCES, EPOLLIN, EPOLL_CTL_ADD, SIOCGIFADDR, SIOCGIFHWADDR,
    SOCK_DGRAM, SOCK_STREAM,
};
use runidbg_arm64_emu_tracer::os::syscall::{
    SYS_CLOSE, SYS_CONNECT, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_PWAIT, SYS_EVENTFD2,
    SYS_IOCTL, SYS_PIPE2, SYS_READ, SYS_RECVFROM, SYS_SENDTO, SYS_SOCKET, SYS_WRITE,
};
use runidbg_arm64_emu_tracer::AndroidEmulator;
use unicorn_engine::unicorn_const::Prot;

fn map_mem(emu: &mut AndroidEmulator, addr: u64, size: u64, perms: Prot) {
    emu.uc_mut().mem_map(addr, size, perms).expect("mem_map");
}

fn write_mem(emu: &mut AndroidEmulator, addr: u64, data: &[u8]) {
    emu.uc_mut().mem_write(addr, data).expect("mem_write");
}

fn read_mem(emu: &AndroidEmulator, addr: u64, len: usize) -> Vec<u8> {
    emu.uc().mem_read_as_vec(addr, len).expect("mem_read")
}

/// 构造一段极简 ARM64 SVC 辅助函数：`svc #0; ret`（8 字节）
fn map_svc_trampoline(emu: &mut AndroidEmulator, addr: u64) {
    let code: [u32; 2] = [
        0xD400_0001, // svc #0
        0xD65F_03C0, // ret
    ];
    let mut bytes = Vec::new();
    for insn in code {
        bytes.extend_from_slice(&insn.to_le_bytes());
    }
    map_mem(emu, addr, 0x1000, Prot::READ | Prot::EXEC);
    write_mem(emu, addr, &bytes);
}

fn invoke_svc(emu: &mut AndroidEmulator, svc_pc: u64, nr: u64, args: &[u64]) -> i64 {
    let mut padded = [0u64; 6];
    for (i, &v) in args.iter().take(6).enumerate() {
        padded[i] = v;
    }
    emu.uc_mut()
        .reg_write(unicorn_engine::RegisterARM64::X8, nr)
        .unwrap();
    emu.call_address(svc_pc, &padded).expect("call svc") as i64
}

#[test]
fn real_tcp_roundtrip_packet_capture_and_offline_guardrail() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local tcp");
    let server_addr = listener.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).expect("read from guest");
        assert_eq!(&buf[..n], b"HELLO_MODIFIED");
        stream.write_all(b"WORLD_OK").expect("write to guest");
    });

    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    let svc_pc = 0x4300_0000u64;
    let scratch = 0x4301_0000u64;
    map_svc_trampoline(&mut emu, svc_pc);
    map_mem(&mut emu, scratch, 0x2000, Prot::READ | Prot::WRITE);

    let sa = serialize_sockaddr(server_addr);
    write_mem(&mut emu, scratch, &sa);

    // 1. 默认 net.enabled == false 时，connect 必须被安全护栏拦截返回 -EACCES
    let fd = invoke_svc(&mut emu, svc_pc, SYS_SOCKET, &[AF_INET as u64, SOCK_STREAM as u64, 0]);
    assert!(fd >= 3, "socket fd should be >= 3, got {fd}");
    let blocked = invoke_svc(&mut emu, svc_pc, SYS_CONNECT, &[fd as u64, scratch, sa.len() as u64]);
    assert_eq!(blocked, EACCES, "net disabled should block connect with -EACCES");

    // 2. 开启真实联网 + 白名单 127.0.0.1 + 抓包 + onSend 改包拦截器
    {
        let net = &mut emu.vfs_mut().net;
        net.config.enabled = true;
        net.config.capture_packets = true;
        net.config.allow_hosts = vec!["127.0.0.1".to_string()];
        net.set_on_send(Some(Box::new(|_fd, _peer, data| {
            if data == b"HELLO_RAW" {
                Some(b"HELLO_MODIFIED".to_vec())
            } else {
                None
            }
        })));
    }

    let rc = invoke_svc(&mut emu, svc_pc, SYS_CONNECT, &[fd as u64, scratch, sa.len() as u64]);
    assert_eq!(rc, 0, "connect to allowed localhost should succeed");

    let send_buf = scratch + 0x100;
    let recv_buf = scratch + 0x200;
    write_mem(&mut emu, send_buf, b"HELLO_RAW");
    let sent = invoke_svc(&mut emu, svc_pc, SYS_SENDTO, &[fd as u64, send_buf, 9, 0, 0, 0]);
    assert_eq!(sent, 14, "onSend modified payload length should be 14");

    let recvd = invoke_svc(&mut emu, svc_pc, SYS_RECVFROM, &[fd as u64, recv_buf, 64, 0, 0, 0]);
    assert_eq!(recvd, 8);
    assert_eq!(&read_mem(&emu, recv_buf, 8), b"WORLD_OK");

    assert_eq!(invoke_svc(&mut emu, svc_pc, SYS_CLOSE, &[fd as u64]), 0);
    server_thread.join().expect("server thread join");

    let pkts = emu.uc().get_data().vfs.net.packets();
    assert_eq!(pkts.len(), 2);
    assert_eq!(pkts[0].dir, "send");
    assert_eq!(pkts[0].data, b"HELLO_MODIFIED");
    assert_eq!(pkts[1].dir, "recv");
    assert_eq!(pkts[1].data, b"WORLD_OK");
}

#[test]
fn real_udp_datagram_roundtrip() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind local udp");
    let server_addr = server.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, peer) = server.recv_from(&mut buf).expect("udp recv");
        assert_eq!(&buf[..n], b"UDP_PING");
        server.send_to(b"UDP_PONG", peer).expect("udp send");
    });

    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    emu.vfs_mut().net.config.enabled = true;
    emu.vfs_mut().net.config.allow_hosts = vec!["127.0.0.1".to_string()];

    let svc_pc = 0x4302_0000u64;
    let scratch = 0x4303_0000u64;
    map_svc_trampoline(&mut emu, svc_pc);
    map_mem(&mut emu, scratch, 0x2000, Prot::READ | Prot::WRITE);

    let sa = serialize_sockaddr(server_addr);
    write_mem(&mut emu, scratch, &sa);
    write_mem(&mut emu, scratch + 0x100, b"UDP_PING");

    let fd = invoke_svc(&mut emu, svc_pc, SYS_SOCKET, &[AF_INET as u64, SOCK_DGRAM as u64, 0]);
    assert!(fd >= 3);
    let sent = invoke_svc(
        &mut emu,
        svc_pc,
        SYS_SENDTO,
        &[fd as u64, scratch + 0x100, 8, 0, scratch, sa.len() as u64],
    );
    assert_eq!(sent, 8);

    let recvd = invoke_svc(
        &mut emu,
        svc_pc,
        SYS_RECVFROM,
        &[fd as u64, scratch + 0x200, 64, 0, 0, 0],
    );
    assert_eq!(recvd, 8);
    assert_eq!(&read_mem(&emu, scratch + 0x200, 8), b"UDP_PONG");
    assert_eq!(invoke_svc(&mut emu, svc_pc, SYS_CLOSE, &[fd as u64]), 0);
    server_thread.join().unwrap();
}

#[test]
fn epoll_eventfd_pipe_and_virtual_nic_ioctl() {
    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    let svc_pc = 0x4304_0000u64;
    let scratch = 0x4305_0000u64;
    map_svc_trampoline(&mut emu, svc_pc);
    map_mem(&mut emu, scratch, 0x2000, Prot::READ | Prot::WRITE);

    // 1. epoll_create1 + eventfd2 + epoll_ctl + write(eventfd) + epoll_pwait
    let epfd = invoke_svc(&mut emu, svc_pc, SYS_EPOLL_CREATE1, &[0]);
    let efd = invoke_svc(&mut emu, svc_pc, SYS_EVENTFD2, &[0, 0]);
    assert!(epfd >= 3 && efd >= 3);

    let mut ev = [0u8; 16];
    ev[0..4].copy_from_slice(&EPOLLIN.to_le_bytes());
    ev[8..16].copy_from_slice(&0xCAFE_1234u64.to_le_bytes());
    write_mem(&mut emu, scratch, &ev);
    assert_eq!(
        invoke_svc(&mut emu, svc_pc, SYS_EPOLL_CTL, &[epfd as u64, EPOLL_CTL_ADD as u64, efd as u64, scratch]),
        0
    );

    assert_eq!(
        invoke_svc(&mut emu, svc_pc, SYS_EPOLL_PWAIT, &[epfd as u64, scratch + 0x100, 4, 0, 0, 0]),
        0
    );

    write_mem(&mut emu, scratch + 0x200, &1u64.to_le_bytes());
    assert_eq!(invoke_svc(&mut emu, svc_pc, SYS_WRITE, &[efd as u64, scratch + 0x200, 8]), 8);
    let nready = invoke_svc(&mut emu, svc_pc, SYS_EPOLL_PWAIT, &[epfd as u64, scratch + 0x100, 4, 50, 0, 0]);
    assert_eq!(nready, 1);
    let out_ev = read_mem(&emu, scratch + 0x100, 16);
    assert_eq!(u64::from_le_bytes(out_ev[8..16].try_into().unwrap()), 0xCAFE_1234);

    // 2. pipe2 读写
    assert_eq!(invoke_svc(&mut emu, svc_pc, SYS_PIPE2, &[scratch + 0x300, 0]), 0);
    let pair = read_mem(&emu, scratch + 0x300, 8);
    let rfd = i32::from_le_bytes(pair[0..4].try_into().unwrap());
    let wfd = i32::from_le_bytes(pair[4..8].try_into().unwrap());
    write_mem(&mut emu, scratch + 0x320, b"WAKE");
    assert_eq!(invoke_svc(&mut emu, svc_pc, SYS_WRITE, &[wfd as u64, scratch + 0x320, 4]), 4);
    assert_eq!(invoke_svc(&mut emu, svc_pc, SYS_READ, &[rfd as u64, scratch + 0x340, 16]), 4);
    assert_eq!(&read_mem(&emu, scratch + 0x340, 4), b"WAKE");

    // 3. 虚拟网卡 ioctl(SIOCGIFADDR / SIOCGIFHWADDR) 与 /proc/net/route
    let ifr = scratch + 0x400;
    let mut ifreq = [0u8; 40];
    ifreq[..5].copy_from_slice(b"wlan0");
    write_mem(&mut emu, ifr, &ifreq);
    assert_eq!(invoke_svc(&mut emu, svc_pc, SYS_IOCTL, &[3, SIOCGIFADDR, ifr]), 0);
    assert_eq!(read_mem(&emu, ifr + 20, 4), vec![192, 168, 1, 108]);

    assert_eq!(invoke_svc(&mut emu, svc_pc, SYS_IOCTL, &[3, SIOCGIFHWADDR, ifr]), 0);
    assert_eq!(read_mem(&emu, ifr + 18, 6), vec![0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);

    let route_fd = {
        let d = emu.uc_mut().get_data_mut();
        d.vfs.open("/proc/net/route", &d.mem) as i32
    };
    let route_txt = String::from_utf8(emu.vfs_mut().read(route_fd, 512).unwrap()).unwrap();
    assert!(route_txt.contains("wlan0"));
}

#[cfg(feature = "js")]
#[test]
fn js_net_api_nic_and_config() {
    use std::path::Path;
    use runidbg_arm64_emu_tracer::script::JsSession;
    let script = r#"
        const emu = Emu.create({
            net: {
                enabled: true,
                capture: true,
                allowHosts: ["127.0.0.1"],
                nic: { name: "wlan0", ipv4: "10.0.0.42", mac: "aa:bb:cc:dd:ee:ff" },
            },
        });
        rpc.exports = {
            info() {
                return { nic: emu.net.nic(), pkts: emu.net.packets().length };
            },
        };
    "#;
    let session = JsSession::new(&[], Path::new("."), true).expect("JsSession");
    session.eval_source(script).expect("eval net js");
    let raw = session.call_rpc_json("info", "[]").expect("call info");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["nic"]["ipv4"], "10.0.0.42");
    assert_eq!(v["nic"]["mac"], "aa:bb:cc:dd:ee:ff");
    assert_eq!(v["pkts"], 0);
}
