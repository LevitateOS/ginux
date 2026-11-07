//! Configured TCP ownership. Only pre-granted numeric destinations can acquire
//! a supervisor socket; the workload never receives its private descriptor.
use crate::supervisor::{syscall2, UserRegs, SYS_KILL};
use crate::tracee_io::{copy_memory, write_stat, IoVectors, Stat};
use ginux_devices::{BoundedTcp, LinuxTcpBackend, NetworkError, TcpEndpoint, TcpFamily};
use ginux_instance::{InstanceConfig, NetworkBackend};

pub const FD_BASE: u32 = 0x6000_0000;
pub const FDS: usize = 16;
const IO: usize = 4096;
#[derive(Clone, Copy)]
struct Socket {
    flags: u32,
    connecting: bool,
    connected: bool,
    // SO_ERROR is consumed by the guest; failed connection state is not.
    failure: i32,
    error: i32,
    nodelay: bool,
    read_timeout: u64,
    write_timeout: u64,
}
struct Receive {
    bytes: [u8; IO],
    at: usize,
    end: usize,
}
impl Receive {
    const fn new() -> Self {
        Self {
            bytes: [0; IO],
            at: 0,
            end: 0,
        }
    }
}
pub enum Result {
    Ready(i64),
    Blocked,
}
pub struct LaunchNetwork {
    network: Option<BoundedTcp<LinuxTcpBackend, 8, FDS>>,
    sockets: [Option<Socket>; FDS],
    received: [Receive; FDS],
}
impl LaunchNetwork {
    pub fn prepare(config: &InstanceConfig) -> core::result::Result<Self, &'static [u8]> {
        let mut network = None;
        if config.network_backend == NetworkBackend::Mediated {
            let mut endpoints = [TcpEndpoint {
                family: TcpFamily::Ipv4,
                address: [0; 16],
                port: 1,
            }; 8];
            let texts = config.network_endpoints.as_slice();
            for (index, text) in texts.iter().enumerate() {
                let address = ginux_instance::parse_network_endpoint(text.as_bytes())
                    .map_err(|_| b"invalid numeric network endpoint".as_slice())?;
                endpoints[index] = match address {
                    core::net::SocketAddr::V4(v4) => TcpEndpoint::ipv4(v4.ip().octets(), v4.port()),
                    core::net::SocketAddr::V6(v6) => TcpEndpoint::ipv6(v6.ip().octets(), v6.port()),
                }
                .map_err(|_| b"invalid TCP endpoint".as_slice())?;
            }
            network = Some(
                BoundedTcp::new(
                    LinuxTcpBackend,
                    &endpoints[..texts.len()],
                    config.network_max_connections as usize,
                    config.network_max_bytes,
                )
                .map_err(|_| b"mediated TCP requires endpoints and explicit budgets".as_slice())?,
            );
        }
        Ok(Self {
            network,
            sockets: [None; FDS],
            received: [const { Receive::new() }; FDS],
        })
    }
    pub fn owns(handle: u32) -> bool {
        (FD_BASE..FD_BASE + FDS as u32).contains(&handle)
    }
    pub fn timeout(&self, handle: u32, syscall: u64) -> u64 {
        self.sockets[(handle - FD_BASE) as usize]
            .map(|s| {
                if matches!(syscall, 0 | 19 | 45) {
                    s.read_timeout
                } else {
                    s.write_timeout
                }
            })
            .unwrap_or(0)
    }
    pub fn readiness(&mut self, handle: u32) -> Option<u16> {
        if !Self::owns(handle) {
            return None;
        }
        let slot = (handle - FD_BASE) as usize;
        let state = self.sockets[slot]?;
        if !state.connecting && !state.connected && state.failure == 0 {
            return Some(4 | 16); // An unconnected stream cannot wait for data.
        }
        // Completion consumes the private SO_ERROR only once and retains it.
        let _ = self.complete(slot);
        let pending = &self.received[slot];
        Some(match self.network.as_mut()?.readiness(slot as u32) {
            Ok(r) => {
                u16::from(r.readable || pending.at < pending.end)
                    | (u16::from(r.writable) * 4)
                    | (u16::from(r.error || self.sockets[slot]?.error != 0) * 8)
                    | (u16::from(r.hangup) * 16)
            }
            Err(_) => 8,
        })
    }
    fn complete(&mut self, slot: usize) -> core::result::Result<bool, i64> {
        let state = self.sockets[slot].ok_or(-9)?;
        if state.failure != 0 {
            return Err(-(state.failure as i64));
        }
        if !state.connecting {
            return Ok(state.connected);
        }
        let net = self.network.as_mut().ok_or(-9)?;
        let ready = net.readiness(slot as u32).map_err(errno)?;
        if !ready.writable && !ready.error && !ready.hangup {
            return Ok(false);
        }
        let error = net.socket_error(slot as u32).map_err(errno)?;
        let state = self.sockets[slot].as_mut().unwrap();
        state.connecting = false;
        if error != 0 {
            state.failure = error;
            state.error = error;
            return Err(-(error as i64));
        }
        state.connected = true;
        Ok(true)
    }
    pub fn claim(&mut self, pid: usize, r: &UserRegs) -> Option<Result> {
        if r.orig_rax == 41 {
            return Some(Result::Ready(self.open(r).unwrap_or_else(|e| e)));
        }
        if !Self::owns(r.rdi as u32) {
            return None;
        }
        let slot = (r.rdi as u32 - FD_BASE) as usize;
        let state = self.sockets[slot];
        let outcome = self.operation(pid, slot, r);
        Some(match outcome {
            Err(-11)
                if state.is_some_and(|s| s.flags & 0o4000 == 0)
                    && matches!(r.orig_rax, 0 | 1 | 19 | 20 | 42 | 44 | 45)
                    && !(matches!(r.orig_rax, 44 | 45) && r.r10 & 0x40 != 0) =>
            {
                Result::Blocked
            }
            value => Result::Ready(value.unwrap_or_else(|e| e)),
        })
    }
    fn open(&mut self, r: &UserRegs) -> core::result::Result<i64, i64> {
        let family = match r.rdi {
            2 => TcpFamily::Ipv4,
            10 => TcpFamily::Ipv6,
            _ => return Err(-97),
        };
        if r.rsi & !(0o4000 | 0o2000000 | 1) != 0 || r.rsi & 15 != 1 || !matches!(r.rdx, 0 | 6) {
            return Err(-93);
        }
        let slot = self
            .network
            .as_mut()
            .ok_or(-13)?
            .open(family)
            .map_err(errno)?;
        self.sockets[slot as usize] = Some(Socket {
            flags: 2 | r.rsi as u32 & 0o4000,
            connected: false,
            connecting: false,
            failure: 0,
            error: 0,
            nodelay: false,
            read_timeout: 0,
            write_timeout: 0,
        });
        self.received[slot as usize] = Receive::new();
        Ok((FD_BASE + slot) as i64)
    }
    fn operation(
        &mut self,
        pid: usize,
        slot: usize,
        r: &UserRegs,
    ) -> core::result::Result<i64, i64> {
        let state = self.sockets[slot].ok_or(-9)?;
        let handle = slot as u32;
        match r.orig_rax {
            3 => {
                self.network
                    .as_mut()
                    .ok_or(-9)?
                    .close(handle)
                    .map_err(errno)?;
                self.received[slot] = Receive::new();
                self.sockets[slot] = None;
                Ok(0)
            }
            42 => {
                if state.connected {
                    return Err(-106);
                }
                if state.failure != 0 {
                    return Err(-(state.failure as i64));
                }
                if !state.connecting {
                    let endpoint = read_endpoint(pid, r.rsi, r.rdx)?;
                    let net = self.network.as_mut().ok_or(-9)?;
                    net.connect(handle, endpoint).map_err(errno)?;
                    self.sockets[slot].as_mut().unwrap().connecting = true;
                    if state.nodelay {
                        net.set_nodelay(handle, true).map_err(errno)?;
                    }
                    if state.flags & 0o4000 != 0 {
                        return Err(-115);
                    }
                } else if state.flags & 0o4000 != 0 {
                    if self.complete(slot)? {
                        return Err(-106);
                    }
                    return Err(-114);
                }
                if self.complete(slot)? {
                    Ok(0)
                } else {
                    Err(-11)
                }
            }
            0 | 1 | 19 | 20 | 44 | 45 => {
                if matches!(r.orig_rax, 44 | 45)
                    && (r.r10 & !(0x4000 | 0x40) != 0 || r.r8 != 0 || r.r9 != 0)
                {
                    return Err(-95);
                }
                let write = matches!(r.orig_rax, 1 | 20 | 44);
                let vectors = if matches!(r.orig_rax, 19 | 20) {
                    IoVectors::read(pid, r.rsi, r.rdx)?
                } else {
                    IoVectors::single(r.rsi, r.rdx)
                };
                let length = vectors.length.min(IO);
                if length == 0 {
                    return Ok(0);
                }
                // Preserve already received bytes even after the shared transport
                // budget is exhausted. Only backend transfers spend that budget.
                if write {
                    if !self.complete(slot)? {
                        return Err(if state.connecting { -11 } else { -107 });
                    }
                    let mut buffer = [0u8; IO];
                    let copied = vectors.copy(pid, &mut buffer[..length], false)?;
                    let result = self
                        .network
                        .as_mut()
                        .ok_or(-9)?
                        .write(handle, &buffer[..copied])
                        .map_err(errno);
                    if result == Err(-32) && !(r.orig_rax == 44 && r.r10 & 0x4000 != 0) {
                        // The backend suppresses host SIGPIPE; signal its guest caller.
                        let _ = unsafe { syscall2(SYS_KILL, pid, 13) };
                    }
                    return result.map(|n| n as i64);
                }
                if self.received[slot].at == self.received[slot].end {
                    if !self.complete(slot)? {
                        return Err(if state.connecting { -11 } else { -107 });
                    }
                    let pending = &mut self.received[slot];
                    let n = self
                        .network
                        .as_mut()
                        .ok_or(-9)?
                        .read(handle, &mut pending.bytes[..length])
                        .map_err(errno)?;
                    pending.at = 0;
                    pending.end = n;
                }
                let pending = &mut self.received[slot];
                let end = pending.end.min(pending.at + length);
                // No copyin/preflight of a receive destination. Advance only by
                // the copied prefix; a failed copy leaves the bytes for aliases.
                let copied = vectors.copy(pid, &mut pending.bytes[pending.at..end], true)?;
                pending.at += copied;
                Ok(copied as i64)
            }
            48 => {
                if r.rsi > 2 {
                    return Err(-22);
                }
                self.network
                    .as_mut()
                    .ok_or(-9)?
                    .shutdown(handle, r.rsi != 1, r.rsi != 0)
                    .map_err(errno)?;
                Ok(0)
            }
            51 | 52 => {
                let endpoint = self
                    .network
                    .as_mut()
                    .ok_or(-9)?
                    .endpoint(handle, r.orig_rax == 52)
                    .map_err(errno)?;
                write_endpoint(pid, r.rsi, r.rdx, endpoint)
            }
            54 => {
                if r.rdi > u32::MAX as u64 {
                    return Err(-9);
                }
                if r.rsi == 6 && r.rdx == 1 && r.r8 == 4 {
                    let mut value = [0u8; 4];
                    if copy_memory(pid, r.r10, &mut value, false)? != 4 {
                        return Err(-14);
                    }
                    let enabled = i32::from_ne_bytes(value) != 0;
                    if state.connecting || state.connected {
                        self.network
                            .as_mut()
                            .ok_or(-9)?
                            .set_nodelay(handle, enabled)
                            .map_err(errno)?;
                    }
                    self.sockets[slot].as_mut().unwrap().nodelay = enabled;
                    return Ok(0);
                }
                if r.rsi != 1 || !matches!(r.rdx, 20 | 21) || r.r8 != 16 {
                    return Err(-92);
                }
                let mut value = [0u8; 16];
                if copy_memory(pid, r.r10, &mut value, false)? != 16 {
                    return Err(-14);
                }
                let sec = i64::from_ne_bytes(value[..8].try_into().unwrap());
                let usec = i64::from_ne_bytes(value[8..].try_into().unwrap());
                if sec < 0 || !(0..1000000).contains(&usec) {
                    return Err(-33);
                }
                let timeout = (sec as u64)
                    .checked_mul(1_000_000_000)
                    .and_then(|n| n.checked_add(usec as u64 * 1000))
                    .ok_or(-22)?;
                let socket = self.sockets[slot].as_mut().unwrap();
                if r.rdx == 20 {
                    socket.read_timeout = timeout;
                } else {
                    socket.write_timeout = timeout;
                }
                Ok(0)
            }
            55 => {
                if r.rsi != 1 || !matches!(r.rdx, 3 | 4) {
                    return Err(-92);
                }
                if r.rdx == 4 {
                    let _ = self.complete(slot);
                    if self.sockets[slot].unwrap().connected {
                        let error = self
                            .network
                            .as_mut()
                            .ok_or(-9)?
                            .socket_error(handle)
                            .map_err(errno)?;
                        if error != 0 {
                            self.sockets[slot].as_mut().unwrap().error = error;
                        }
                    }
                }
                let value = if r.rdx == 3 {
                    1
                } else {
                    self.sockets[slot].unwrap().error
                };
                let mut length = [0u8; 4];
                if copy_memory(pid, r.r8, &mut length, false)? != 4 {
                    return Err(-14);
                }
                let count = (u32::from_ne_bytes(length) as usize).min(4);
                let mut bytes = value.to_ne_bytes();
                if count != 0 && copy_memory(pid, r.r10, &mut bytes[..count], true)? != count as i64
                {
                    return Err(-14);
                }
                length.copy_from_slice(&(count as u32).to_ne_bytes());
                if copy_memory(pid, r.r8, &mut length, true)? != 4 {
                    return Err(-14);
                }
                if r.rdx == 4 {
                    self.sockets[slot].as_mut().unwrap().error = 0;
                }
                Ok(0)
            }
            72 => match r.rsi {
                3 => Ok(state.flags as i64),
                4 if r.rdx & !(2 | 0o4000) == 0 => {
                    self.sockets[slot].as_mut().unwrap().flags = r.rdx as u32;
                    Ok(0)
                }
                _ => Err(-95),
            },
            16 if r.rsi == 0x5421 => {
                let mut bytes = [0; 4];
                if copy_memory(pid, r.rdx, &mut bytes, false)? != 4 {
                    return Err(-14);
                }
                self.sockets[slot].as_mut().unwrap().flags = 2
                    | if i32::from_ne_bytes(bytes) != 0 {
                        0o4000
                    } else {
                        0
                    };
                Ok(0)
            }
            5 => write_stat(
                pid,
                r.rsi,
                Stat {
                    links: 1,
                    accessed: ginux_vfs::Timestamp::ZERO,
                    modified: ginux_vfs::Timestamp::ZERO,
                    inode: 0x60000000 + slot as u64,
                    mode: 0o140600,
                    size: 0,
                    device_major: 0,
                    device_minor: 0,
                },
                false,
            ),
            8 => Err(-29),
            _ => Err(-95),
        }
    }
}
fn read_endpoint(pid: usize, address: u64, length: u64) -> core::result::Result<TcpEndpoint, i64> {
    if !(2..=128).contains(&length) {
        return Err(-22);
    }
    let mut bytes = [0u8; 28];
    let n = (length as usize).min(bytes.len());
    if copy_memory(pid, address, &mut bytes[..n], false)? != n as i64 {
        return Err(-14);
    }
    let family = u16::from_ne_bytes(bytes[..2].try_into().unwrap());
    let port = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
    match family {
        2 if length >= 16 => {
            TcpEndpoint::ipv4(bytes[4..8].try_into().unwrap(), port).map_err(errno)
        }
        10 if length >= 28 && bytes[4..8] == [0; 4] && bytes[24..28] == [0; 4] => {
            TcpEndpoint::ipv6(bytes[8..24].try_into().unwrap(), port).map_err(errno)
        }
        _ => Err(-97),
    }
}
fn write_endpoint(
    pid: usize,
    address: u64,
    length_address: u64,
    endpoint: TcpEndpoint,
) -> core::result::Result<i64, i64> {
    let mut bytes = [0u8; 28];
    let length = if endpoint.family == TcpFamily::Ipv4 {
        16
    } else {
        28
    };
    bytes[..2].copy_from_slice(&(if length == 16 { 2u16 } else { 10 }).to_ne_bytes());
    bytes[2..4].copy_from_slice(&endpoint.port.to_be_bytes());
    if length == 16 {
        bytes[4..8].copy_from_slice(&endpoint.address[..4]);
    } else {
        bytes[8..24].copy_from_slice(&endpoint.address);
    }
    let mut supplied = [0u8; 4];
    if copy_memory(pid, length_address, &mut supplied, false)? != 4 {
        return Err(-14);
    }
    let n = (u32::from_ne_bytes(supplied) as usize).min(length);
    if n != 0 && copy_memory(pid, address, &mut bytes[..n], true)? != n as i64 {
        return Err(-14);
    }
    supplied.copy_from_slice(&(length as u32).to_ne_bytes());
    if copy_memory(pid, length_address, &mut supplied, true)? != 4 {
        return Err(-14);
    }
    Ok(0)
}
fn errno(error: NetworkError) -> i64 {
    match error {
        NetworkError::PermissionDenied => -13,
        NetworkError::DescriptorLimit => -24,
        NetworkError::InvalidDescriptor | NetworkError::Closed => -9,
        NetworkError::AlreadyConnected => -106,
        NetworkError::NotConnected => -107,
        NetworkError::WouldBlock => -11,
        NetworkError::ByteLimit => -122,
        NetworkError::Backend(n) => -(n as i64),
        NetworkError::InvalidEndpoint => -22,
    }
}
