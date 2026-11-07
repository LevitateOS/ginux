#![no_std]

pub const MAX_DEVICE_NAME: usize = 16;
pub const MAX_FRAME_SIZE: usize = 2048;
pub const IOCTL_CONSOLE_GET_SIZE: u64 = 0x5413;
pub const IOCTL_BLOCK_GET_SIZE: u64 = 0x8008_1272;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceError {
    InvalidName,
    UnknownDevice,
    NotAssigned,
    AssignmentConflict,
    RegistryFull,
    DescriptorLimit,
    InvalidDescriptor,
    PermissionDenied,
    InvalidPayload,
    UnknownIoctl,
    DirectMappingDenied,
    OutOfRange,
    ReadOnly,
    Backend,
    Closed,
    FrameTooLarge,
    QueueFull,
    QueueEmpty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceKind {
    Console,
    Null,
    Zero,
    Random,
    Block,
    Network,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceName {
    bytes: [u8; MAX_DEVICE_NAME],
    len: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceView {
    pub name: DeviceName,
    pub kind: DeviceKind,
    pub major: u32,
    pub minor: u32,
}

impl DeviceName {
    pub fn new(value: &[u8]) -> Result<Self, DeviceError> {
        if value.is_empty()
            || value.len() > MAX_DEVICE_NAME
            || !value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(DeviceError::InvalidName);
        }
        let mut name = Self {
            bytes: [0; MAX_DEVICE_NAME],
            len: value.len() as u8,
        };
        name.bytes[..value.len()].copy_from_slice(value);
        Ok(name)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Clone, Copy)]
struct Assignment {
    active: bool,
    instance: u64,
    backend: u64,
    name: DeviceName,
    kind: DeviceKind,
}

impl Assignment {
    const fn empty() -> Self {
        Self {
            active: false,
            instance: 0,
            backend: 0,
            name: DeviceName {
                bytes: [0; MAX_DEVICE_NAME],
                len: 0,
            },
            kind: DeviceKind::Null,
        }
    }
}

#[derive(Clone, Copy)]
struct Descriptor {
    open: bool,
    instance: u64,
    assignment: usize,
}

impl Descriptor {
    const fn empty() -> Self {
        Self {
            open: false,
            instance: 0,
            assignment: 0,
        }
    }
}

pub struct DeviceRegistry<const DEVICES: usize, const FDS: usize> {
    assignments: [Assignment; DEVICES],
    descriptors: [Descriptor; FDS],
    random_state: u64,
}

impl<const DEVICES: usize, const FDS: usize> Default for DeviceRegistry<DEVICES, FDS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEVICES: usize, const FDS: usize> DeviceRegistry<DEVICES, FDS> {
    pub const fn new() -> Self {
        Self {
            assignments: [Assignment::empty(); DEVICES],
            descriptors: [Descriptor::empty(); FDS],
            random_state: 0x6a09_e667_f3bc_c909,
        }
    }

    pub fn assign(
        &mut self,
        instance: u64,
        backend: u64,
        name: DeviceName,
        kind: DeviceKind,
    ) -> Result<(), DeviceError> {
        if self.assignments.iter().any(|entry| {
            entry.active
                && (entry.backend == backend
                    || (entry.instance == instance && entry.name.as_bytes() == name.as_bytes()))
        }) {
            return Err(DeviceError::AssignmentConflict);
        }
        let slot = self
            .assignments
            .iter_mut()
            .find(|entry| !entry.active)
            .ok_or(DeviceError::RegistryFull)?;
        *slot = Assignment {
            active: true,
            instance,
            backend,
            name,
            kind,
        };
        Ok(())
    }

    pub fn visible(&self, instance: u64, output: &mut [DeviceName]) -> usize {
        let mut count = 0;
        for entry in self
            .assignments
            .iter()
            .filter(|entry| entry.active && entry.instance == instance)
        {
            if count == output.len() {
                break;
            }
            output[count] = entry.name;
            count += 1;
        }
        count
    }

    pub fn views(&self, instance: u64, output: &mut [DeviceView]) -> usize {
        let mut count = 0usize;
        for (index, entry) in self
            .assignments
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.active && entry.instance == instance)
        {
            if count == output.len() {
                break;
            }
            let (major, minor) = match entry.kind {
                DeviceKind::Console => (5, 1),
                DeviceKind::Null => (1, 3),
                DeviceKind::Zero => (1, 5),
                DeviceKind::Random => (1, 8),
                DeviceKind::Block => (254, index as u32),
                DeviceKind::Network => (0, index as u32 + 1),
            };
            output[count] = DeviceView {
                name: entry.name,
                kind: entry.kind,
                major,
                minor,
            };
            count += 1;
        }
        count
    }

    pub fn open(&mut self, instance: u64, name: &[u8]) -> Result<u32, DeviceError> {
        let assignment = self
            .assignments
            .iter()
            .position(|entry| {
                entry.active && entry.instance == instance && entry.name.as_bytes() == name
            })
            .ok_or(DeviceError::NotAssigned)?;
        let descriptor = self
            .descriptors
            .iter_mut()
            .position(|entry| !entry.open)
            .ok_or(DeviceError::DescriptorLimit)?;
        self.descriptors[descriptor] = Descriptor {
            open: true,
            instance,
            assignment,
        };
        Ok(0x4000_0000 | descriptor as u32)
    }

    fn descriptor(&self, instance: u64, fd: u32) -> Result<&Assignment, DeviceError> {
        if fd & 0x4000_0000 == 0 {
            return Err(DeviceError::InvalidDescriptor);
        }
        let index = (fd & 0x3fff_ffff) as usize;
        let descriptor = self
            .descriptors
            .get(index)
            .filter(|entry| entry.open && entry.instance == instance)
            .ok_or(DeviceError::InvalidDescriptor)?;
        self.assignments
            .get(descriptor.assignment)
            .filter(|entry| entry.active && entry.instance == instance)
            .ok_or(DeviceError::InvalidDescriptor)
    }

    pub fn read(
        &mut self,
        instance: u64,
        fd: u32,
        output: &mut [u8],
    ) -> Result<usize, DeviceError> {
        let kind = self.descriptor(instance, fd)?.kind;
        match kind {
            DeviceKind::Null | DeviceKind::Console => Ok(0),
            DeviceKind::Zero => {
                output.fill(0);
                Ok(output.len())
            }
            DeviceKind::Random => {
                for byte in output.iter_mut() {
                    self.random_state ^= self.random_state << 13;
                    self.random_state ^= self.random_state >> 7;
                    self.random_state ^= self.random_state << 17;
                    *byte = self.random_state as u8;
                }
                Ok(output.len())
            }
            DeviceKind::Block | DeviceKind::Network => Err(DeviceError::PermissionDenied),
        }
    }

    pub fn write(&self, instance: u64, fd: u32, input: &[u8]) -> Result<usize, DeviceError> {
        match self.descriptor(instance, fd)?.kind {
            DeviceKind::Null | DeviceKind::Console => Ok(input.len()),
            DeviceKind::Zero | DeviceKind::Random | DeviceKind::Block | DeviceKind::Network => {
                Err(DeviceError::PermissionDenied)
            }
        }
    }

    pub fn ioctl(
        &self,
        instance: u64,
        fd: u32,
        request: u64,
        payload: &mut [u8],
    ) -> Result<(), DeviceError> {
        let kind = self.descriptor(instance, fd)?.kind;
        match (kind, request) {
            (DeviceKind::Console, IOCTL_CONSOLE_GET_SIZE) if payload.len() == 8 => {
                payload.copy_from_slice(&[24, 0, 80, 0, 0, 0, 0, 0]);
                Ok(())
            }
            (DeviceKind::Console, IOCTL_CONSOLE_GET_SIZE) => Err(DeviceError::InvalidPayload),
            _ => Err(DeviceError::UnknownIoctl),
        }
    }

    pub fn map(&self, instance: u64, fd: u32) -> Result<(), DeviceError> {
        self.descriptor(instance, fd)?;
        Err(DeviceError::DirectMappingDenied)
    }

    pub fn close(&mut self, instance: u64, fd: u32) -> Result<(), DeviceError> {
        self.descriptor(instance, fd)?;
        let index = (fd & 0x3fff_ffff) as usize;
        self.descriptors[index] = Descriptor::empty();
        Ok(())
    }

    pub fn revoke(&mut self, instance: u64) {
        for descriptor in &mut self.descriptors {
            if descriptor.open && descriptor.instance == instance {
                *descriptor = Descriptor::empty();
            }
        }
        for assignment in &mut self.assignments {
            if assignment.active && assignment.instance == instance {
                *assignment = Assignment::empty();
            }
        }
    }
}

pub trait BlockBackend {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), DeviceError>;
    fn write_at(&mut self, offset: u64, input: &[u8]) -> Result<(), DeviceError>;
    fn flush(&mut self) -> Result<(), DeviceError>;
    fn close(&mut self) -> Result<(), DeviceError>;
}

pub struct Partition<B> {
    backend: B,
    start: u64,
    len: u64,
    read_only: bool,
    closed: bool,
}

impl<B: BlockBackend> Partition<B> {
    pub fn new(backend: B, start: u64, len: u64, read_only: bool) -> Result<Self, DeviceError> {
        let end = start.checked_add(len).ok_or(DeviceError::OutOfRange)?;
        if len == 0 || end > backend.len() {
            return Err(DeviceError::OutOfRange);
        }
        Ok(Self {
            backend,
            start,
            len,
            read_only,
            closed: false,
        })
    }

    fn range(&self, offset: u64, size: usize) -> Result<u64, DeviceError> {
        if self.closed {
            return Err(DeviceError::Closed);
        }
        let end = offset
            .checked_add(size as u64)
            .ok_or(DeviceError::OutOfRange)?;
        if end > self.len {
            return Err(DeviceError::OutOfRange);
        }
        self.start
            .checked_add(offset)
            .ok_or(DeviceError::OutOfRange)
    }

    pub fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), DeviceError> {
        let absolute = self.range(offset, output.len())?;
        self.backend.read_at(absolute, output)
    }

    pub fn write_at(&mut self, offset: u64, input: &[u8]) -> Result<(), DeviceError> {
        if self.read_only {
            return Err(DeviceError::ReadOnly);
        }
        let absolute = self.range(offset, input.len())?;
        self.backend.write_at(absolute, input)
    }

    pub fn size(&self) -> u64 {
        self.len
    }

    pub fn flush(&mut self) -> Result<(), DeviceError> {
        if self.closed {
            return Err(DeviceError::Closed);
        }
        self.backend.flush()
    }

    pub fn close(&mut self) -> Result<(), DeviceError> {
        if self.closed {
            return Err(DeviceError::Closed);
        }
        self.backend.flush()?;
        self.backend.close()?;
        self.closed = true;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Frame {
    len: usize,
    bytes: [u8; MAX_FRAME_SIZE],
}

impl Frame {
    const fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; MAX_FRAME_SIZE],
        }
    }
}

pub struct IsolatedNetwork<const FRAMES: usize> {
    queue: [Frame; FRAMES],
    head: usize,
    len: usize,
    closed: bool,
}

impl<const FRAMES: usize> Default for IsolatedNetwork<FRAMES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const FRAMES: usize> IsolatedNetwork<FRAMES> {
    pub const fn new() -> Self {
        Self {
            queue: [Frame::empty(); FRAMES],
            head: 0,
            len: 0,
            closed: false,
        }
    }

    pub fn send(&mut self, frame: &[u8]) -> Result<(), DeviceError> {
        if self.closed {
            return Err(DeviceError::Closed);
        }
        if frame.is_empty() || frame.len() > MAX_FRAME_SIZE {
            return Err(DeviceError::FrameTooLarge);
        }
        if self.len == FRAMES {
            return Err(DeviceError::QueueFull);
        }
        let index = (self.head + self.len) % FRAMES;
        self.queue[index].bytes[..frame.len()].copy_from_slice(frame);
        self.queue[index].len = frame.len();
        self.len += 1;
        Ok(())
    }

    pub fn receive(&mut self, output: &mut [u8]) -> Result<usize, DeviceError> {
        if self.closed {
            return Err(DeviceError::Closed);
        }
        if self.len == 0 {
            return Err(DeviceError::QueueEmpty);
        }
        let frame = &self.queue[self.head];
        if output.len() < frame.len {
            return Err(DeviceError::InvalidPayload);
        }
        output[..frame.len].copy_from_slice(&frame.bytes[..frame.len]);
        let size = frame.len;
        self.queue[self.head] = Frame::empty();
        self.head = (self.head + 1) % FRAMES;
        self.len -= 1;
        Ok(size)
    }

    pub fn control(&self, _request: u64) -> Result<(), DeviceError> {
        Err(DeviceError::UnknownIoctl)
    }

    pub fn close(&mut self) {
        self.queue.fill(Frame::empty());
        self.head = 0;
        self.len = 0;
        self.closed = true;
    }
}

/// A numeric TCP destination granted before a instance starts. Hostname resolution
/// belongs to the caller; connecting never expands this set or performs DNS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpEndpoint {
    pub family: TcpFamily,
    pub address: [u8; 16],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpFamily {
    Ipv4,
    Ipv6,
}

impl TcpEndpoint {
    pub fn ipv4(address: [u8; 4], port: u16) -> Result<Self, NetworkError> {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&address);
        let endpoint = Self {
            family: TcpFamily::Ipv4,
            address: bytes,
            port,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn ipv6(address: [u8; 16], port: u16) -> Result<Self, NetworkError> {
        let endpoint = Self {
            family: TcpFamily::Ipv6,
            address,
            port,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    fn validate(&self) -> Result<(), NetworkError> {
        if self.port == 0
            || (self.family == TcpFamily::Ipv4 && self.address[4..].iter().any(|byte| *byte != 0))
        {
            return Err(NetworkError::InvalidEndpoint);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkError {
    InvalidEndpoint,
    PermissionDenied,
    DescriptorLimit,
    InvalidDescriptor,
    AlreadyConnected,
    NotConnected,
    WouldBlock,
    ByteLimit,
    Closed,
    /// The backend preserves an operating-system error without granting access
    /// to any underlying descriptor or address not present in the policy.
    Backend(i32),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpReadiness {
    pub readable: bool,
    pub writable: bool,
    pub hangup: bool,
    pub error: bool,
}

/// Nonblocking TCP supplied by the supervisor. A successful connect may still
/// be in progress; readiness and socket_error report its eventual outcome.
/// Every handle stays private to this owner. close must release it exactly once,
/// including when the connection is still in progress or already shut down.
pub trait TcpBackend {
    type Handle: Copy;
    fn connect(&mut self, endpoint: TcpEndpoint) -> Result<Self::Handle, NetworkError>;
    fn read(&mut self, handle: Self::Handle, output: &mut [u8]) -> Result<usize, NetworkError>;
    fn write(&mut self, handle: Self::Handle, input: &[u8]) -> Result<usize, NetworkError>;
    fn readiness(&mut self, handle: Self::Handle) -> Result<TcpReadiness, NetworkError>;
    fn socket_error(&mut self, handle: Self::Handle) -> Result<i32, NetworkError>;
    fn endpoint(&mut self, handle: Self::Handle, peer: bool) -> Result<TcpEndpoint, NetworkError>;
    fn set_nodelay(&mut self, handle: Self::Handle, enabled: bool) -> Result<(), NetworkError>;
    fn shutdown(
        &mut self,
        handle: Self::Handle,
        read: bool,
        write: bool,
    ) -> Result<(), NetworkError>;
    fn close(&mut self, handle: Self::Handle);
}

#[derive(Clone, Copy)]
struct TcpSocket<H: Copy> {
    family: TcpFamily,
    handle: Option<H>,
}

/// Supervisor-owned TCP sockets with an immutable endpoint set, bounded slots,
/// and one cumulative sent/received byte budget. Public descriptor aliases are
/// counted by the caller and share a slot until their final close.
pub struct BoundedTcp<B: TcpBackend, const ENDPOINTS: usize, const SOCKETS: usize> {
    backend: B,
    endpoints: [Option<TcpEndpoint>; ENDPOINTS],
    sockets: [Option<TcpSocket<B::Handle>>; SOCKETS],
    socket_limit: usize,
    remaining_bytes: u64,
    revoked: bool,
}

impl<B: TcpBackend, const ENDPOINTS: usize, const SOCKETS: usize>
    BoundedTcp<B, ENDPOINTS, SOCKETS>
{
    pub fn new(
        backend: B,
        endpoints: &[TcpEndpoint],
        socket_limit: usize,
        byte_limit: u64,
    ) -> Result<Self, NetworkError> {
        if endpoints.is_empty()
            || endpoints.len() > ENDPOINTS
            || socket_limit == 0
            || socket_limit > SOCKETS
            || byte_limit == 0
        {
            return Err(NetworkError::InvalidEndpoint);
        }
        let mut allowed = [None; ENDPOINTS];
        for (index, endpoint) in endpoints.iter().copied().enumerate() {
            endpoint.validate()?;
            if endpoints[..index].contains(&endpoint) {
                return Err(NetworkError::InvalidEndpoint);
            }
            allowed[index] = Some(endpoint);
        }
        Ok(Self {
            backend,
            endpoints: allowed,
            sockets: [None; SOCKETS],
            socket_limit,
            remaining_bytes: byte_limit,
            revoked: false,
        })
    }

    pub fn open(&mut self, family: TcpFamily) -> Result<u32, NetworkError> {
        if self.revoked {
            return Err(NetworkError::Closed);
        }
        let index = self.sockets[..self.socket_limit]
            .iter()
            .position(Option::is_none)
            .ok_or(NetworkError::DescriptorLimit)?;
        self.sockets[index] = Some(TcpSocket {
            family,
            handle: None,
        });
        Ok(index as u32)
    }

    pub fn connect(&mut self, socket: u32, endpoint: TcpEndpoint) -> Result<(), NetworkError> {
        let current = *self.socket(socket)?;
        if current.handle.is_some() {
            return Err(NetworkError::AlreadyConnected);
        }
        if current.family != endpoint.family {
            return Err(NetworkError::InvalidEndpoint);
        }
        endpoint.validate()?;
        if !self.endpoints.contains(&Some(endpoint)) {
            return Err(NetworkError::PermissionDenied);
        }
        let handle = self.backend.connect(endpoint)?;
        self.sockets[socket as usize].as_mut().unwrap().handle = Some(handle);
        Ok(())
    }

    pub fn read(&mut self, socket: u32, output: &mut [u8]) -> Result<usize, NetworkError> {
        let handle = self.handle(socket)?;
        if output.is_empty() {
            return Ok(0);
        }
        let length = self.transfer_length(output.len())?;
        let count = self.backend.read(handle, &mut output[..length])?;
        if count > length {
            return Err(NetworkError::Backend(5));
        }
        self.remaining_bytes -= count as u64;
        Ok(count)
    }

    pub fn write(&mut self, socket: u32, input: &[u8]) -> Result<usize, NetworkError> {
        let handle = self.handle(socket)?;
        if input.is_empty() {
            return Ok(0);
        }
        let length = self.transfer_length(input.len())?;
        let count = self.backend.write(handle, &input[..length])?;
        if count > length {
            return Err(NetworkError::Backend(5));
        }
        self.remaining_bytes -= count as u64;
        Ok(count)
    }

    pub fn readiness(&mut self, socket: u32) -> Result<TcpReadiness, NetworkError> {
        let handle = self.handle(socket)?;
        self.backend.readiness(handle)
    }

    pub fn socket_error(&mut self, socket: u32) -> Result<i32, NetworkError> {
        let handle = self.handle(socket)?;
        self.backend.socket_error(handle)
    }

    pub fn endpoint(&mut self, socket: u32, peer: bool) -> Result<TcpEndpoint, NetworkError> {
        let handle = self.handle(socket)?;
        self.backend.endpoint(handle, peer)
    }

    pub fn set_nodelay(&mut self, socket: u32, enabled: bool) -> Result<(), NetworkError> {
        let handle = self.handle(socket)?;
        self.backend.set_nodelay(handle, enabled)
    }

    pub fn shutdown(&mut self, socket: u32, read: bool, write: bool) -> Result<(), NetworkError> {
        let handle = self.handle(socket)?;
        if !read && !write {
            return Err(NetworkError::Backend(22));
        }
        self.backend.shutdown(handle, read, write)
    }

    pub fn close(&mut self, socket: u32) -> Result<(), NetworkError> {
        self.socket(socket)?;
        if let Some(handle) = self.sockets[socket as usize].take().unwrap().handle {
            self.backend.close(handle);
        }
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        for socket in &mut self.sockets {
            if let Some(handle) = socket.take().and_then(|socket| socket.handle) {
                self.backend.close(handle);
            }
        }
    }

    pub fn remaining_bytes(&self) -> u64 {
        self.remaining_bytes
    }

    fn socket(&self, socket: u32) -> Result<&TcpSocket<B::Handle>, NetworkError> {
        if self.revoked {
            return Err(NetworkError::Closed);
        }
        self.sockets
            .get(socket as usize)
            .and_then(Option::as_ref)
            .ok_or(NetworkError::InvalidDescriptor)
    }

    fn handle(&self, socket: u32) -> Result<B::Handle, NetworkError> {
        self.socket(socket)?
            .handle
            .ok_or(NetworkError::NotConnected)
    }

    fn transfer_length(&self, requested: usize) -> Result<usize, NetworkError> {
        if self.remaining_bytes == 0 {
            return Err(NetworkError::ByteLimit);
        }
        Ok(requested
            .min(4096)
            .min(self.remaining_bytes.min(usize::MAX as u64) as usize))
    }
}

impl<B: TcpBackend, const ENDPOINTS: usize, const SOCKETS: usize> Drop
    for BoundedTcp<B, ENDPOINTS, SOCKETS>
{
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Linux supervisor adapter. Sockets are always nonblocking and close-on-exec;
/// they are never installed in a workload's native descriptor table.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub struct LinuxTcpBackend;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
pub struct LinuxTcpHandle(i32);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl LinuxTcpBackend {
    unsafe fn call(number: usize, args: [usize; 6]) -> i64 {
        let result: i64;
        core::arch::asm!("syscall", inlateout("rax") number as i64 => result,
            in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
            in("r10") args[3], in("r8") args[4], in("r9") args[5],
            lateout("rcx") _, lateout("r11") _, options(nostack));
        result
    }

    fn result(result: i64) -> Result<usize, NetworkError> {
        match result {
            -11 => Err(NetworkError::WouldBlock),
            value if value < 0 => Err(NetworkError::Backend((-value) as i32)),
            value => Ok(value as usize),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl TcpBackend for LinuxTcpBackend {
    type Handle = LinuxTcpHandle;

    fn connect(&mut self, endpoint: TcpEndpoint) -> Result<Self::Handle, NetworkError> {
        endpoint.validate()?;
        let family = match endpoint.family {
            TcpFamily::Ipv4 => 2u16,
            TcpFamily::Ipv6 => 10u16,
        };
        let fd = Self::result(unsafe {
            Self::call(41, [family as usize, 1 | 0x800 | 0x80000, 6, 0, 0, 0])
        })?;
        let mut address = [0u8; 28];
        address[..2].copy_from_slice(&family.to_ne_bytes());
        address[2..4].copy_from_slice(&endpoint.port.to_be_bytes());
        let size = if endpoint.family == TcpFamily::Ipv4 {
            address[4..8].copy_from_slice(&endpoint.address[..4]);
            16
        } else {
            address[8..24].copy_from_slice(&endpoint.address);
            28
        };
        let result = unsafe { Self::call(42, [fd, address.as_ptr() as usize, size, 0, 0, 0]) };
        if result < 0 && result != -115 {
            // EINPROGRESS remains owned until poll/close.
            unsafe {
                Self::call(3, [fd, 0, 0, 0, 0, 0]);
            }
            return Err(NetworkError::Backend((-result) as i32));
        }
        Ok(LinuxTcpHandle(fd as i32))
    }

    fn read(&mut self, handle: Self::Handle, output: &mut [u8]) -> Result<usize, NetworkError> {
        Self::result(unsafe {
            Self::call(
                45,
                [
                    handle.0 as usize,
                    output.as_mut_ptr() as usize,
                    output.len(),
                    0x40,
                    0,
                    0,
                ],
            )
        })
    }

    fn write(&mut self, handle: Self::Handle, input: &[u8]) -> Result<usize, NetworkError> {
        // MSG_NOSIGNAL prevents a closed peer from terminating the supervisor.
        Self::result(unsafe {
            Self::call(
                44,
                [
                    handle.0 as usize,
                    input.as_ptr() as usize,
                    input.len(),
                    0x4040,
                    0,
                    0,
                ],
            )
        })
    }

    fn readiness(&mut self, handle: Self::Handle) -> Result<TcpReadiness, NetworkError> {
        #[repr(C)]
        struct PollFd {
            fd: i32,
            events: i16,
            revents: i16,
        }
        let mut fd = PollFd {
            fd: handle.0,
            events: 5,
            revents: 0,
        };
        Self::result(unsafe { Self::call(7, [&mut fd as *mut PollFd as usize, 1, 0, 0, 0, 0]) })?;
        if fd.revents & 0x20 != 0 {
            return Err(NetworkError::InvalidDescriptor);
        }
        Ok(TcpReadiness {
            readable: fd.revents & 1 != 0,
            writable: fd.revents & 4 != 0,
            hangup: fd.revents & 0x10 != 0,
            error: fd.revents & 8 != 0,
        })
    }

    fn socket_error(&mut self, handle: Self::Handle) -> Result<i32, NetworkError> {
        let mut error = 0i32;
        let mut size = 4u32;
        Self::result(unsafe {
            Self::call(
                55,
                [
                    handle.0 as usize,
                    1,
                    4,
                    &mut error as *mut i32 as usize,
                    &mut size as *mut u32 as usize,
                    0,
                ],
            )
        })?;
        if size != 4 {
            return Err(NetworkError::Backend(5));
        }
        Ok(error)
    }

    fn endpoint(&mut self, handle: Self::Handle, peer: bool) -> Result<TcpEndpoint, NetworkError> {
        let mut address = [0u8; 28];
        let mut size = address.len() as u32;
        Self::result(unsafe {
            Self::call(
                if peer { 52 } else { 51 },
                [
                    handle.0 as usize,
                    address.as_mut_ptr() as usize,
                    &mut size as *mut u32 as usize,
                    0,
                    0,
                    0,
                ],
            )
        })?;
        let port = u16::from_be_bytes([address[2], address[3]]);
        match (u16::from_ne_bytes([address[0], address[1]]), size) {
            (2, 16) => TcpEndpoint::ipv4([address[4], address[5], address[6], address[7]], port),
            (10, 28) => {
                let mut ip = [0; 16];
                ip.copy_from_slice(&address[8..24]);
                TcpEndpoint::ipv6(ip, port)
            }
            _ => Err(NetworkError::Backend(5)),
        }
    }

    fn set_nodelay(&mut self, handle: Self::Handle, enabled: bool) -> Result<(), NetworkError> {
        let value = i32::from(enabled);
        Self::result(unsafe {
            Self::call(
                54,
                [handle.0 as usize, 6, 1, &value as *const i32 as usize, 4, 0],
            )
        })
        .map(|_| ())
    }

    fn shutdown(
        &mut self,
        handle: Self::Handle,
        read: bool,
        write: bool,
    ) -> Result<(), NetworkError> {
        let how = match (read, write) {
            (true, true) => 2,
            (false, true) => 1,
            (true, false) => 0,
            _ => return Err(NetworkError::Backend(22)),
        };
        Self::result(unsafe { Self::call(48, [handle.0 as usize, how, 0, 0, 0, 0]) }).map(|_| ())
    }

    fn close(&mut self, handle: Self::Handle) {
        // Linux releases the descriptor even if close reports EINTR; retrying
        // would risk closing a newly reused descriptor.
        unsafe {
            Self::call(3, [handle.0 as usize, 0, 0, 0, 0, 0]);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    struct MemoryBlock {
        bytes: Vec<u8>,
        flushes: usize,
        closed: bool,
    }

    impl BlockBackend for MemoryBlock {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), DeviceError> {
            let start = offset as usize;
            let end = start
                .checked_add(output.len())
                .ok_or(DeviceError::OutOfRange)?;
            let source = self.bytes.get(start..end).ok_or(DeviceError::OutOfRange)?;
            output.copy_from_slice(source);
            Ok(())
        }
        fn write_at(&mut self, offset: u64, input: &[u8]) -> Result<(), DeviceError> {
            let start = offset as usize;
            let end = start
                .checked_add(input.len())
                .ok_or(DeviceError::OutOfRange)?;
            let destination = self
                .bytes
                .get_mut(start..end)
                .ok_or(DeviceError::OutOfRange)?;
            destination.copy_from_slice(input);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), DeviceError> {
            self.flushes += 1;
            Ok(())
        }
        fn close(&mut self) -> Result<(), DeviceError> {
            self.closed = true;
            Ok(())
        }
    }

    fn block() -> MemoryBlock {
        MemoryBlock {
            bytes: vec![0; 64],
            flushes: 0,
            closed: false,
        }
    }

    #[test]
    fn registry_projects_only_assigned_devices_and_uses_virtual_handles() {
        let mut registry: DeviceRegistry<8, 8> = DeviceRegistry::new();
        registry
            .assign(1, 10, DeviceName::new(b"null").unwrap(), DeviceKind::Null)
            .unwrap();
        registry
            .assign(2, 11, DeviceName::new(b"zero").unwrap(), DeviceKind::Zero)
            .unwrap();
        let mut visible = [DeviceName::new(b"unused").unwrap(); 4];
        assert_eq!(registry.visible(1, &mut visible), 1);
        assert_eq!(visible[0].as_bytes(), b"null");
        assert_eq!(registry.open(1, b"zero"), Err(DeviceError::NotAssigned));
        let fd = registry.open(1, b"null").unwrap();
        assert_eq!(fd, 0x4000_0000);
        assert_eq!(registry.write(1, fd, b"discard"), Ok(7));
        assert_eq!(
            registry.write(2, fd, b"escape"),
            Err(DeviceError::InvalidDescriptor)
        );
    }

    #[test]
    fn pseudo_devices_and_console_are_ginux_owned() {
        let mut registry: DeviceRegistry<8, 8> = DeviceRegistry::new();
        for (backend, name, kind) in [
            (1, b"console".as_slice(), DeviceKind::Console),
            (2, b"null", DeviceKind::Null),
            (3, b"zero", DeviceKind::Zero),
            (4, b"random", DeviceKind::Random),
        ] {
            registry
                .assign(7, backend, DeviceName::new(name).unwrap(), kind)
                .unwrap();
        }
        let zero = registry.open(7, b"zero").unwrap();
        let mut bytes = [9; 8];
        assert_eq!(registry.read(7, zero, &mut bytes), Ok(8));
        assert_eq!(bytes, [0; 8]);
        let random = registry.open(7, b"random").unwrap();
        registry.read(7, random, &mut bytes).unwrap();
        assert_ne!(bytes, [0; 8]);
        let console = registry.open(7, b"console").unwrap();
        let mut size = [0; 8];
        registry
            .ioctl(7, console, IOCTL_CONSOLE_GET_SIZE, &mut size)
            .unwrap();
        assert_eq!(&size[..4], &[24, 0, 80, 0]);
    }

    #[test]
    fn conflicts_ioctls_mappings_and_revoke_fail_closed() {
        let mut registry: DeviceRegistry<4, 4> = DeviceRegistry::new();
        registry
            .assign(
                1,
                77,
                DeviceName::new(b"console").unwrap(),
                DeviceKind::Console,
            )
            .unwrap();
        assert_eq!(
            registry.assign(
                2,
                77,
                DeviceName::new(b"tty0").unwrap(),
                DeviceKind::Console
            ),
            Err(DeviceError::AssignmentConflict)
        );
        let fd = registry.open(1, b"console").unwrap();
        assert_eq!(
            registry.ioctl(1, fd, IOCTL_CONSOLE_GET_SIZE, &mut [0; 7]),
            Err(DeviceError::InvalidPayload)
        );
        assert_eq!(
            registry.ioctl(1, fd, 0xdead, &mut []),
            Err(DeviceError::UnknownIoctl)
        );
        assert_eq!(registry.map(1, fd), Err(DeviceError::DirectMappingDenied));
        registry.revoke(1);
        assert_eq!(
            registry.write(1, fd, b"x"),
            Err(DeviceError::InvalidDescriptor)
        );
        registry
            .assign(
                2,
                77,
                DeviceName::new(b"tty0").unwrap(),
                DeviceKind::Console,
            )
            .unwrap();
    }

    #[test]
    fn block_partition_confines_reads_and_writes() {
        let mut partition = Partition::new(block(), 16, 16, false).unwrap();
        partition.write_at(0, b"inside").unwrap();
        let mut value = [0; 6];
        partition.read_at(0, &mut value).unwrap();
        assert_eq!(&value, b"inside");
        assert_eq!(partition.write_at(15, b"xx"), Err(DeviceError::OutOfRange));
        assert_eq!(
            partition.read_at(16, &mut [0; 1]),
            Err(DeviceError::OutOfRange)
        );
    }

    #[test]
    fn block_read_only_flush_and_close_policy() {
        let mut read_only = Partition::new(block(), 0, 32, true).unwrap();
        assert_eq!(read_only.write_at(0, b"x"), Err(DeviceError::ReadOnly));
        read_only.flush().unwrap();
        read_only.close().unwrap();
        assert_eq!(read_only.read_at(0, &mut [0; 1]), Err(DeviceError::Closed));
        assert_eq!(read_only.close(), Err(DeviceError::Closed));
    }

    #[test]
    fn network_is_isolated_bounded_and_revocable() {
        let mut network: IsolatedNetwork<2> = IsolatedNetwork::new();
        network.send(b"packet-one").unwrap();
        network.send(b"packet-two").unwrap();
        assert_eq!(network.send(b"packet-three"), Err(DeviceError::QueueFull));
        let mut output = [0; 32];
        let size = network.receive(&mut output).unwrap();
        assert_eq!(&output[..size], b"packet-one");
        assert_eq!(network.control(1), Err(DeviceError::UnknownIoctl));
        network.close();
        assert_eq!(network.send(b"after-close"), Err(DeviceError::Closed));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn tcp_endpoint_slots_budget_and_revocation_use_real_connections() {
        use std::io::{Read, Write};
        use std::net::{Ipv4Addr, TcpListener};
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let denied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        denied.set_nonblocking(true).unwrap();
        let endpoint =
            TcpEndpoint::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port()).unwrap();
        let forbidden =
            TcpEndpoint::ipv4([127, 0, 0, 1], denied.local_addr().unwrap().port()).unwrap();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut input = [0; 4];
            stream.read_exact(&mut input).unwrap();
            assert_eq!(&input, b"ping");
            stream.write_all(b"pong").unwrap();
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!("revocation left peer open: {other:?}"),
            }
        });
        let mut network: BoundedTcp<_, 2, 2> =
            BoundedTcp::new(LinuxTcpBackend, &[endpoint], 2, 7).unwrap();
        let socket = network.open(TcpFamily::Ipv4).unwrap();
        let unused = network.open(TcpFamily::Ipv4).unwrap();
        assert_eq!(
            network.open(TcpFamily::Ipv4),
            Err(NetworkError::DescriptorLimit)
        );
        assert_eq!(
            network.connect(socket, forbidden),
            Err(NetworkError::PermissionDenied)
        );
        assert!(
            matches!(denied.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        assert_eq!(
            network.read(socket, &mut [0]),
            Err(NetworkError::NotConnected)
        );
        network.connect(socket, endpoint).unwrap();
        assert_eq!(
            network.connect(socket, endpoint),
            Err(NetworkError::AlreadyConnected)
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while !network.readiness(socket).unwrap().writable {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(network.socket_error(socket), Ok(0));
        assert_eq!(network.endpoint(socket, true), Ok(endpoint));
        let local = network.endpoint(socket, false).unwrap();
        assert_eq!(local.family, TcpFamily::Ipv4);
        assert_eq!(&local.address[..4], &[127, 0, 0, 1]);
        assert_ne!(local.port, 0);
        network.set_nodelay(socket, true).unwrap();
        assert_eq!(network.write(socket, b"ping"), Ok(4));
        let mut response = [0; 16];
        let count = loop {
            match network.read(socket, &mut response) {
                Err(NetworkError::WouldBlock) => {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => break result.unwrap(),
            }
        };
        assert_eq!(count, 3);
        assert_eq!(&response[..count], b"pon");
        assert_eq!(network.remaining_bytes(), 0);
        assert_eq!(network.write(socket, b"x"), Err(NetworkError::ByteLimit));
        assert_eq!(
            network.read(socket, &mut response),
            Err(NetworkError::ByteLimit)
        );
        network.close(unused).unwrap();
        network.revoke();
        network.revoke();
        assert_eq!(network.open(TcpFamily::Ipv4), Err(NetworkError::Closed));
        assert_eq!(network.write(socket, b""), Err(NetworkError::Closed));
        peer.join().unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn tcp_drop_closes_connecting_handles_and_invalid_policy_never_opens() {
        use std::io::Read;
        use std::net::{Ipv4Addr, TcpListener};
        use std::time::Duration;

        assert_eq!(
            TcpEndpoint::ipv4([127, 0, 0, 1], 0),
            Err(NetworkError::InvalidEndpoint)
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint =
            TcpEndpoint::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port()).unwrap();
        assert!(matches!(
            BoundedTcp::<_, 2, 2>::new(LinuxTcpBackend, &[endpoint, endpoint], 1, 10),
            Err(NetworkError::InvalidEndpoint)
        ));
        let mut network: BoundedTcp<_, 1, 2> =
            BoundedTcp::new(LinuxTcpBackend, &[endpoint], 1, 100).unwrap();
        let wrong_family = network.open(TcpFamily::Ipv6).unwrap();
        assert_eq!(
            network.connect(wrong_family, endpoint),
            Err(NetworkError::InvalidEndpoint)
        );
        network.close(wrong_family).unwrap();
        assert_eq!(
            network.close(wrong_family),
            Err(NetworkError::InvalidDescriptor)
        );
        let socket = network.open(TcpFamily::Ipv4).unwrap();
        network.connect(socket, endpoint).unwrap();
        // Drop revokes a connect before the caller has waited for readiness.
        drop(network);
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn tcp_loopback_roundtrip_metadata_and_budget() {
        use std::io::{Read, Write};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let listener = TcpListener::bind((address, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let endpoint = match address {
                IpAddr::V4(ip) => TcpEndpoint::ipv4(ip.octets(), port).unwrap(),
                IpAddr::V6(ip) => TcpEndpoint::ipv6(ip.octets(), port).unwrap(),
            };
            let (ready_tx, ready_rx) = mpsc::channel();
            let (reply_tx, reply_rx) = mpsc::channel();
            let peer = std::thread::spawn(move || {
                let (mut stream, remote) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"ping");
                assert_eq!(stream.read(&mut [0u8]).unwrap(), 0); // Ordinary write half-close.
                ready_tx.send(remote).unwrap();
                reply_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                stream.write_all(b"pong").unwrap();
            });
            let mut network: BoundedTcp<_, 1, 1> =
                BoundedTcp::new(LinuxTcpBackend, &[endpoint], 1, 7).unwrap();
            let socket = network.open(endpoint.family).unwrap();
            network.connect(socket, endpoint).unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            while !network.readiness(socket).unwrap().writable {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(network.socket_error(socket), Ok(0));
            assert_eq!(network.endpoint(socket, true), Ok(endpoint));
            network.set_nodelay(socket, true).unwrap();
            network.set_nodelay(socket, false).unwrap();
            assert_eq!(network.write(socket, b"ping"), Ok(4));
            network.shutdown(socket, false, true).unwrap();
            let remote = ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            let local = network.endpoint(socket, false).unwrap();
            assert_eq!(local.port, remote.port());
            assert_eq!(local.family, endpoint.family);
            assert_eq!(local.address, endpoint.address);
            let mut reply = [0u8; 16];
            assert_eq!(
                network.read(socket, &mut reply),
                Err(NetworkError::WouldBlock)
            );
            assert_eq!(network.remaining_bytes(), 3);
            reply_tx.send(()).unwrap();
            let mut used = 0;
            while used < 3 {
                match network.read(socket, &mut reply[used..]) {
                    Ok(count) => {
                        assert_ne!(count, 0);
                        used += count;
                    }
                    Err(NetworkError::WouldBlock) => {
                        assert!(Instant::now() < deadline);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    other => panic!("ordinary reply failed: {other:?}"),
                }
            }
            assert_eq!(&reply[..used], b"pon");
            assert_eq!(network.remaining_bytes(), 0);
            assert_eq!(network.write(socket, b"x"), Err(NetworkError::ByteLimit));
            assert_eq!(
                network.read(socket, &mut reply),
                Err(NetworkError::ByteLimit)
            );
            assert_eq!(network.write(socket, b""), Ok(0));
            assert_eq!(network.read(socket, &mut []), Ok(0));
            network.close(socket).unwrap();
            peer.join().unwrap();
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn tcp_loopback_close_drop_and_revoke() {
        use std::io::Read;
        use std::net::{Ipv4Addr, TcpListener};
        use std::time::Duration;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint =
            TcpEndpoint::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port()).unwrap();
        for completion in 0..3 {
            let mut network: BoundedTcp<_, 1, 2> =
                BoundedTcp::new(LinuxTcpBackend, &[endpoint], 1, 16).unwrap();
            let socket = network.open(TcpFamily::Ipv4).unwrap();
            assert_eq!(
                network.open(TcpFamily::Ipv4),
                Err(NetworkError::DescriptorLimit)
            );
            network.connect(socket, endpoint).unwrap();
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            if completion == 0 {
                network.close(socket).unwrap();
            }
            if completion == 1 {
                network.revoke();
                network.revoke();
            }
            drop(network);
            assert_eq!(peer.read(&mut [0u8]).unwrap(), 0);
        }
    }
}
