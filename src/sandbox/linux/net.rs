//! Network isolation for the Linux backend.
//!
//! Landlock only gained TCP controls in ABI 4 and filters by *port*, never by
//! address, so it cannot express `sx`'s network modes on its own. Network
//! isolation is done with namespaces instead, with a seccomp filter as a
//! fallback for distributions that block unprivileged user namespaces
//! (Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`, for example).
//!
//! | Mode | Mechanism |
//! |------|-----------|
//! | `online` | nothing |
//! | `offline` | empty network namespace, else seccomp on `socket(AF_INET*)` |
//! | `localhost` | network namespace with `lo` brought up |
//!
//! `localhost` differs from macOS by design: Seatbelt filters the *host's*
//! loopback, so a sandboxed server is reachable from the host. A network
//! namespace gives the sandbox its own private loopback instead - sandboxed
//! processes reach each other over 127.0.0.1, and nothing else. That is
//! strictly tighter (host-local databases, agent sockets and daemons stay out
//! of reach) but it is a real behavioural difference.

use crate::config::schema::NetworkMode;
use std::io;

/// How network access ended up being restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// `online`: no restriction applied.
    Unrestricted,
    /// Private network namespace, optionally with loopback up.
    Namespace { loopback: bool },
    /// seccomp filter rejecting AF_INET/AF_INET6/AF_PACKET sockets.
    Seccomp,
}

impl std::fmt::Display for Enforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Enforcement::Unrestricted => write!(f, "unrestricted"),
            Enforcement::Namespace { loopback: false } => {
                write!(f, "network namespace (no interfaces)")
            }
            Enforcement::Namespace { loopback: true } => {
                write!(f, "network namespace (private loopback only)")
            }
            Enforcement::Seccomp => write!(f, "seccomp (AF_INET/AF_INET6/AF_PACKET blocked)"),
        }
    }
}

/// Restrict the calling process's network access for `mode`.
///
/// Must run in a single-threaded process: `unshare(CLONE_NEWUSER)` requires it.
pub fn apply(mode: NetworkMode) -> Result<Enforcement, String> {
    match mode {
        NetworkMode::Online => Ok(Enforcement::Unrestricted),
        NetworkMode::Offline => match unshare_network(false) {
            Ok(()) => Ok(Enforcement::Namespace { loopback: false }),
            Err(ns_err) => match block_inet_sockets() {
                Ok(()) => Ok(Enforcement::Seccomp),
                // Fail closed: never run an "offline" command with live network.
                Err(seccomp_err) => Err(format!(
                    "could not isolate the network: user namespace failed ({ns_err}) and the \
                     seccomp fallback failed ({seccomp_err}). Refusing to run with network access."
                )),
            },
        },
        NetworkMode::Localhost => unshare_network(true)
            .map(|()| Enforcement::Namespace { loopback: true })
            .map_err(|e| {
                format!(
                    "localhost mode needs an unprivileged user namespace, which this system \
                     refused ({e}). Enable it (`sysctl -w kernel.unprivileged_userns_clone=1`, or \
                     on Ubuntu `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`) or use \
                     --offline / --online instead."
                )
            }),
    }
}

/// Enter a private user + network namespace.
fn unshare_network(loopback: bool) -> Result<(), String> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };

    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }

    // Map our own credentials 1:1 so files keep their normal ownership. The
    // kernel allows an unprivileged single-entry map for the caller's own uid;
    // `setgroups` must be denied before gid_map may be written.
    write_proc("/proc/self/setgroups", "deny")?;
    write_proc("/proc/self/uid_map", &format!("{uid} {uid} 1"))?;
    write_proc("/proc/self/gid_map", &format!("{gid} {gid} 1"))?;

    if loopback {
        bring_loopback_up()?;
    }
    Ok(())
}

fn write_proc(path: &str, value: &str) -> Result<(), String> {
    std::fs::write(path, value).map_err(|e| format!("failed to write {path}: {e}"))
}

// SIOCGIFFLAGS / SIOCSIFFLAGS are stable Linux ioctl numbers.
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

/// `struct ifreq`, spelled out so it does not depend on libc's union layout.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    flags: libc::c_short,
    _union_pad: [u8; 22],
}

/// Bring `lo` up inside the new namespace.
///
/// We hold CAP_NET_ADMIN over this namespace because we created the user
/// namespace that owns it.
fn bring_loopback_up() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!(
            "failed to open control socket: {}",
            io::Error::last_os_error()
        ));
    }

    let mut req = IfReq {
        name: [0; 16],
        flags: 0,
        _union_pad: [0; 22],
    };
    for (slot, byte) in req.name.iter_mut().zip(b"lo") {
        *slot = *byte as libc::c_char;
    }

    let result = unsafe {
        if libc::ioctl(fd, SIOCGIFFLAGS, &mut req as *mut IfReq) != 0 {
            Err(io::Error::last_os_error())
        } else {
            req.flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(fd, SIOCSIFFLAGS, &req as *const IfReq) != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    };
    unsafe { libc::close(fd) };
    result.map_err(|e| format!("failed to bring up loopback: {e}"))
}

/// Report whether an unprivileged user namespace can be created, without
/// disturbing the calling process.
///
/// Forks a child that only calls `unshare` and `_exit`, so it stays
/// async-signal-safe even if the caller has threads.
pub fn user_namespace_available() -> bool {
    match unsafe { libc::fork() } {
        -1 => false,
        0 => {
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
            unsafe { libc::_exit(if rc == 0 { 0 } else { 1 }) }
        }
        pid => {
            let mut status = 0;
            if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                return false;
            }
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }
    }
}

// --- seccomp fallback ---

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

// Offsets into `struct seccomp_data`.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0: u32 = 16;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Reject creation of IP and packet sockets for this process and its children.
///
/// Coarser than a network namespace - it cannot distinguish loopback - but it
/// needs no namespace support, which is what makes it a usable fallback.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn block_inet_sockets() -> Result<(), String> {
    let deny = SECCOMP_RET_ERRNO | (libc::EAFNOSUPPORT as u32 & 0xffff);
    let filter = [
        insn(BPF_LD_W_ABS, 0, 0, OFF_ARCH),
        insn(BPF_JMP_JEQ_K, 1, 0, AUDIT_ARCH),
        insn(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        insn(BPF_LD_W_ABS, 0, 0, OFF_NR),
        insn(BPF_JMP_JEQ_K, 0, 5, libc::SYS_socket as u32),
        insn(BPF_LD_W_ABS, 0, 0, OFF_ARG0),
        insn(BPF_JMP_JEQ_K, 2, 0, libc::AF_INET as u32),
        insn(BPF_JMP_JEQ_K, 1, 0, libc::AF_INET6 as u32),
        insn(BPF_JMP_JEQ_K, 0, 1, libc::AF_PACKET as u32),
        insn(BPF_RET_K, 0, 0, deny),
        insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
    ];

    // A seccomp filter may only be installed with no_new_privs set. Landlock
    // sets it too, but the filter goes on first.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "failed to set no_new_privs: {}",
            io::Error::last_os_error()
        ));
    }

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &prog as *const libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(format!(
            "seccomp filter rejected: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn block_inet_sockets() -> Result<(), String> {
    Err("no seccomp filter is defined for this architecture".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_applies_nothing() {
        assert_eq!(
            apply(NetworkMode::Online).unwrap(),
            Enforcement::Unrestricted
        );
    }

    #[test]
    fn enforcement_descriptions_are_distinct() {
        assert_ne!(
            Enforcement::Namespace { loopback: true }.to_string(),
            Enforcement::Namespace { loopback: false }.to_string()
        );
        assert!(Enforcement::Seccomp.to_string().contains("seccomp"));
    }

    /// Verifies the BPF program in a throwaway child: the filter is
    /// irreversible, so it cannot be installed in the test process itself.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn seccomp_fallback_blocks_inet_but_keeps_unix() {
        let mut status = 0;
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let code = match block_inet_sockets() {
                Err(_) => 10,
                Ok(()) => {
                    let inet = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                    let unix = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
                    match (inet < 0, unix >= 0) {
                        (true, true) => 0,
                        (false, _) => 11, // AF_INET was allowed through
                        (_, false) => 12, // AF_UNIX was wrongly blocked
                    }
                }
            };
            unsafe { libc::_exit(code) }
        }
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        assert_eq!(libc::WEXITSTATUS(status), 0, "seccomp filter misbehaved");
    }
}
