//! The `sx --sandbox-apply` helper.
//!
//! `sx` re-execs itself in this mode as the sandbox launcher, mirroring how the
//! macOS backend goes through `/usr/bin/sandbox-exec`. Doing the work in a
//! freshly exec'd process rather than in a `pre_exec` hook keeps it
//! single-threaded (required by `unshare(CLONE_NEWUSER)`) and avoids running
//! allocating code between `fork` and `exec`.
//!
//! The helper can only ever *add* restrictions - Landlock rulesets compose
//! monotonically and namespaces only remove access - so it is safe for a
//! sandboxed process to invoke it again.

use crate::sandbox::backend;
use crate::sandbox::executor::exit_codes;
use crate::sandbox::linux::{landlock, net, rules};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// Apply the sandbox described by `args[0]`, then exec `args[1..]`.
///
/// Never returns on success: the process is replaced by the target command.
pub fn run(args: &[OsString]) -> ! {
    let Some((spec_path, command)) = args.split_first() else {
        fail("usage: sx --sandbox-apply <spec> <command> [args...]");
    };
    if command.is_empty() {
        fail("no command given to run inside the sandbox");
    }

    let params = match backend::load_spec(Path::new(spec_path)) {
        Ok(params) => params,
        Err(e) => fail(&format!("could not read sandbox spec: {e}")),
    };

    // Network first: writing /proc/self/uid_map must happen before the
    // filesystem policy is in force.
    if let Err(e) = net::apply(params.network_mode) {
        fail(&e);
    }

    if let Err(e) = landlock::apply(&rules::build(&params)) {
        fail(&e);
    }

    let error = Command::new(&command[0]).args(&command[1..]).exec();

    let code = match error.kind() {
        std::io::ErrorKind::NotFound => exit_codes::COMMAND_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => exit_codes::COMMAND_NOT_EXECUTABLE,
        _ => exit_codes::GENERAL_ERROR,
    };
    eprintln!(
        "\x1b[31m[sx]\x1b[0m {}: {}",
        command[0].to_string_lossy(),
        error
    );
    std::process::exit(code);
}

fn fail(message: &str) -> ! {
    eprintln!("\x1b[31m[sx]\x1b[0m {}", message);
    std::process::exit(exit_codes::CONFIG_ERROR);
}
