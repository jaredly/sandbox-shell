//! Platform sandbox backends.
//!
//! Both platforms follow the same shape: `sx` resolves a policy, writes it to a
//! private temp file, and launches the target command through a helper that
//! applies the policy before `exec`.
//!
//! | Platform | Helper | Policy language |
//! |----------|--------|-----------------|
//! | macOS    | `/usr/bin/sandbox-exec` | Seatbelt profile |
//! | Linux    | `sx --sandbox-apply` (this binary) | serialised `SandboxParams`, enforced with Landlock |
//!
//! Both implementations are compiled on every platform so they stay
//! type-checked everywhere; only the selection below is target-specific.

use crate::sandbox::params::SandboxParams;
use crate::sandbox::seatbelt::generate_seatbelt_profile;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::PathBuf;
use tempfile::NamedTempFile;

/// Hidden argument that puts `sx` into "apply sandbox then exec" mode.
pub const APPLY_FLAG: &str = "--sandbox-apply";

/// Error building a sandbox policy
#[derive(Debug)]
pub enum PolicyError {
    Io(io::Error),
    /// The backend refused to build a policy from these parameters.
    Invalid(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Io(e) => write!(f, "IO error: {}", e),
            PolicyError::Invalid(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PolicyError::Io(e) => Some(e),
            PolicyError::Invalid(_) => None,
        }
    }
}

impl From<io::Error> for PolicyError {
    fn from(e: io::Error) -> Self {
        PolicyError::Io(e)
    }
}

/// A prepared sandbox launcher.
///
/// `program` + `args` are prepended to the user's command; the policy temp file
/// is owned here and must outlive the child process that reads it.
#[derive(Debug)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    _policy: NamedTempFile,
}

/// Human-readable name of the active enforcement mechanism.
pub const fn name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "seatbelt"
    }
    #[cfg(target_os = "linux")]
    {
        "landlock"
    }
}

/// One-line description of the active backend, for `--explain` and `--verbose`.
pub fn describe() -> String {
    #[cfg(target_os = "macos")]
    {
        "seatbelt (/usr/bin/sandbox-exec)".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        // Kernel details come from `caveats()` so they are not repeated.
        "landlock".to_string()
    }
}

/// Platform-specific caveats that apply to these parameters.
pub fn caveats(params: &SandboxParams) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let _ = params;
        Vec::new()
    }
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::linux::policy::notes(params)
    }
}

/// Build the launcher for the current platform.
pub fn prepare(params: &SandboxParams) -> Result<Launch, PolicyError> {
    #[cfg(target_os = "macos")]
    {
        prepare_seatbelt(params)
    }
    #[cfg(target_os = "linux")]
    {
        prepare_landlock(params)
    }
}

/// Render the policy as text, for `--dry-run`.
pub fn render_policy(params: &SandboxParams) -> Result<String, PolicyError> {
    #[cfg(target_os = "macos")]
    {
        render_seatbelt(params)
    }
    #[cfg(target_os = "linux")]
    {
        Ok(crate::sandbox::linux::policy::render(params))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("sx supports macOS (Seatbelt) and Linux (Landlock) only");

// --- macOS (Seatbelt) ---
//
// Compiled on every target so the macOS launcher keeps being type-checked (and
// unit-tested) by Linux CI; only the selection above is target-specific.

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn render_seatbelt(params: &SandboxParams) -> Result<String, PolicyError> {
    generate_seatbelt_profile(params).map_err(|e| PolicyError::Invalid(e.to_string()))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn prepare_seatbelt(params: &SandboxParams) -> Result<Launch, PolicyError> {
    let profile = render_seatbelt(params)?;
    let policy = NamedTempFile::new()?;
    fs::write(policy.path(), &profile)?;

    Ok(Launch {
        program: PathBuf::from("/usr/bin/sandbox-exec"),
        args: vec![OsString::from("-f"), policy.path().into()],
        _policy: policy,
    })
}

// --- Linux (Landlock) ---

/// Serialise the resolved parameters for the helper process.
///
/// The helper re-execs this same binary, so the policy crosses the process
/// boundary as a file rather than as `argv` (which is world-readable) or an
/// env var (which the sandboxed program would inherit).
#[cfg(target_os = "linux")]
fn prepare_landlock(params: &SandboxParams) -> Result<Launch, PolicyError> {
    // Strip everything the helper does not need. Environment filtering is
    // applied by the parent to the child's `Command`, so carrying `set_env`
    // values into a file under /tmp would put configured secrets on disk for
    // no benefit. Raw seatbelt rules are macOS-only.
    let mut spec = params.clone();
    spec.pass_env.clear();
    spec.deny_env.clear();
    spec.set_env.clear();
    spec.raw_rules = None;

    let spec = toml::to_string(&spec)
        .map_err(|e| PolicyError::Invalid(format!("failed to serialise sandbox spec: {}", e)))?;
    let policy = NamedTempFile::new()?;
    fs::write(policy.path(), &spec)?;

    let program = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));

    Ok(Launch {
        program,
        args: vec![OsString::from(APPLY_FLAG), policy.path().into()],
        _policy: policy,
    })
}

/// Parse a spec file written by [`prepare`].
#[cfg(target_os = "linux")]
pub fn load_spec(path: &std::path::Path) -> Result<SandboxParams, PolicyError> {
    let content = fs::read_to_string(path)?;
    toml::from_str(&content)
        .map_err(|e| PolicyError::Invalid(format!("invalid sandbox spec: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample() -> SandboxParams {
        SandboxParams {
            working_dir: PathBuf::from("/tmp/project"),
            allow_read: vec![PathBuf::from("/usr")],
            ..Default::default()
        }
    }

    #[test]
    fn seatbelt_launcher_wraps_sandbox_exec() {
        let launch = prepare_seatbelt(&sample()).unwrap();
        assert_eq!(launch.program, Path::new("/usr/bin/sandbox-exec"));
        assert_eq!(launch.args[0], OsString::from("-f"));

        let profile = fs::read_to_string(&launch.args[1]).unwrap();
        assert!(profile.starts_with("(version 1)"));
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn seatbelt_render_rejects_paths_that_would_break_the_profile() {
        let params = SandboxParams {
            allow_read: vec![PathBuf::from("/tmp/eviln\"(allow default)")],
            ..Default::default()
        };
        assert!(matches!(
            render_seatbelt(&params),
            Err(PolicyError::Invalid(_))
        ));
    }

    #[test]
    fn backend_name_matches_target() {
        if cfg!(target_os = "macos") {
            assert_eq!(name(), "seatbelt");
        } else {
            assert_eq!(name(), "landlock");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_launcher_reexecs_this_binary_with_a_readable_spec() {
        let launch = prepare_landlock(&sample()).unwrap();
        assert_eq!(launch.args[0], OsString::from(APPLY_FLAG));

        let spec = load_spec(Path::new(&launch.args[1])).unwrap();
        assert_eq!(spec.working_dir, PathBuf::from("/tmp/project"));
        assert_eq!(spec.allow_read, vec![PathBuf::from("/usr")]);
    }

    /// The helper needs the policy, not the environment: env filtering happens
    /// in the parent, so nothing sensitive is written to the spec file.
    #[cfg(target_os = "linux")]
    #[test]
    fn spec_omits_environment_values() {
        let params = SandboxParams {
            set_env: [("TOKEN".to_string(), "s3cret".to_string())]
                .into_iter()
                .collect(),
            pass_env: vec!["TOKEN".into()],
            deny_env: vec!["AWS_*".into()],
            raw_rules: Some("(allow x)".into()),
            ..sample()
        };
        let launch = prepare_landlock(&params).unwrap();

        let raw = fs::read_to_string(&launch.args[1]).unwrap();
        assert!(!raw.contains("s3cret"), "spec file leaked a set_env value");

        let back = load_spec(Path::new(&launch.args[1])).unwrap();
        assert!(back.set_env.is_empty());
        assert!(back.pass_env.is_empty());
        assert!(back.deny_env.is_empty());
        assert!(back.raw_rules.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spec_round_trips_the_policy_fields() {
        let params = SandboxParams {
            working_dir: PathBuf::from("/w"),
            home_dir: PathBuf::from("/h"),
            network_mode: crate::config::schema::NetworkMode::Localhost,
            allow_read: vec![PathBuf::from("/a")],
            deny_read: vec![PathBuf::from("/d")],
            allow_write: vec![PathBuf::from("/w2")],
            allow_list_dirs: vec![PathBuf::from("/l")],
            raw_rules: None,
            allow_exec_sugid: crate::config::schema::ExecSugid::Paths(vec!["/bin/ps".into()]),
            pass_env: Vec::new(),
            deny_env: Vec::new(),
            set_env: Default::default(),
        };
        let launch = prepare_landlock(&params).unwrap();
        let back = load_spec(Path::new(&launch.args[1])).unwrap();

        assert_eq!(back.working_dir, params.working_dir);
        assert_eq!(back.home_dir, params.home_dir);
        assert_eq!(back.network_mode, params.network_mode);
        assert_eq!(back.allow_read, params.allow_read);
        assert_eq!(back.deny_read, params.deny_read);
        assert_eq!(back.allow_write, params.allow_write);
        assert_eq!(back.allow_list_dirs, params.allow_list_dirs);
        assert_eq!(back.allow_exec_sugid, params.allow_exec_sugid);
    }
}
