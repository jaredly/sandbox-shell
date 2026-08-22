`sx` (sandbox-shell) is a Rust CLI that wraps shell sessions and commands in a kernel sandbox - Seatbelt on macOS, Landlock on Linux. It protects developers from malicious code in npm packages, untrusted repositories, and build scripts by restricting filesystem and network access.

**Architecture**: config/profiles/CLI are platform-neutral and produce a `SandboxParams`. `sandbox::backend` turns that into a launcher: `sandbox-exec -f <profile>` on macOS, `sx --sandbox-apply <spec>` (a re-exec of this binary) on Linux. Both backends are compiled on every target so the macOS code stays type-checked by Linux CI; only the selection in `backend.rs` is target-specific.

**Critical Seatbelt Rules**:
1. Root literal `(allow file-read* (literal "/"))` is required for path traversal - processes need to read `/` to resolve paths
2. Seatbelt uses last-match-wins semantics when rules have matching filter types - deny rules after allow rules take precedence for nested paths (e.g., allow `/home` then deny `/home/.ssh`)
3. `(allow file-read-metadata)` must be global (no path filter) - required for `getaddrinfo()` DNS resolution to work. Without this, `curl`, Python, and other tools using the system resolver fail with "Could not resolve host" even when network is allowed. Commands like `host` and `nslookup` work without it because they use direct DNS UDP queries.

**Critical Landlock Rules**:
1. Landlock is **allow-list only** - there are no deny rules. `deny_read` is emulated by subtraction in `sandbox::linux::rules`: an allowed hierarchy containing a denied path is expanded into its siblings. Listing is granted on the hierarchy (so `ls ~` works), file contents are carved out
2. Landlock rules reference **resolved paths at policy-build time** - globs are expanded once, and paths created later do not match. Seatbelt regexes are evaluated at access time
3. Do **not** handle `AccessFs::IoctlDev` - leaving it unhandled keeps device ioctls implicitly allowed, which is what terminal control needs (mirrors Seatbelt's global `(allow file-ioctl)`)
4. Landlock cannot express the network modes (ABI 4 filters TCP by port, not address). Network isolation uses a user+network namespace, with a seccomp filter as the fallback where unprivileged user namespaces are blocked
5. Always fail closed: if Landlock reports `NotEnforced`, or no network mechanism can be applied, refuse to run rather than execute unsandboxed
6. The `--sandbox-apply` helper runs in a freshly exec'd, single-threaded process. `unshare(CLONE_NEWUSER)` requires that, and it avoids allocating between `fork` and `exec`

**Configuration Options**:
- `inherit_base = false` in `.sandbox.toml` skips the base profile for full custom control over allowed paths
- Profiles support `[platform.macos.*]` / `[platform.linux.*]` overlays, folded into the shared fields when the profile loads

## Programming Rules

Produce code following **LEAN, CLEAN, MINIMAL but thoughtful KISS & YAGNI principle**.
Follow TDD paradigm `red-green-refactor` for unit test.
Follow Rust Book, Rust API Guidelines, and idiomatic Rust resources.
