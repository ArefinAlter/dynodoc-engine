//! Platform-safe private file and directory creation for history artifacts.
//!
//! Enforces exclusive creation and owner-only access from the moment of creation:
//! - Unix: mode 0600 for files and 0700 for directories set at creation time (no permission window).
//! - Windows: exclusive creation followed by DACL restriction removing inheritance and granting
//!   full control to the current user only (verified via system icacls). Fails closed before content
//!   is written.
//!
//! Pre-existing scratch paths are rejected; cleanup guards ensure partial or failed writes
//! are removed while keeping existing destinations intact.

use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

fn file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Create a new private file that must not already exist, readable and writable
/// by the current user only (mode 0600 on Unix at creation, one-entry DACL on Windows).
///
/// If creation or restriction fails, fails closed and ensures no partial file remains.
pub fn create_private_file(path: &Path) -> std::io::Result<File> {
    let file = file_options().open(path)?;
    if let Err(reason) = restrict_windows(path) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            reason,
        ));
    }
    Ok(file)
}

/// Create a new private directory that must not already exist, accessible by the
/// current user only (mode 0700 on Unix at creation, one-entry DACL on Windows).
///
/// Rejects pre-existing paths; does NOT use `create_dir_all`.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[allow(unused_mut)]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    if let Err(reason) = restrict_windows(path) {
        let _ = std::fs::remove_dir(path);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            reason,
        ));
    }
    Ok(())
}

/// Cleanup guard for newly created output files.
///
/// Automatically removes the file on drop unless explicitly committed.
/// Handles must be closed prior to dropping to ensure clean removal across platforms.
pub struct AutoRemoveFile {
    path: PathBuf,
    active: bool,
}

impl AutoRemoveFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    /// Mark the output file write as completed; prevents cleanup on drop.
    pub fn commit(mut self) {
        self.active = false;
    }
}

impl Drop for AutoRemoveFile {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Restrict access to the current Windows user on Windows, or no-op on other platforms.
#[cfg(not(windows))]
pub fn restrict_windows(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Restrict access to the current Windows user using icacls and verify the resulting DACL.
#[cfg(windows)]
pub fn restrict_windows(path: &Path) -> Result<(), String> {
    use std::process::Command;
    let username = std::env::var("USERNAME")
        .ok()
        .filter(|u| !u.is_empty())
        .ok_or("cannot determine the current Windows user (USERNAME is not set)")?;
    let principal = match std::env::var("USERDOMAIN").ok().filter(|d| !d.is_empty()) {
        Some(domain) => format!("{domain}\\{username}"),
        None => username.clone(),
    };
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let icacls = root.join("System32").join("icacls.exe");
    let fail = |what: &str, detail: String| {
        format!(
            "cannot restrict {} to the current user ({what}: {detail})",
            path.display()
        )
    };
    let applied = Command::new(&icacls)
        .args(icacls_apply_args(path, &principal))
        .output()
        .map_err(|e| fail("icacls did not start", e.to_string()))?;
    if !applied.status.success() {
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&applied.stdout),
            String::from_utf8_lossy(&applied.stderr)
        );
        let first = text.lines().find(|l| !l.trim().is_empty());
        return Err(fail(
            "icacls failed",
            first.unwrap_or("no message").trim().to_owned(),
        ));
    }
    let shown = Command::new(&icacls)
        .arg(path)
        .output()
        .map_err(|e| fail("icacls did not start for verification", e.to_string()))?;
    let text = String::from_utf8_lossy(&shown.stdout).into_owned();
    match acl_principals(&text, path) {
        Some(found) if only_user(&found, &username) => Ok(()),
        Some(found) => Err(fail(
            "verification",
            format!("access list is {}", found.join(", ")),
        )),
        None => Err(fail(
            "verification",
            "unrecognised icacls output".to_owned(),
        )),
    }
}

/// `icacls` arguments that drop inherited entries and leave one entry for `principal` with full control.
pub fn icacls_apply_args(path: &Path, principal: &str) -> Vec<std::ffi::OsString> {
    vec![
        path.as_os_str().to_owned(),
        "/inheritance:r".into(),
        "/remove:g".into(),
        "*S-1-5-18".into(),
        "*S-1-5-32-544".into(),
        "/grant:r".into(),
        format!("{principal}:F").into(),
    ]
}

/// The principals named in `icacls <path>` output.
pub fn acl_principals(output: &str, path: &Path) -> Option<Vec<String>> {
    let raw_path = path.to_string_lossy();
    let path = raw_path.strip_prefix(r"\\?\").unwrap_or(&raw_path);
    let mut principals = Vec::new();
    for (index, line) in output.lines().enumerate() {
        if line.trim().is_empty() {
            break;
        }
        let line = line.strip_prefix(r"\\?\").unwrap_or(line);
        let entry = if index == 0 && path.is_ascii() {
            let head = line.get(..path.len())?;
            if !head.eq_ignore_ascii_case(path) {
                return None;
            }
            &line[path.len()..]
        } else {
            line
        };
        let entry = entry.trim();
        let (principal, rights) = entry.split_once(":(")?;
        if principal.is_empty() || rights.is_empty() {
            return None;
        }
        principals.push(principal.to_owned());
    }
    (!principals.is_empty()).then_some(principals)
}

/// All entries belong to `username`'s account (icacls prints `DOMAIN\name`).
///
/// Directories or objects with inheritance rules may have multiple ACEs
/// (e.g. direct full control plus container/object inheritance), all of which
/// must belong to the current user with no other principals present.
pub fn only_user(principals: &[String], username: &str) -> bool {
    !principals.is_empty()
        && principals.iter().all(|one| {
            one.rsplit('\\')
                .next()
                .is_some_and(|name| same_account_name(name, username))
        })
}

/// Case-insensitive ASCII account name comparison.
pub fn same_account_name(printed: &str, username: &str) -> bool {
    if printed.eq_ignore_ascii_case(username) {
        return true;
    }
    let shape = |text: &str| -> Vec<char> {
        text.chars()
            .map(|c| {
                if c.is_ascii() && c != '?' {
                    c.to_ascii_lowercase()
                } else {
                    '?'
                }
            })
            .collect()
    };
    !username.is_ascii() && shape(printed) == shape(username)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icacls_apply_args_removes_admin_and_system_and_grants_user() {
        let path = Path::new(r"C:\test\artifact.json");
        let args = icacls_apply_args(path, "alice");
        let rendered: Vec<String> = args
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(rendered[0], r"C:\test\artifact.json");
        assert_eq!(rendered[1], "/inheritance:r");
        assert_eq!(rendered[2], "/remove:g");
        assert_eq!(rendered[3], "*S-1-5-18");
        assert_eq!(rendered[4], "*S-1-5-32-544");
        assert_eq!(rendered[5], "/grant:r");
        assert_eq!(rendered[6], "alice:F");
    }

    #[test]
    fn acl_principals_parses_single_and_multi_principal_output() {
        let path = Path::new(r"C:\test\artifact.json");
        let sample =
            "C:\\test\\artifact.json DOMAIN\\alice:(F)\n\nSuccessfully processed 1 files;\n";
        let principals = acl_principals(sample, path).unwrap();
        assert_eq!(principals, vec!["DOMAIN\\alice"]);
        assert!(only_user(&principals, "alice"));
        assert!(!only_user(&principals, "bob"));

        let multi = "C:\\test\\artifact.json DOMAIN\\alice:(F)\n                     BUILTIN\\Users:(R)\n\n";
        let principals_multi = acl_principals(multi, path).unwrap();
        assert_eq!(principals_multi, vec!["DOMAIN\\alice", "BUILTIN\\Users"]);
        assert!(!only_user(&principals_multi, "alice"));

        let duplicate_user = vec!["DOMAIN\\alice".to_string(), "DOMAIN\\alice".to_string()];
        assert!(only_user(&duplicate_user, "alice"));
        assert!(!only_user(&duplicate_user, "bob"));
    }

    #[test]
    fn auto_remove_guard_cleans_up_unless_committed() {
        let temp_dir =
            std::env::temp_dir().join(format!("dynodoc-test-guard-{}", uuid::Uuid::new_v4()));
        create_private_dir(&temp_dir).unwrap();
        let target = temp_dir.join("partial.dynoarc");

        {
            let file = create_private_file(&target).unwrap();
            let guard = AutoRemoveFile::new(target.clone());
            drop(file);
            // Dropped without commit -> removed
            drop(guard);
        }
        assert!(!target.exists());

        {
            let file = create_private_file(&target).unwrap();
            let guard = AutoRemoveFile::new(target.clone());
            drop(file);
            guard.commit();
        }
        assert!(target.exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn permissive_umask_file_and_dir_creation_preserves_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        extern "C" {
            fn umask(mask: u32) -> u32;
        }

        let temp_dir =
            std::env::temp_dir().join(format!("dynodoc-test-umask-{}", uuid::Uuid::new_v4()));

        // Save current umask and set completely permissive 0o000 umask
        let old_umask = unsafe { umask(0o000) };
        let result = std::panic::catch_unwind(|| {
            create_private_dir(&temp_dir).unwrap();
            let dir_mode = std::fs::metadata(&temp_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                dir_mode, 0o700,
                "directory mode must be 0700 even with permissive umask"
            );

            let file_path = temp_dir.join("test-file.bin");
            let file = create_private_file(&file_path).unwrap();
            drop(file);

            let file_mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                file_mode, 0o600,
                "file mode must be 0600 even with permissive umask"
            );
        });
        // Restore umask immediately
        unsafe { umask(old_umask) };
        let _ = std::fs::remove_dir_all(&temp_dir);

        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn existing_files_dirs_and_symlinks_are_refused_and_left_intact() {
        let temp_dir =
            std::env::temp_dir().join(format!("dynodoc-test-refuse-{}", uuid::Uuid::new_v4()));
        create_private_dir(&temp_dir).unwrap();

        // 1. Existing regular file
        let existing_file = temp_dir.join("existing.bin");
        std::fs::write(&existing_file, b"untouchable content").unwrap();
        assert!(create_private_file(&existing_file).is_err());
        assert_eq!(
            std::fs::read(&existing_file).unwrap(),
            b"untouchable content"
        );

        // 2. Existing directory
        let existing_dir = temp_dir.join("subdir");
        create_private_dir(&existing_dir).unwrap();
        // Trying to create a file where a directory already exists
        assert!(create_private_file(&existing_dir).is_err());
        // Trying to create a private dir where a directory already exists
        assert!(create_private_dir(&existing_dir).is_err());

        // 3. Symlink on Unix
        #[cfg(unix)]
        {
            let target_file = temp_dir.join("target.bin");
            std::fs::write(&target_file, b"target content").unwrap();
            let symlink_path = temp_dir.join("symlink.bin");
            std::os::unix::fs::symlink(&target_file, &symlink_path).unwrap();

            // Refuses creating over existing symlink
            assert!(create_private_file(&symlink_path).is_err());
            // Target is untouched
            assert_eq!(std::fs::read(&target_file).unwrap(), b"target content");

            // Dangling symlink
            let dangling_symlink = temp_dir.join("dangling.bin");
            std::os::unix::fs::symlink(temp_dir.join("nonexistent.bin"), &dangling_symlink)
                .unwrap();
            assert!(create_private_file(&dangling_symlink).is_err());
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn injected_permission_or_parent_failure_fails_closed() {
        let temp_dir =
            std::env::temp_dir().join(format!("dynodoc-test-fail-{}", uuid::Uuid::new_v4()));
        create_private_dir(&temp_dir).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let readonly_dir = temp_dir.join("readonly");
            create_private_dir(&readonly_dir).unwrap();
            // Remove write permissions on readonly_dir
            std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o500))
                .unwrap();

            let target = readonly_dir.join("forbidden.bin");
            let err = create_private_file(&target);
            assert!(err.is_err());
            assert!(!target.exists());

            // Restore write permissions so cleanup succeeds
            std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }

        // Non-existent parent directory
        let bad_path = temp_dir.join("no_such_parent").join("child.bin");
        assert!(create_private_file(&bad_path).is_err());
        assert!(!bad_path.exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
