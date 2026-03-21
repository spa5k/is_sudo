#![allow(clippy::bool_comparison)]

/// Cross platform representation of the state the current program running
#[derive(Debug, PartialEq, Eq)]
pub enum RunningAs {
    /// Root (Linux/Mac OS/Unix) or Administrator (Windows)
    Root,
    /// Running as a normal user
    User,
}

#[cfg(windows)]
mod window;

#[cfg(any(test, unix))]
fn running_as_from_unix_ids(_uid: u32, euid: u32) -> RunningAs {
    if euid == 0 {
        RunningAs::Root
    } else {
        RunningAs::User
    }
}

#[cfg(any(test, windows))]
fn running_as_from_elevation(is_elevated: bool) -> RunningAs {
    if is_elevated {
        RunningAs::Root
    } else {
        RunningAs::User
    }
}

#[cfg(unix)]
/// This checks whether the current process is running as sudo or not.
/// Returns the RunningAs enum as result
/// # Examples
/// ```rust
/// use is_sudo::RunningAs;
/// let running_as = is_sudo::check();
/// match running_as {
///     RunningAs::Root => println!("Running as root"),
///     RunningAs::User => println!("Running as user"),
/// }
/// ```
pub fn check() -> RunningAs {
    let uid = unsafe { libc::getuid() } as u32;
    let euid = unsafe { libc::geteuid() } as u32;

    running_as_from_unix_ids(uid, euid)
}

#[cfg(windows)]
/// This checks whether the current process is running as admin(root) or not.
/// Returns the RunningAs enum as result
/// # Examples
/// ```rust
/// use is_sudo::RunningAs;
/// let running_as = is_sudo::check();
/// match running_as {
///     RunningAs::Root => println!("Running as root"),
///     RunningAs::User => println!("Running as user"),
/// }
/// ```
pub fn check() -> RunningAs {
    running_as_from_elevation(window::is_app_elevated())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_ids_report_root_for_root_process() {
        assert_eq!(running_as_from_unix_ids(0, 0), RunningAs::Root);
    }

    #[test]
    fn unix_ids_report_root_for_sudo_process() {
        assert_eq!(running_as_from_unix_ids(1000, 0), RunningAs::Root);
    }

    #[test]
    fn unix_ids_report_user_when_privileges_are_dropped() {
        assert_eq!(running_as_from_unix_ids(0, 1000), RunningAs::User);
    }

    #[test]
    fn unix_ids_report_user_for_regular_user() {
        assert_eq!(running_as_from_unix_ids(1000, 1000), RunningAs::User);
    }

    #[test]
    fn elevation_reports_root_when_process_is_elevated() {
        assert_eq!(running_as_from_elevation(true), RunningAs::Root);
    }

    #[test]
    fn elevation_reports_user_when_process_is_not_elevated() {
        assert_eq!(running_as_from_elevation(false), RunningAs::User);
    }

    #[cfg(unix)]
    #[test]
    fn check_matches_unix_helper() {
        let uid = unsafe { libc::getuid() } as u32;
        let euid = unsafe { libc::geteuid() } as u32;

        assert_eq!(check(), running_as_from_unix_ids(uid, euid));
    }
}
