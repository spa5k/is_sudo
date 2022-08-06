//! [![crates.io](https://img.shields.io/crates/v/sudo?logo=rust)](https://crates.io/crates/sudo/)
//! [![docs.rs](https://docs.rs/sudo/badge.svg)](https://docs.rs/sudo)
//!
//! Detect if you are running as root, restart self with `sudo` if needed or setup uid zero when running with the SUID flag set.
//!
//! ## Requirements
//!
//! * The `sudo` program is required to be installed and setup correctly on the target system.
//! * Linux or Mac OS X tested
//!     * It should work on *BSD. However, it is not tested.
#![allow(clippy::bool_comparison)]

use crate::RunningAs::Root;
use crate::RunningAs::User;

/// Cross platform representation of the state the current program running
#[derive(Debug, PartialEq, Eq)]
pub enum RunningAs {
    /// Root (Linux/Mac OS/Unix) or Administrator (Windows)
    Root,
    /// Running as a normal user
    User,
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
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };

    match (uid, euid) {
        (0, 0) => Root,
        (_, _) => User,
    }
    //if uid == 0 { Root } else { User }
}

mod window;

// Use windows-rs crate to check admin permission in windows
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
    match window::check_main::is_app_elevated() {
        true => RunningAs::Root,
        false => RunningAs::User,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let c = check();
        println!("{:?}", c);
        assert!(true, "{:?}", c);
    }
}
