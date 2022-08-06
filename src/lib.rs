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

#[cfg(unix)]
/// Cross platform representation of the state the current program running
#[derive(Debug, PartialEq, Eq)]
pub enum RunningAs {
    /// Root (Linux/Mac OS/Unix) or Administrator (Windows)
    Root,
    /// Running as a normal user
    User,
}

use RunningAs::*;

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

// Use windows-rs crate to check admin permission in windows
#[cfg(windows)]
/// This checks whether the current process is running as sudo or not.
/// Returns the RunningAs enum as result
/// # Examples
/// ```rust
/// use is_sudo::RunningAs;
/// let running_as = is_sudo::check();
/// match running_as {
///     RunningAs::Root => println!("Running as root"),
///     RunningAs::User => println!("Running as user"),
///  
/// }
/// ```
pub fn check() -> RunningAs {
    use windows_api::*;
    let mut token_handle = INVALID_HANDLE_VALUE;
    let result = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle);
    if result == 0 {
        return User;
    }
    let mut token_info = TOKEN_USER {
        User: SID_AND_ATTRIBUTES {
            Sid: SID {
                Revision: 0,
                SubAuthorityCount: 0,
                IdentifierAuthority: SID_IDENTIFIER_AUTHORITY {
                    Value: [0, 0, 0, 0, 0, 0],
                },
            },
            Attributes: 0,
        },
    };
    let token_info_size = std::mem::size_of::<TOKEN_USER>() as u32;
    let result = GetTokenInformation(
        token_handle,
        TokenUser,
        &mut token_info as *mut TOKEN_USER as *mut c_void,
        token_info_size,
        &mut token_info_size,
    );
    if result == 0 {
        return User;
    }
    let sid_size = std::mem::size_of::<SID>() as u32;
    let result = GetLengthSid(token_info.User.Sid);
    if result == 0 {
        return User;
    }
    let mut sid = vec![0u8; result as usize];
    let result = GetSidSubAuthority(token_info.User.Sid, 0, sid.as_mut_ptr() as *mut DWORD);
    if result == 0 {
        return User;
    }
    let result = if sid[0] == SECURITY_BUILTIN_DOMAIN_RID {
        GetSidSubAuthority(token_info.User.Sid, 1, sid.as_mut_ptr() as *mut DWORD)
    } else {
        GetSidSubAuthority(token_info.User.Sid, 0, sid.as_mut_ptr() as *mut DWORD)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let c = check();
        assert!(true, "{:?}", c);
    }
}
