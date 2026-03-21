use std::io::Error;
use std::ptr;

use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY};

/// Returns true if the current process has admin rights, otherwise false.
pub(crate) fn is_app_elevated() -> bool {
    try_is_app_elevated().unwrap_or(false)
}

/// On success returns a bool indicating if the current process has admin rights.
/// Otherwise returns an OS error.
///
/// This is unlikely to fail but if it does it's even more unlikely that you have admin permissions anyway.
/// Therefore the public function above simply eats the error and returns a bool.
fn try_is_app_elevated() -> Result<bool, Error> {
    let token = QueryAccessToken::from_current_process()?;
    token.is_elevated()
}

/// A safe wrapper around querying Windows access tokens.
struct QueryAccessToken(HANDLE);

impl QueryAccessToken {
    fn from_current_process() -> Result<Self, Error> {
        unsafe {
            let mut handle: HANDLE = ptr::null_mut();
            let result = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle);

            if result != 0 {
                Ok(Self(handle))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    /// On success returns a bool indicating if the access token has elevated privileges.
    /// Otherwise returns an OS error.
    fn is_elevated(&self) -> Result<bool, Error> {
        unsafe {
            let mut elevation = TOKEN_ELEVATION::default();
            let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
            let mut ret_size = size;

            if GetTokenInformation(
                self.0,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                size,
                &mut ret_size,
            ) != 0
            {
                Ok(elevation.TokenIsElevated != 0)
            } else {
                Err(Error::last_os_error())
            }
        }
    }
}

impl Drop for QueryAccessToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}
