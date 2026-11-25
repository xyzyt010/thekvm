//! UI preferences read from the OS: group policy inspection is out of
//! scope — this module exposes the two accessibility signals the product
//! actually honours.

/// DS-07: the OS "show animations" preference. On Windows this is the
/// shell's MinAnimate flag (0 = animations off); elsewhere the app
/// animates only when this returns false.
#[cfg(target_os = "windows")]
pub fn reduced_motion() -> bool {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegQueryValueExW, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_READ,
    };
    use windows::core::PCWSTR;
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let subkey = wide("Control Panel\\Desktop\\WindowMetrics");
    let name = wide("MinAnimate");
    let mut key = windows::Win32::System::Registry::HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return false;
    }
    let found: bool;
    let flag = unsafe {
        let mut buffer = [0u8; 4];
        let mut size = buffer.len() as u32;
        let mut value_type = windows::Win32::System::Registry::REG_VALUE_TYPE(0);
        let result = RegQueryValueExW(
            key,
            PCWSTR::from_raw(name.as_ptr()),
            None,
            Some(&mut value_type),
            Some(buffer.as_mut_ptr()),
            Some(&mut size),
        );
        found = result == ERROR_SUCCESS && size == 4;
        u32::from_ne_bytes(buffer)
    };
    unsafe {
        let _ = RegCloseKey(key);
    };
    if !found {
        return false;
    }
    flag == 0
}

#[cfg(not(target_os = "windows"))]
pub fn reduced_motion() -> bool {
    false
}
