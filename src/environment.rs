use anyhow::{anyhow, Result};
use std::ffi::{CString, OsString};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::System::Environment::{GetEnvironmentVariableW, SetEnvironmentVariableW};
use windows_sys::Win32::System::ProcessStatus::{K32GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/// Represents environment manipulation capabilities for a process
pub struct ProcessEnvironment {
    process_id: u32,
    process_handle: HANDLE,
}

impl ProcessEnvironment {
    /// Creates a new ProcessEnvironment instance for the specified process
    pub fn new(process_id: u32) -> Result<Self> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        Ok(Self {
            process_id,
            process_handle,
        })
    }

    /// Gets all environment variables for the current process
    pub fn get_all_env_vars() -> Result<Vec<(String, String)>> {
        let mut env_vars = Vec::new();
        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;

        unsafe {
            let result = GetEnvironmentVariableW(
                ptr::null(),
                buffer.as_mut_ptr(),
                &mut size,
            );

            if result == 0 {
                return Err(anyhow!("Failed to get environment variables"));
            }

            let env_block = String::from_utf16_lossy(&buffer[..size as usize]);
            for line in env_block.split('\0') {
                if let Some((name, value)) = line.split_once('=') {
                    env_vars.push((name.to_string(), value.to_string()));
                }
            }
        }

        Ok(env_vars)
    }

    /// Gets a specific environment variable
    pub fn get_env_var(name: &str) -> Result<String> {
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;

        unsafe {
            let result = GetEnvironmentVariableW(
                name_wide.as_ptr(),
                buffer.as_mut_ptr(),
                &mut size,
            );

            if result == 0 {
                return Err(anyhow!("Failed to get environment variable"));
            }

            Ok(String::from_utf16_lossy(&buffer[..size as usize]))
        }
    }

    /// Sets an environment variable
    pub fn set_env_var(name: &str, value: &str) -> Result<()> {
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let value_wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            if SetEnvironmentVariableW(name_wide.as_ptr(), value_wide.as_ptr()) == 0 {
                return Err(anyhow!("Failed to set environment variable"));
            }
        }

        Ok(())
    }

    /// Removes an environment variable
    pub fn remove_env_var(name: &str) -> Result<()> {
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            if SetEnvironmentVariableW(name_wide.as_ptr(), ptr::null()) == 0 {
                return Err(anyhow!("Failed to remove environment variable"));
            }
        }

        Ok(())
    }

    /// Gets the PATH environment variable
    pub fn get_path() -> Result<Vec<String>> {
        let path = Self::get_env_var("PATH")?;
        Ok(path.split(';').map(|s| s.to_string()).collect())
    }

    /// Adds a directory to the PATH environment variable
    pub fn add_to_path(dir: &str) -> Result<()> {
        let mut path = Self::get_path()?;
        if !path.contains(&dir.to_string()) {
            path.push(dir.to_string());
            Self::set_env_var("PATH", &path.join(";"))?;
        }
        Ok(())
    }

    /// Removes a directory from the PATH environment variable
    pub fn remove_from_path(dir: &str) -> Result<()> {
        let mut path = Self::get_path()?;
        path.retain(|d| d != dir);
        Self::set_env_var("PATH", &path.join(";"))?;
        Ok(())
    }

    /// Gets the current working directory
    pub fn get_current_dir() -> Result<String> {
        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;

        unsafe {
            let result = GetEnvironmentVariableW(
                "CD".encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>().as_ptr(),
                buffer.as_mut_ptr(),
                &mut size,
            );

            if result == 0 {
                return Err(anyhow!("Failed to get current directory"));
            }

            Ok(String::from_utf16_lossy(&buffer[..size as usize]))
        }
    }

    /// Sets the current working directory
    pub fn set_current_dir(dir: &str) -> Result<()> {
        Self::set_env_var("CD", dir)
    }

    /// Gets the system drive
    pub fn get_system_drive() -> Result<String> {
        Self::get_env_var("SystemDrive")
    }

    /// Gets the system root directory
    pub fn get_system_root() -> Result<String> {
        Self::get_env_var("SystemRoot")
    }

    /// Gets the user profile directory
    pub fn get_user_profile() -> Result<String> {
        Self::get_env_var("USERPROFILE")
    }

    /// Gets the temporary directory
    pub fn get_temp_dir() -> Result<String> {
        Self::get_env_var("TEMP")
    }

    /// Gets the OS name
    pub fn get_os_name() -> Result<String> {
        Self::get_env_var("OS")
    }

    /// Gets the processor architecture
    pub fn get_processor_architecture() -> Result<String> {
        Self::get_env_var("PROCESSOR_ARCHITECTURE")
    }

    /// Gets the number of processors
    pub fn get_processor_count() -> Result<String> {
        Self::get_env_var("NUMBER_OF_PROCESSORS")
    }

    /// Gets the computer name
    pub fn get_computer_name() -> Result<String> {
        Self::get_env_var("COMPUTERNAME")
    }

    /// Gets the user name
    pub fn get_user_name() -> Result<String> {
        Self::get_env_var("USERNAME")
    }

    /// Gets the domain name
    pub fn get_domain_name() -> Result<String> {
        Self::get_env_var("USERDOMAIN")
    }
}

impl Drop for ProcessEnvironment {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_handle);
        }
    }
} 