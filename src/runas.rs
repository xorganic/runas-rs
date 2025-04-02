use anyhow::{bail, Result};
use core::{
    ptr,
    ffi::c_void,
    ops::BitOr,
    mem::{zeroed, size_of}, 
    ptr::{null, null_mut},
};

use std::{
    ffi::OsStr, 
    os::windows::ffi::OsStrExt
};

use crate::{
    sid::get_user_sid,
    acl::{Acl, Object}, 
    pipe::Pipe,
};

use windows_sys::{
    core::w, 
    Win32::Storage::FileSystem::{
        READ_CONTROL, WRITE_DAC
    },
    Win32::System::Threading::{
        OpenProcess, OpenThread, SuspendThread, ResumeThread, PROCESS_SUSPEND_RESUME, 
        PROCESS_QUERY_INFORMATION, THREAD_SUSPEND_RESUME, OpenProcessToken,
        ImpersonateLoggedOnUser, RevertToSelf, DuplicateTokenEx, LookupPrivilegeNameW,
        AdjustTokenPrivileges, CreateEnvironmentBlock, DestroyEnvironmentBlock,
        GetEnvironmentStringsW, GetUserObjectInformationW, GetSidSubAuthorityCount,
        GetSidSubAuthority, GetTokenInformation, TokenIntegrityLevel,
        security_mandatory_low_rid, security_mandatory_medium_rid,
        security_mandatory_high_rid, security_mandatory_system_rid
    },
    Win32::Foundation::{CloseHandle, GetLastError, TRUE, FALSE},
    Win32::Security::{
        GetTokenInformation, SetTokenInformation, TokenUser, TokenGroups, TokenPrivileges,
        TokenSource, TokenType, TokenImpersonationLevel, TOKEN_QUERY, TOKEN_QUERY_SOURCE,
        TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_PRIVILEGES, TOKEN_SOURCE,
        TOKEN_TYPE, TOKEN_IMPERSONATION_LEVEL, TOKEN_USER, TOKEN_GROUPS, TOKEN_PRIVILEGES,
        TOKEN_SOURCE_LENGTH, TOKEN_SOURCE_LENGTH as TOKEN_SOURCE_LENGTH_CONST,
    },
    Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, 
        TH32CS_SNAPTHREAD, INVALID_HANDLE_VALUE
    },
};

/// Represents a security context for a process or thread
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// The process or thread ID
    pub id: u32,
    /// The user SID associated with the context
    pub user_sid: Vec<u8>,
    /// The integrity level of the context
    pub integrity_level: u32,
    /// The privileges available in the context
    pub privileges: Vec<u8>,
    /// The groups associated with the context
    pub groups: Vec<u8>,
    /// The impersonation level of the context
    pub impersonation_level: u32,
    /// The source name of the token
    pub source_name: String,
    /// The source identifier of the token
    pub source_identifier: windows_sys::Win32::Foundation::LUID,
    /// The type of the token
    pub token_type: u32,
    /// The group SIDs associated with the context
    pub group_sids: Vec<u8>,
}

impl SecurityContext {
    /// Creates a new security context
    pub fn new(id: u32) -> Self {
        SecurityContext {
            id,
            user_sid: Vec::new(),
            integrity_level: 0,
            privileges: Vec::new(),
            groups: Vec::new(),
            impersonation_level: 0,
            source_name: String::new(),
            source_identifier: windows_sys::Win32::Foundation::LUID { LowPart: 0, HighPart: 0 },
            token_type: 0,
            group_sids: Vec::new(),
        }
    }

    /// Gets the security context for a process
    pub fn get_process_context(pid: u32) -> Result<Self> {
        unsafe {
            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if process_handle == 0 {
                bail!("Failed to open process");
            }

            let mut token_handle = 0;
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle) == 0 {
                CloseHandle(process_handle);
                bail!("Failed to open process token");
            }

            let mut context = SecurityContext::new(pid);
            
            // Get user SID
            let mut token_user: TOKEN_USER = zeroed();
            let mut return_length = 0;
            if GetTokenInformation(
                token_handle,
                TokenUser,
                &mut token_user as *mut _ as *mut _,
                size_of::<TOKEN_USER>() as u32,
                &mut return_length,
            ) == 0 {
                CloseHandle(token_handle);
                CloseHandle(process_handle);
                bail!("Failed to get token user information");
            }
            
            // Get integrity level
            let mut integrity_level = 0;
            let mut return_length = 0;
            if GetTokenInformation(
                token_handle,
                TokenIntegrityLevel,
                &mut integrity_level as *mut _ as *mut _,
                size_of::<u32>() as u32,
                &mut return_length,
            ) == 0 {
                CloseHandle(token_handle);
                CloseHandle(process_handle);
                bail!("Failed to get token integrity level");
            }
            context.integrity_level = integrity_level;

            // Get privileges
            let mut privileges: TOKEN_PRIVILEGES = zeroed();
            let mut return_length = 0;
            if GetTokenInformation(
                token_handle,
                TokenPrivileges,
                &mut privileges as *mut _ as *mut _,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut return_length,
            ) == 0 {
                CloseHandle(token_handle);
                CloseHandle(process_handle);
                bail!("Failed to get token privileges");
            }

            // Get groups
            let mut groups: TOKEN_GROUPS = zeroed();
            let mut return_length = 0;
            if GetTokenInformation(
                token_handle,
                TokenGroups,
                &mut groups as *mut _ as *mut _,
                size_of::<TOKEN_GROUPS>() as u32,
                &mut return_length,
            ) == 0 {
                CloseHandle(token_handle);
                CloseHandle(process_handle);
                bail!("Failed to get token groups");
            }

            // Get impersonation level
            let mut impersonation_level = 0;
            let mut return_length = 0;
            if GetTokenInformation(
                token_handle,
                TokenImpersonationLevel,
                &mut impersonation_level as *mut _ as *mut _,
                size_of::<u32>() as u32,
                &mut return_length,
            ) == 0 {
                CloseHandle(token_handle);
                CloseHandle(process_handle);
                bail!("Failed to get token impersonation level");
            }
            context.impersonation_level = impersonation_level;

            CloseHandle(token_handle);
            CloseHandle(process_handle);

            Ok(context)
        }
    }

    /// Sets the security context for a process
    pub fn set_process_context(&self, pid: u32) -> Result<()> {
        unsafe {
            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, pid);
            if process_handle == 0 {
                bail!("Failed to open process");
            }

            let mut token_handle = 0;
            if OpenProcessToken(process_handle, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &mut token_handle) == 0 {
                CloseHandle(process_handle);
                bail!("Failed to open process token");
            }

            // Set integrity level
            if SetTokenInformation(
                token_handle,
                TokenIntegrityLevel,
                &self.integrity_level as *const _ as *const _,
                size_of::<u32>() as u32,
            ) == 0 {
                CloseHandle(token_handle);
                CloseHandle(process_handle);
                bail!("Failed to set token integrity level");
            }

            CloseHandle(token_handle);
            CloseHandle(process_handle);

            Ok(())
        }
    }

    /// Gets the integrity level of a process
    pub fn get_integrity_level(pid: u32) -> Result<u32> {
        let context = SecurityContext::get_process_context(pid)?;
        Ok(context.integrity_level)
    }

    /// Sets the integrity level of a process
    pub fn set_integrity_level(pid: u32, level: u32) -> Result<()> {
        let mut context = SecurityContext::get_process_context(pid)?;
        context.integrity_level = level;
        context.set_process_context(pid)
    }

    /// Checks if a process has a specific privilege
    pub fn has_privilege(pid: u32, privilege: &str) -> Result<bool> {
        let context = SecurityContext::get_process_context(pid)?;
        Ok(context.privileges.iter().any(|p| p == privilege))
    }

    /// Enables a privilege for a process
    pub fn enable_privilege(pid: u32, privilege: &str) -> Result<()> {
        unsafe {
            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if process_handle == 0 {
                bail!("Failed to open process");
            }

            let mut token_handle = 0;
            if OpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token_handle) == 0 {
                CloseHandle(process_handle);
                bail!("Failed to open process token");
            }

            let privilege_name = std::ffi::CString::new(privilege).unwrap();
            let mut privilege_value = 0;
            if LookupPrivilegeValueW(
                null(),
                privilege_name.as_ptr() as *const i8,
                &mut privilege_value,
            ) == 0 {
                CloseHandle(token_handle);
                CloseHandle(process_handle);
                bail!("Failed to lookup privilege value");
            }

            let mut new_privileges: TOKEN_PRIVILEGES = zeroed();
            new_privileges.PrivilegeCount = 1;
            new_privileges.Privileges[0].Luid.LowPart = privilege_value as u32;
            new_privileges.Privileges[0].Luid.HighPart = 0;
            new_privileges.Privileges[0].Attributes = 2; // SE_PRIVILEGE_ENABLED

            if AdjustTokenPrivileges(
                token_handle,
                FALSE,
                &mut new_privileges,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                null_mut(),
                null_mut(),
            ) == 0 {
                CloseHandle(token_handle);
                CloseHandle(process_handle);
                bail!("Failed to adjust token privileges");
            }

            CloseHandle(token_handle);
            CloseHandle(process_handle);

            Ok(())
        }
    }

    /// Gets a predefined integrity level constant
    pub fn get_integrity_level_constant(level: &str) -> u32 {
        match level.to_lowercase().as_str() {
            "low" => security_mandatory_low_rid,
            "medium" => security_mandatory_medium_rid,
            "high" => security_mandatory_high_rid,
            "system" => security_mandatory_system_rid,
            _ => security_mandatory_medium_rid,
        }
    }

    /// Impersonates a user token
    pub fn impersonate_token(&self, token_handle: isize) -> Result<()> {
        unsafe {
            if ImpersonateLoggedOnUser(token_handle) == 0 {
                bail!("Failed to impersonate token");
            }
            Ok(())
        }
    }

    /// Reverts impersonation
    pub fn revert_impersonation() -> Result<()> {
        unsafe {
            if RevertToSelf() == 0 {
                bail!("Failed to revert impersonation");
            }
            Ok(())
        }
    }

    /// Duplicates a token with specified access rights and impersonation level
    pub fn duplicate_token(
        source_token: isize,
        access_rights: u32,
        impersonation_level: u32,
    ) -> Result<isize> {
        unsafe {
            let mut new_token = 0;
            if DuplicateTokenEx(
                source_token,
                access_rights,
                null_mut(),
                impersonation_level,
                &mut new_token,
            ) == 0 {
                bail!("Failed to duplicate token");
            }
            Ok(new_token)
        }
    }
}

/// Represents bitwise options for running processes with specific settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Options(pub u32);

impl Options {
    /// Option to indicate that the environment should be loaded (`/env`).
    pub const Env: Options = Options(0b00000001);

    /// Option to specify that the user profile should not be loaded (`/noprofile`).
    pub const NoProfile: Options = Options(0b00000010);

    /// Option to specify that the user profile should be loaded (`/profile`).
    pub const Profile: Options = Options(0b0000100);

    /// Option to specify that credentials should only be used for remote access (`/netonly`).
    pub const NetOnly: Options = Options(0b00001000);
    
    /// Option to create the process with a new console window.
    pub const NewConsole: Options = Options(0b00010000);
    
    /// Option to create the process with a new process group.
    pub const NewProcessGroup: Options = Options(0b00100000);
    
    /// Option to create the process with a new window.
    pub const NewWindow: Options = Options(0b01000000);
    
    /// Option to create the process with a suspended main thread.
    pub const Suspended: Options = Options(0b10000000);
    
    /// Option to create the process with a debug flag.
    pub const DebugProcess: Options = Options(0b100000000);
    
    /// Option to create the process with a debug flag for child processes.
    pub const DebugOnlyThisProcess: Options = Options(0b1000000000);
    
    /// Option to create the process with a protected process flag.
    pub const ProtectedProcess: Options = Options(0b10000000000);

    /// Checks if the current [`Options`] instance contains the specified option.
    ///
    /// # Parameters
    ///
    /// * `other` - Another `Options` instance to check against.
    ///
    /// # Returns
    ///
    /// * `true` if the current instance includes the `other` option, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let opts = Options::Env | Options::NetOnly;
    /// assert!(opts.contains(Options::Env));
    /// assert!(opts.contains(Options::NetOnly));
    /// ``` 
    fn contains(self, other: Options) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for Options {
    type Output = Self;

    /// Combines two [`Options`] instances using a bitwise OR operation.
    ///
    /// # Parameters
    ///
    /// * `rhs` - The right-hand side `Options` instance.
    ///
    /// # Returns
    ///
    /// * A new [`Options`] instance that represents the combination of both options.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let combined = Options::Env | Options::NetOnly;
    /// assert!(combined.contains(Options::Env));
    /// assert!(combined.contains(Options::NetOnly));
    /// ```
    fn bitor(self, rhs: Self) -> Self::Output {
        Options(self.0 | rhs.0)
    }
}

/// A struct to execute processes under a different user account.
/// 
/// This struct allows running commands as another user, setting up necessary permissions, 
/// and ensuring the security context is properly configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runas<'a> {
    /// The username of the target account.
    username: &'a str,
    
    /// The password for the account.
    password: &'a str,
    
    /// The domain of the user (optional, defaults to an empty string).
    domain: &'a str,

    /// If true, loads the user environment.
    env: *mut c_void,

    /// Flags for logon operations (such as `/netonly`, `/profile` or `/noprofile`).
    logon_flags: u32,

    /// The type of logon operation to perform.
    logon_type: u32,

    /// Specifies the logon provider.
    provider: u32,

    /// Flags for process creation (such as creating with environment variables).
    creation_flags: u32
}

impl Default for Runas<'_> {
    /// Provides a default-initialized `Runas`.
    ///
    /// # Returns
    ///
    /// * A default-initialized `Runas`.
    fn default() -> Self {
        Self {
            username: "",
            password: "",
            domain: ".",
            env: null_mut(),
            logon_flags: 0,
            creation_flags: 0,
            logon_type: LOGON32_LOGON_INTERACTIVE,
            provider: LOGON32_PROVIDER_DEFAULT
        }
    }
}

impl<'a> Runas<'a> {
    /// Creates a new [`Runas`] instance with user credentials.
    ///
    /// # Parameters
    ///
    /// * `username` - The name of the user account.
    /// * `password` - The password associated with the account.
    /// * `domain` - (Optional) The domain of the user. Defaults to an empty string.
    ///
    /// # Returns
    ///
    /// * Returns a new [`Runas`] instance configured with the given credentials.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let runas = Runas::new("example", "example", None);
    /// ```
    pub fn new(
        username: &'a str, 
        password: &'a str, 
        domain: Option<&'a str>
    ) -> Self {
        Self {
            username,
            password,
            domain: domain.unwrap_or("."),
            ..Default::default()
        }
    }
    
    /// Sets the options for the [`Runas`] instance.
    ///
    /// This function allows the user to configure environment loading and 
    /// saving credentials using the [`Options`] bitflags.
    ///
    /// # Parameters
    ///
    /// * `flags` - A combination of [`Options`] flags.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let runas = Runas::new("example", "example", None)
    ///     .options(Options::Env | Options::Profile)?;
    /// ```
    pub fn options(mut self, flags: Options) -> Result<Self> {
        if flags.contains(Options::Profile) && flags.contains(Options::NoProfile) {
            bail!("`/profile` is not compatible with `/noprofile`");
        }

        if flags.contains(Options::Profile) && flags.contains(Options::NetOnly) {
            bail!("`/profile` is not compatible with `/netonly`");
        }

        if flags.contains(Options::Profile) {
            self.logon_flags = LOGON_WITH_PROFILE;
        } else if flags.contains(Options::NoProfile) {
            self.logon_flags &= !LOGON_WITH_PROFILE;
        }

        if flags.contains(Options::NetOnly) {
            self.logon_flags |= LOGON_NETCREDENTIALS_ONLY;
            self.logon_type = LOGON32_LOGON_NEW_CREDENTIALS;
            self.provider = LOGON32_PROVIDER_WINNT50
        }

        if flags.contains(Options::Env) {
            self.env = unsafe { GetEnvironmentStringsW().cast() };
            self.creation_flags = CREATE_UNICODE_ENVIRONMENT;
        }
        
        // Process creation options
        if flags.contains(Options::NewConsole) {
            self.creation_flags |= CREATE_NEW_CONSOLE;
        }
        
        if flags.contains(Options::NewProcessGroup) {
            self.creation_flags |= CREATE_NEW_PROCESS_GROUP;
        }
        
        if flags.contains(Options::NewWindow) {
            self.creation_flags |= CREATE_NEW_WINDOW;
        }
        
        if flags.contains(Options::Suspended) {
            self.creation_flags |= CREATE_SUSPENDED;
        }
        
        if flags.contains(Options::DebugProcess) {
            self.creation_flags |= DEBUG_PROCESS;
        }
        
        if flags.contains(Options::DebugOnlyThisProcess) {
            self.creation_flags |= DEBUG_ONLY_THIS_PROCESS;
        }
        
        if flags.contains(Options::ProtectedProcess) {
            self.creation_flags |= CREATE_PROTECTED_PROCESS;
        }

        Ok(self)
    }

    /// This function logs in with the provided credentials and runs the given command.
    ///
    /// # Parameters
    ///
    /// * `command` - The path to the executable that should be run.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Command output (if available).
    /// * `Err(anyhow::Error)` - If any Windows API call fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// runas.run("cmd.exe /c whoami")?;
    /// ```
    pub fn run(&mut self, command: &str) -> Result<String> {
        unsafe {
            // Configure access control for the user's window station and desktop
            let desktop = self.configure()?;
            let mut desktop_wide = desktop.as_str().to_pwstr();

            // Create a pipe for interprocess communication (to capture output / error)
            let (read, write) = Pipe::create()?;
            let mut pi = zeroed::<PROCESS_INFORMATION>();
            let si = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                lpDesktop: desktop_wide.as_mut_ptr(),
                hStdOutput: write,
                hStdError: write,
                dwFlags: STARTF_USESTDHANDLES,
                ..zeroed()
            };

            // Convert username, domain, password and command to wide strings (UTF-16)
            let username = self.username.to_pwstr();
            let domain = self.domain.to_pwstr();
            let password = self.password.to_pwstr();
            let mut command = command.to_pwstr();

            // Create an output handler with default options
            let mut output_handler = OutputHandler::new(OutputOptions::default())
                .with_command(command.to_string_lossy().to_string())
                .with_start_time(std::time::SystemTime::now());

            match self.default_process()? {
                CreateProcessFunction::CreateProcessAsUser => {
                    // Authenticate user and obtain token
                    let mut h_token = null_mut();
                    if LogonUserW(username.as_ptr(), domain.as_ptr(), password.as_ptr(), self.logon_type, self.provider, &mut h_token) == FALSE {
                        bail!("LogonUserW Failed With Error [CreateProcessAsUser]: {}", GetLastError());
                    }

                    // Enabling the privilege
                    if !Token::enable_privilege("SeAssignPrimaryTokenPrivilege")? {
                        bail!("Error enabling privilege SeAssignPrimaryTokenPrivilege");
                    }

                    // Duplicate the token to ensure it's a primary token
                    let mut h_duptoken = null_mut();
                    if DuplicateTokenEx(h_token, TOKEN_ALL_ACCESS, null(), SecurityImpersonation, TokenPrimary, &mut h_duptoken) == FALSE {
                        bail!("DuplicateTokenEx Failed With Error [CreateProcessAsUser]: {}", GetLastError());
                    }

                    // Create a new environment block for the user represented by the duplicated token.
                    if self.env.is_null() {
                        if CreateEnvironmentBlock(&mut self.env, h_duptoken, FALSE) == FALSE {
                            bail!("CreateEnvironmentBlock Failed With Error: {}", GetLastError());
                        }
                    }

                    // Launch the new process in the user's session using the duplicated token.
                    let dir = format!("{}\\System32", std::env::var("SystemRoot")?).as_str().to_pwstr();
                    if CreateProcessAsUserW(
                        h_duptoken, 
                        null(),
                        command.as_mut_ptr(), 
                        null_mut(), 
                        null_mut(), 
                        TRUE, 
                        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, 
                        self.env, 
                        dir.as_ptr(), 
                        &si, 
                        &mut pi
                    ) == FALSE {
                        bail!("CreateProcessAsUserW Failed With Error: {}", GetLastError());
                    }
                },
                CreateProcessFunction::CreateProcessWithToken => {
                    // Authenticate user and obtain token
                    let mut h_token = null_mut();
                    if LogonUserW(username.as_ptr(), domain.as_ptr(), password.as_ptr(), self.logon_type, self.provider, &mut h_token) == FALSE {
                        bail!("LogonUserW Failed With Error [CreateProcessWithToken]: {}", GetLastError());
                    }

                    // Enabling the privilege
                    if !Token::enable_privilege("SeImpersonatePrivilege")? {
                        bail!("Error enabling privilege SeImpersonatePrivilege");
                    }

                    // Duplicate the token to ensure it's a primary token
                    let mut h_duptoken = null_mut();
                    if DuplicateTokenEx(h_token, TOKEN_ALL_ACCESS, null(), SecurityImpersonation, TokenPrimary, &mut h_duptoken) == FALSE {
                        bail!("DuplicateTokenEx Failed With Error [CreateProcessWithToken]: {}", GetLastError());
                    }

                    // Launch the process with the duplicated token
                    if CreateProcessWithTokenW(
                        h_duptoken, 
                        self.logon_flags,
                        null(), 
                        command.as_mut_ptr(), 
                        CREATE_NO_WINDOW | self.creation_flags, 
                        self.env, 
                        null_mut(),
                        &si,
                        &mut pi,
                    ) == FALSE {
                        bail!("CreateProcessWithTokenW Failed With Error: {}", GetLastError());
                    }
                },
                CreateProcessFunction::CreateProcessWithLogon => {
                    // Create a new process using the specified user's credential
                    if CreateProcessWithLogonW(
                        username.as_ptr(),
                        domain.as_ptr(),
                        password.as_ptr(),
                        self.logon_flags,
                        null_mut(),
                        command.as_mut_ptr(),
                        CREATE_NO_WINDOW | self.creation_flags,
                        self.env,
                        null_mut(),
                        &si,
                        &mut pi,
                    ) == FALSE {               
                        bail!("CreateProcessWithLogonW Failed With Error: {}", GetLastError());
                    }
                }
            }

            // Set the process handle and PID in the output handler
            output_handler = output_handler
                .with_process_handle(pi.hProcess)
                .with_pid(pi.dwProcessId);

            // Close the write handle
            CloseHandle(write);

            // Wait for the process to complete
            output_handler.wait_for_completion()?;

            // Capture the output
            output_handler.capture_output(read)?;

            // Close the read handle
            CloseHandle(read);

            // Close the process handle
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            // Return the formatted output
            Ok(output_handler.get_formatted_output())
        }
    }

    /// Configures access control for the user's window station and desktop.
    ///
    /// This function ensures that the specified user has the necessary permissions
    /// to interact with the window station and desktop.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The configured window station name.
    /// * `Err(anyhow::Error)` - If any API call fails.
    fn configure(&self) -> Result<String> {
        let name = self.get_windows_station()?;
        let station_name = name.as_str().to_pwstr();
        unsafe {
            // Get the handle of the current process's window station
            let old_hwinsta = GetProcessWindowStation();
            
            // Open the specified window station with READ_CONTROL and WRITE_DAC permissions
            let h_winsta = OpenWindowStationW(
                station_name.as_ptr(),
                FALSE,
                READ_CONTROL | WRITE_DAC,
            );

            if h_winsta.is_null() {
                bail!("OpenWindowStationW Failed With Error: {}", GetLastError());
            }

            // Set the opened window station as the current process's window station
            SetProcessWindowStation(h_winsta);

            // Open the default desktop with the necessary permissions
            let h_desktop = OpenDesktopW(
                w!("Default"),
                0,
                FALSE,
                DESKTOP_READ_CONTROL | DESKTOP_WRITE_DAC | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS,
            );

            if h_desktop.is_null() {
                bail!("OpenDesktopW Failed With Error: {}", GetLastError());
            }

            // Restore the original window station to the process
            SetProcessWindowStation(old_hwinsta);
            
            // Retrieve the security identifier (SID) for the user
            let mut user_sid = get_user_sid(&self.username, &self.domain)?;

            // Add the necessary access control entries (ACEs) for the window station and desktop (If it doesn't exist)
            let mut acl_station = Acl::new(h_winsta, &mut user_sid, Object::WindowsStation);
            if !acl_station.check_permissions()? {
                acl_station.add_ace()?;
            }

            let mut acl_desktop = Acl::new(h_desktop, &mut user_sid, Object::Desktop);
            if !acl_desktop.check_permissions()? {
                acl_desktop.add_ace()?;
            }

            CloseWindowStation(h_winsta);
            CloseDesktop(h_desktop);

            Ok(format!("{name}\\Default"))
        }
    }
    
    /// Decides which process creation API should be used based on privileges and integrity.
    /// 
    /// * [`CreateProcessAsUser`] — If `SeAssignPrimaryTokenPrivilege` is present and integrity is Medium or higher
    /// * [`CreateProcessWithToken`] — If `SeImpersonatePrivilege` is present and integrity is High or higher
    /// * [`CreateProcessWithLogon`] — Default/fallback method
    ///
    /// # Returns
    ///
    /// * `Ok(CreateProcessFunction)` - Enum indicating the best available API for process creation
    /// * `Err(anyhow::Error)` - If privilege or integrity detection fails
    fn default_process(&self) -> Result<CreateProcessFunction> {
        let integrity = Token::integrity_level()?;
        let se_impersonate = Token::has_privilege("SeImpersonatePrivilege")?;
        let se_assign = Token::has_privilege("SeAssignPrimaryTokenPrivilege")?;
        
        if se_assign && matches!(integrity, "Medium" | "High" | "System") {
            Ok(CreateProcessFunction::CreateProcessAsUser)
        } else if se_impersonate && matches!(integrity, "High" | "System") {
            Ok(CreateProcessFunction::CreateProcessWithToken)
        } else {
            Ok(CreateProcessFunction::CreateProcessWithLogon)
        }
    }

    /// Retrieves the name of the current Windows station.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The name of the current Windows station.
    /// * `Err(anyhow::Error)` - If the function fails to retrieve the station name.
    fn get_windows_station(&self) -> Result<String> {
        // Get a handle to the current process's window station
        let h_winsta = unsafe { GetProcessWindowStation() };
        if h_winsta.is_null() {
            bail!("GetProcessWindowStation Failed With Error: {}", unsafe { GetLastError() });
        }

        // Retrieve the name of the window station using GetUserObjectInformationW
        let mut buffer = vec![0u16; 256];
        let mut len = 0;
        if unsafe { 
            GetUserObjectInformationW(
                h_winsta,
                UOI_NAME,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 2) as u32,
                &mut len,
            ) 
        } == FALSE {
            bail!("GetUserObjectInformationW Failed With Error: {}", unsafe { GetLastError() });
        }

        // Convert UTF-16 buffer into a Rust `String` and return
        let len = (len / 2) as usize - 1;
        buffer.truncate(len);

        Ok(String::from_utf16_lossy(&buffer))
    }

    /// Suspends a process by its process ID
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID of the process to suspend
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the process was successfully suspended
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// runas.suspend_process(1234)?;
    /// ```
    pub fn suspend_process(&self, pid: u32) -> Result<()> {
        unsafe {
            // Open the process with the necessary access rights
            let process_handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
            if process_handle.is_null() {
                bail!("OpenProcess Failed With Error: {}", GetLastError());
            }

            // Suspend the process
            let result = SuspendThread(process_handle);
            if result == -1 {
                CloseHandle(process_handle);
                bail!("SuspendThread Failed With Error: {}", GetLastError());
            }

            // Close the process handle
            CloseHandle(process_handle);
            Ok(())
        }
    }

    /// Resumes a suspended process by its process ID
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID of the process to resume
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the process was successfully resumed
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// runas.resume_process(1234)?;
    /// ```
    pub fn resume_process(&self, pid: u32) -> Result<()> {
        unsafe {
            // Open the process with the necessary access rights
            let process_handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
            if process_handle.is_null() {
                bail!("OpenProcess Failed With Error: {}", GetLastError());
            }

            // Resume the process
            let result = ResumeThread(process_handle);
            if result == -1 {
                CloseHandle(process_handle);
                bail!("ResumeThread Failed With Error: {}", GetLastError());
            }

            // Close the process handle
            CloseHandle(process_handle);
            Ok(())
        }
    }

    /// Suspends all threads in a process by its process ID
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID of the process whose threads should be suspended
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all threads were successfully suspended
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// runas.suspend_all_threads(1234)?;
    /// ```
    pub fn suspend_all_threads(&self, pid: u32) -> Result<()> {
        unsafe {
            // Open the process with the necessary access rights
            let process_handle = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if process_handle.is_null() {
                bail!("OpenProcess Failed With Error: {}", GetLastError());
            }

            // Get a snapshot of all threads in the system
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                CloseHandle(process_handle);
                bail!("CreateToolhelp32Snapshot Failed With Error: {}", GetLastError());
            }

            // Initialize the thread entry structure
            let mut thread_entry = THREADENTRY32 {
                dwSize: size_of::<THREADENTRY32>() as u32,
                ..zeroed()
            };

            // Iterate through all threads
            if Thread32First(snapshot, &mut thread_entry) == TRUE {
                loop {
                    // Check if the thread belongs to our target process
                    if thread_entry.th32OwnerProcessID == pid {
                        // Open the thread with the necessary access rights
                        let thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
                        if !thread_handle.is_null() {
                            // Suspend the thread
                            let result = SuspendThread(thread_handle);
                            if result == -1 {
                                CloseHandle(thread_handle);
                                CloseHandle(process_handle);
                                CloseHandle(snapshot);
                                bail!("SuspendThread Failed With Error: {}", GetLastError());
                            }
                            CloseHandle(thread_handle);
                        }
                    }

                    // Move to the next thread
                    if Thread32Next(snapshot, &mut thread_entry) == FALSE {
                        break;
                    }
                }
            }

            // Clean up
            CloseHandle(snapshot);
            CloseHandle(process_handle);
            Ok(())
        }
    }

    /// Resumes all threads in a process by its process ID
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID of the process whose threads should be resumed
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all threads were successfully resumed
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// runas.resume_all_threads(1234)?;
    /// ```
    pub fn resume_all_threads(&self, pid: u32) -> Result<()> {
        unsafe {
            // Open the process with the necessary access rights
            let process_handle = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if process_handle.is_null() {
                bail!("OpenProcess Failed With Error: {}", GetLastError());
            }

            // Get a snapshot of all threads in the system
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                CloseHandle(process_handle);
                bail!("CreateToolhelp32Snapshot Failed With Error: {}", GetLastError());
            }

            // Initialize the thread entry structure
            let mut thread_entry = THREADENTRY32 {
                dwSize: size_of::<THREADENTRY32>() as u32,
                ..zeroed()
            };

            // Iterate through all threads
            if Thread32First(snapshot, &mut thread_entry) == TRUE {
                loop {
                    // Check if the thread belongs to our target process
                    if thread_entry.th32OwnerProcessID == pid {
                        // Open the thread with the necessary access rights
                        let thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
                        if !thread_handle.is_null() {
                            // Resume the thread
                            let result = ResumeThread(thread_handle);
                            if result == -1 {
                                CloseHandle(thread_handle);
                                CloseHandle(process_handle);
                                CloseHandle(snapshot);
                                bail!("ResumeThread Failed With Error: {}", GetLastError());
                            }
                            CloseHandle(thread_handle);
                        }
                    }

                    // Move to the next thread
                    if Thread32Next(snapshot, &mut thread_entry) == FALSE {
                        break;
                    }
                }
            }

            // Clean up
            CloseHandle(snapshot);
            CloseHandle(process_handle);
            Ok(())
        }
    }
}

/// Implements the `Drop` trait to release env when `Runas` goes out of scope.
impl Drop for Runas<'_> {
    fn drop(&mut self) {
        if !self.env.is_null() {
            unsafe { DestroyEnvironmentBlock(self.env) };
        }
    }
}

/// Defines which Windows API will be used to spawn the process.
#[derive(Debug, Clone, Copy)]
enum CreateProcessFunction {
    /// https://learn.microsoft.com/pt-br/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera
    CreateProcessAsUser = 0,
    
    /// https://learn.microsoft.com/pt-br/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
    CreateProcessWithToken = 1,
    
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
    CreateProcessWithLogon = 2,
}

/// Represents a simple wrapper around Token on Windows. 
pub struct Token;

impl Token {
    /// Returns the integrity level of the current process token.
    ///
    /// # Returns
    ///
    /// * `Ok(&'static str)` - A string indicating the integrity level.
    /// * `Err(anyhow::Error)` - If any token API call fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let level = Token::integrity_level()?;
    /// println!("Integrity level: {}", level);
    /// ```
    pub fn integrity_level() -> Result<&'static str> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("GetProcessWindowStation Failed With Error: {}", GetLastError());
            }
    
            // Make the first call to GetTokenInformation to get the size required
            let mut len = 0;
            GetTokenInformation(h_token, TokenIntegrityLevel, null_mut(), 0, &mut len);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER  {
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }
    
            // Allocate memory for the TOKEN_MANDATORY_LABEL structure
            let mut buffer = vec![0u8; len as usize];
            if GetTokenInformation(h_token, TokenIntegrityLevel, buffer.as_mut_ptr().cast(), len, &mut len) == FALSE {
                bail!("GetTokenInformation [2] Failed With Error: {}", GetLastError());
            }
    
            // Retrieve the actual integrity level information
            let til = buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL;
            let count = GetSidSubAuthorityCount((*til).Label.Sid);
            if count.is_null() {
                bail!("GetSidSubAuthorityCount Failed With Error: {}", GetLastError());
            }
    
            // Extract the RID from the SID, which represents the integrity level
            let ptr = GetSidSubAuthority((*til).Label.Sid, (*count - 1) as u32);
            if ptr.is_null() {
                bail!("GetSidSubAuthority Failed With Error: {}", GetLastError());
            }
            
            // Interpret the integrity level RID and print a human-readable labe
            let level = ptr::read(ptr) as i32;
            let label = match level {
                security_mandatory_low_rid => "Low",
                security_mandatory_medium_rid => "Medium",
                security_mandatory_high_rid => "High",
                security_mandatory_system_rid => "System",
                _ => "Unknown",
            };
    
            Ok(label)
        }
    }

    /// Checks if the current process token has a specific privilege enabled.
    ///
    /// # Parameters
    ///
    /// * `name` - The name of the privilege to check.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the privilege is found in the token.
    /// * `Ok(false)` if the privilege is not found.
    /// * `Err(anyhow::Error)` if the token query fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if Token::has_privilege("SeImpersonatePrivilege")? {
    ///     println!("Privilege is enabled!");
    /// }
    /// ```
    pub fn has_privilege(name: &str) -> Result<bool> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Make the first call to GetTokenInformation to get the size required
            let mut len = 0;
            GetTokenInformation(h_token, TokenPrivileges, null_mut(), 0, &mut len);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Allocate memory for the TOKEN_PRIVILEGES structure
            let mut buffer = vec![0u8; len as usize];
            if GetTokenInformation(h_token, TokenPrivileges, buffer.as_mut_ptr().cast(), len, &mut len) == FALSE {
                bail!("GetTokenInformation [2] Failed With Error: {}", GetLastError());
            }

            let header = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
            let privs = &header.Privileges as *const LUID_AND_ATTRIBUTES;
            for i in 0..header.PrivilegeCount {
                let luid_attr = privs.add(i as usize);
                let luid = (*luid_attr).Luid;
                
                let mut buffer = vec![0u16; 128];
                let mut len = buffer.len() as u32;

                // Lookup the string name of the privilege from its LUID.
                if LookupPrivilegeNameW(null(), &luid, buffer.as_mut_ptr(), &mut len) == FALSE {
                    continue
                }

                // Convert UTF-16 buffer into a Rust `String`
                buffer.truncate(len as usize);
                let privilege = String::from_utf16_lossy(&buffer);

                // Compare the privilege name to the target; if it matches, return true
                if privilege == name {
                    return Ok(true)
                }
            }
        }

        Ok(false)
    }

    /// Enables a specific privilege on the current process token.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// Token::enable_privilege("SeDebugPrivilege")?;
    /// ```
    pub fn enable_privilege(name: &str) -> Result<bool> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Look up the LUID for the given privilege name 
            let mut token_priv = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: zeroed(), Attributes: SE_PRIVILEGE_ENABLED}; 1],
            };
            if LookupPrivilegeValueW(null_mut(), name.to_pwstr().as_ptr(), &mut token_priv.Privileges[0].Luid as *mut LUID) == FALSE {
                bail!("LookupPrivilegeValueW Failed With Error: {}", GetLastError());
            }

            // Apply the adjusted privileges to the token.
            if AdjustTokenPrivileges(h_token, 0, &token_priv, 0, null_mut(), null_mut()) == FALSE {
                bail!("AdjustTokenPrivileges Failed With Error: {}", GetLastError());
            }
        }

        Ok(true)
    }

    /// Impersonates a user by their SID
    ///
    /// # Parameters
    ///
    /// * `sid` - The security identifier (SID) of the user to impersonate
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If impersonation was successful
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let user_sid = get_user_sid("username", "domain")?;
    /// Token::impersonate_by_sid(&user_sid)?;
    /// ```
    pub fn impersonate_by_sid(sid: &[u8]) -> Result<()> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Create an impersonation token
            let mut h_impersonation_token = null_mut();
            if DuplicateTokenEx(
                h_token,
                TOKEN_ALL_ACCESS,
                null_mut(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut h_impersonation_token
            ) == FALSE {
                bail!("DuplicateTokenEx Failed With Error: {}", GetLastError());
            }

            // Set the token's user SID
            let mut token_user = TOKEN_USER {
                User: SID_AND_ATTRIBUTES {
                    Sid: sid.as_ptr() as *mut _,
                    Attributes: 0,
                },
            };

            if SetTokenInformation(
                h_impersonation_token,
                TokenUser,
                &mut token_user as *mut _ as *mut c_void,
                size_of::<TOKEN_USER>() as u32,
            ) == FALSE {
                bail!("SetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Impersonate the token
            if ImpersonateLoggedOnUser(h_impersonation_token) == FALSE {
                bail!("ImpersonateLoggedOnUser Failed With Error: {}", GetLastError());
            }

            // Clean up
            CloseHandle(h_impersonation_token);
            CloseHandle(h_token);

            Ok(())
        }
    }
    
    /// Reverts impersonation to the original token
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If reversion was successful
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// Token::revert_impersonation()?;
    /// ```
    pub fn revert_impersonation() -> Result<()> {
        unsafe {
            if RevertToSelf() == FALSE {
                bail!("RevertToSelf Failed With Error: {}", GetLastError());
            }
            Ok(())
        }
    }
    
    /// Duplicates a token with specific access rights
    ///
    /// # Parameters
    ///
    /// * `access_rights` - The access rights to request for the duplicated token
    /// * `impersonation_level` - The impersonation level for the duplicated token
    /// * `token_type` - The type of token to create
    ///
    /// # Returns
    ///
    /// * `Ok(HANDLE)` - The handle to the duplicated token
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let h_token = Token::duplicate_token(
    ///     TOKEN_ALL_ACCESS,
    ///     SecurityImpersonation,
    ///     TokenPrimary
    /// )?;
    /// ```
    pub fn duplicate_token(access_rights: u32, impersonation_level: u32, token_type: u32) -> Result<HANDLE> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_DUPLICATE | TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Duplicate the token with the specified parameters
            let mut h_duplicated_token = null_mut();
            if DuplicateTokenEx(
                h_token,
                access_rights,
                null_mut(),
                impersonation_level,
                token_type,
                &mut h_duplicated_token
            ) == FALSE {
                CloseHandle(h_token);
                bail!("DuplicateTokenEx Failed With Error: {}", GetLastError());
            }

            // Clean up the original token
            CloseHandle(h_token);

            Ok(h_duplicated_token)
        }
    }
    
    /// Gets all privileges available in the current token
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<String>)` - A vector of privilege names
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let privileges = Token::get_all_privileges()?;
    /// for privilege in privileges {
    ///     println!("Privilege: {}", privilege);
    /// }
    /// ```
    pub fn get_all_privileges() -> Result<Vec<String>> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Make the first call to GetTokenInformation to get the size required
            let mut len = 0;
            GetTokenInformation(h_token, TokenPrivileges, null_mut(), 0, &mut len);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Allocate memory for the TOKEN_PRIVILEGES structure
            let mut buffer = vec![0u8; len as usize];
            if GetTokenInformation(h_token, TokenPrivileges, buffer.as_mut_ptr().cast(), len, &mut len) == FALSE {
                CloseHandle(h_token);
                bail!("GetTokenInformation [2] Failed With Error: {}", GetLastError());
            }

            let header = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
            let privs = &header.Privileges as *const LUID_AND_ATTRIBUTES;
            
            let mut privileges = Vec::new();
            
            for i in 0..header.PrivilegeCount {
                let luid_attr = privs.add(i as usize);
                let luid = (*luid_attr).Luid;
                
                let mut buffer = vec![0u16; 128];
                let mut len = buffer.len() as u32;

                // Lookup the string name of the privilege from its LUID
                if LookupPrivilegeNameW(null(), &luid, buffer.as_mut_ptr(), &mut len) == FALSE {
                    continue;
                }

                // Convert UTF-16 buffer into a Rust `String`
                buffer.truncate(len as usize);
                let privilege = String::from_utf16_lossy(&buffer);
                
                privileges.push(privilege);
            }
            
            CloseHandle(h_token);
            Ok(privileges)
        }
    }

    /// Gets the security context of the current process
    ///
    /// # Returns
    ///
    /// * `Ok(SecurityContext)` - A struct containing the security context information
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let context = Token::get_security_context()?;
    /// println!("User SID: {:?}", context.user_sid);
    /// println!("Group SIDs: {:?}", context.group_sids);
    /// println!("Privileges: {:?}", context.privileges);
    /// ```
    pub fn get_security_context() -> Result<SecurityContext> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Get the user SID
            let mut user_sid = Vec::new();
            let mut user_sid_size = 0;
            GetTokenInformation(h_token, TokenUser, null_mut(), 0, &mut user_sid_size);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            user_sid.resize(user_sid_size as usize, 0);
            if GetTokenInformation(h_token, TokenUser, user_sid.as_mut_ptr().cast(), user_sid_size, &mut user_sid_size) == FALSE {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the group SIDs
            let mut group_sids = Vec::new();
            let mut group_sids_size = 0;
            GetTokenInformation(h_token, TokenGroups, null_mut(), 0, &mut group_sids_size);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            group_sids.resize(group_sids_size as usize, 0);
            if GetTokenInformation(h_token, TokenGroups, group_sids.as_mut_ptr().cast(), group_sids_size, &mut group_sids_size) == FALSE {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the privileges
            let mut privileges = Vec::new();
            let mut privileges_size = 0;
            GetTokenInformation(h_token, TokenPrivileges, null_mut(), 0, &mut privileges_size);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            privileges.resize(privileges_size as usize, 0);
            if GetTokenInformation(h_token, TokenPrivileges, privileges.as_mut_ptr().cast(), privileges_size, &mut privileges_size) == FALSE {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the token source
            let mut token_source = TOKEN_SOURCE {
                SourceName: [0; 8],
                SourceIdentifier: zeroed(),
            };
            let mut token_source_size = size_of::<TOKEN_SOURCE>() as u32;
            if GetTokenInformation(h_token, TokenSource, &mut token_source as *mut _ as *mut c_void, token_source_size, &mut token_source_size) == FALSE {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the token type
            let mut token_type = 0;
            let mut token_type_size = size_of::<u32>() as u32;
            if GetTokenInformation(h_token, TokenType, &mut token_type as *mut _ as *mut c_void, token_type_size, &mut token_type_size) == FALSE {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the token impersonation level
            let mut impersonation_level = 0;
            let mut impersonation_level_size = size_of::<u32>() as u32;
            if GetTokenInformation(h_token, TokenImpersonationLevel, &mut impersonation_level as *mut _ as *mut c_void, impersonation_level_size, &mut impersonation_level_size) == FALSE {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the integrity level
            let mut integrity_level = 0;
            let mut integrity_level_size = size_of::<u32>() as u32;
            if GetTokenInformation(h_token, TokenIntegrityLevel, &mut integrity_level as *mut _ as *mut c_void, integrity_level_size, &mut integrity_level_size) == FALSE {
                CloseHandle(h_token);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Clean up
            CloseHandle(h_token);

            // Convert the token source name to a string
            let source_name = std::str::from_utf8(&token_source.SourceName)
                .unwrap_or("Unknown")
                .trim_matches('\0')
                .to_string();

            Ok(SecurityContext {
                id: 0, // Current process ID
                user_sid,
                integrity_level,
                privileges,
                groups: Vec::new(), // This is a duplicate of group_sids
                impersonation_level,
                source_name,
                source_identifier: token_source.SourceIdentifier,
                token_type,
                group_sids,
            })
        }
    }

    /// Sets the security context for the current process
    ///
    /// # Parameters
    ///
    /// * `context` - The security context to set
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the security context was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let context = Token::get_security_context()?;
    /// // Modify the context as needed
    /// Token::set_security_context(&context)?;
    /// ```
    pub fn set_security_context(context: &SecurityContext) -> Result<()> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Set the user SID
            if !context.user_sid.is_empty() {
                let user_sid_ptr = context.user_sid.as_ptr() as *const TOKEN_USER;
                if SetTokenInformation(h_token, TokenUser, user_sid_ptr as *mut c_void, context.user_sid.len() as u32) == FALSE {
                    CloseHandle(h_token);
                    bail!("SetTokenInformation Failed With Error: {}", GetLastError());
                }
            }

            // Set the group SIDs
            if !context.group_sids.is_empty() {
                let group_sids_ptr = context.group_sids.as_ptr() as *const TOKEN_GROUPS;
                if SetTokenInformation(h_token, TokenGroups, group_sids_ptr as *mut c_void, context.group_sids.len() as u32) == FALSE {
                    CloseHandle(h_token);
                    bail!("SetTokenInformation Failed With Error: {}", GetLastError());
                }
            }

            // Set the privileges
            if !context.privileges.is_empty() {
                let privileges_ptr = context.privileges.as_ptr() as *const TOKEN_PRIVILEGES;
                if SetTokenInformation(h_token, TokenPrivileges, privileges_ptr as *mut c_void, context.privileges.len() as u32) == FALSE {
                    CloseHandle(h_token);
                    bail!("SetTokenInformation Failed With Error: {}", GetLastError());
                }
            }

            // Clean up
            CloseHandle(h_token);
            Ok(())
        }
    }

    /// Gets the security context of a process by its process ID
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID of the process
    ///
    /// # Returns
    ///
    /// * `Ok(SecurityContext)` - A struct containing the security context information
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let context = Token::get_process_security_context(1234)?;
    /// println!("User SID: {:?}", context.user_sid);
    /// ```
    pub fn get_process_security_context(pid: u32) -> Result<SecurityContext> {
        unsafe {
            // Open the process with the necessary access rights
            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if process_handle.is_null() {
                bail!("OpenProcess Failed With Error: {}", GetLastError());
            }

            // Get the process token
            let mut h_token = null_mut();
            if OpenProcessToken(process_handle, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &mut h_token) == FALSE {
                CloseHandle(process_handle);
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Get the user SID
            let mut user_sid = Vec::new();
            let mut user_sid_size = 0;
            GetTokenInformation(h_token, TokenUser, null_mut(), 0, &mut user_sid_size);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            user_sid.resize(user_sid_size as usize, 0);
            if GetTokenInformation(h_token, TokenUser, user_sid.as_mut_ptr().cast(), user_sid_size, &mut user_sid_size) == FALSE {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the group SIDs
            let mut group_sids = Vec::new();
            let mut group_sids_size = 0;
            GetTokenInformation(h_token, TokenGroups, null_mut(), 0, &mut group_sids_size);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            group_sids.resize(group_sids_size as usize, 0);
            if GetTokenInformation(h_token, TokenGroups, group_sids.as_mut_ptr().cast(), group_sids_size, &mut group_sids_size) == FALSE {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the privileges
            let mut privileges = Vec::new();
            let mut privileges_size = 0;
            GetTokenInformation(h_token, TokenPrivileges, null_mut(), 0, &mut privileges_size);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            privileges.resize(privileges_size as usize, 0);
            if GetTokenInformation(h_token, TokenPrivileges, privileges.as_mut_ptr().cast(), privileges_size, &mut privileges_size) == FALSE {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the token source
            let mut token_source = TOKEN_SOURCE {
                SourceName: [0; 8],
                SourceIdentifier: zeroed(),
            };
            let mut token_source_size = size_of::<TOKEN_SOURCE>() as u32;
            if GetTokenInformation(h_token, TokenSource, &mut token_source as *mut _ as *mut c_void, token_source_size, &mut token_source_size) == FALSE {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the token type
            let mut token_type = 0;
            let mut token_type_size = size_of::<u32>() as u32;
            if GetTokenInformation(h_token, TokenType, &mut token_type as *mut _ as *mut c_void, token_type_size, &mut token_type_size) == FALSE {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the token impersonation level
            let mut impersonation_level = 0;
            let mut impersonation_level_size = size_of::<u32>() as u32;
            if GetTokenInformation(h_token, TokenImpersonationLevel, &mut impersonation_level as *mut _ as *mut c_void, impersonation_level_size, &mut impersonation_level_size) == FALSE {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Get the integrity level
            let mut integrity_level = 0;
            let mut integrity_level_size = size_of::<u32>() as u32;
            if GetTokenInformation(h_token, TokenIntegrityLevel, &mut integrity_level as *mut _ as *mut c_void, integrity_level_size, &mut integrity_level_size) == FALSE {
                CloseHandle(h_token);
                CloseHandle(process_handle);
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Clean up
            CloseHandle(h_token);
            CloseHandle(process_handle);

            // Convert the token source name to a string
            let source_name = std::str::from_utf8(&token_source.SourceName)
                .unwrap_or("Unknown")
                .trim_matches('\0')
                .to_string();

            Ok(SecurityContext {
                id: pid,
                user_sid,
                integrity_level,
                privileges,
                groups: Vec::new(), // This is a duplicate of group_sids
                impersonation_level,
                source_name,
                source_identifier: token_source.SourceIdentifier,
                token_type,
                group_sids,
            })
        }
    }

    /// Sets the security context for a process by its process ID
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID of the process
    /// * `context` - The security context to set
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the security context was successfully set
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let context = Token::get_process_security_context(1234)?;
    /// // Modify the context as needed
    /// Token::set_process_security_context(1234, &context)?;
    /// ```
    pub fn set_process_security_context(pid: u32, context: &SecurityContext) -> Result<()> {
        unsafe {
            // Open the process with the necessary access rights
            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if process_handle.is_null() {
                bail!("OpenProcess Failed With Error: {}", GetLastError());
            }

            // Get the process token
            let mut h_token = null_mut();
            if OpenProcessToken(process_handle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == FALSE {
                CloseHandle(process_handle);
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Set the user SID
            if !context.user_sid.is_empty() {
                let user_sid_ptr = context.user_sid.as_ptr() as *const TOKEN_USER;
                if SetTokenInformation(h_token, TokenUser, user_sid_ptr as *mut c_void, context.user_sid.len() as u32) == FALSE {
                    CloseHandle(h_token);
                    CloseHandle(process_handle);
                    bail!("SetTokenInformation Failed With Error: {}", GetLastError());
                }
            }

            // Set the group SIDs
            if !context.group_sids.is_empty() {
                let group_sids_ptr = context.group_sids.as_ptr() as *const TOKEN_GROUPS;
                if SetTokenInformation(h_token, TokenGroups, group_sids_ptr as *mut c_void, context.group_sids.len() as u32) == FALSE {
                    CloseHandle(h_token);
                    CloseHandle(process_handle);
                    bail!("SetTokenInformation Failed With Error: {}", GetLastError());
                }
            }

            // Set the privileges
            if !context.privileges.is_empty() {
                let privileges_ptr = context.privileges.as_ptr() as *const TOKEN_PRIVILEGES;
                if SetTokenInformation(h_token, TokenPrivileges, privileges_ptr as *mut c_void, context.privileges.len() as u32) == FALSE {
                    CloseHandle(h_token);
                    CloseHandle(process_handle);
                    bail!("SetTokenInformation Failed With Error: {}", GetLastError());
                }
            }

            // Clean up
            CloseHandle(h_token);
            CloseHandle(process_handle);
            Ok(())
        }
    }
}

trait PWSTR {
    /// Converts a `&str` to a null-terminated UTF-16 wide string, suitable for Windows APIs.
    fn to_pwstr(&self) -> Vec<u16>;
}

impl PWSTR for &str {
    fn to_pwstr(&self) -> Vec<u16> {
        OsStr::new(self).encode_wide().chain(std::iter::once(0)).collect()
    }
}
